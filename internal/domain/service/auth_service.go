package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	dto "10.1.20.130/dropping/auth-service/internal/domain/dto"
	"10.1.20.130/dropping/auth-service/internal/domain/repository"
	_mq "10.1.20.130/dropping/auth-service/internal/infrastructure/message-queue"
	"10.1.20.130/dropping/auth-service/pkg/constant"
	"10.1.20.130/dropping/auth-service/pkg/generators"
	"10.1.20.130/dropping/auth-service/pkg/jwt"
	fpb "github.com/dropboks/proto-file/pkg/fpb"
	upb "github.com/dropboks/proto-user/pkg/upb"
	_dto "github.com/dropboks/sharedlib/dto"
	_utils "github.com/dropboks/sharedlib/utils"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

type (
	AuthService interface {
		LoginService(req dto.LoginRequest) (string, error)
		RegisterService(req dto.RegisterRequest) error
		VerifyService(token string) (string, error)
		LogoutService(token string) error
		VerifyEmailService(userId, token, changeToken string) error
		ResendVerificationService(email string) error
		VerifyOTPService(otp, email string) (string, error)
		ResendVerificationOTPService(email string) error
		ResetPasswordService(email string) error
		ChangePasswordService(userId, resetPasswordToken string, req *dto.ChangePasswordRequest) error
	}
	authService struct {
		authRepository    repository.AuthRepository
		userServiceClient upb.UserServiceClient
		fileServiceClient fpb.FileServiceClient
		logger            zerolog.Logger
		js                _mq.Nats
		g                 generators.RandomGenerator
	}
)

func New(authRepository repository.AuthRepository, userServiceClient upb.UserServiceClient, fileServiceClient fpb.FileServiceClient, logger zerolog.Logger, js _mq.Nats, g generators.RandomGenerator) AuthService {
	return &authService{
		authRepository:    authRepository,
		userServiceClient: userServiceClient,
		fileServiceClient: fileServiceClient,
		logger:            logger,
		js:                js,
		g:                 g,
	}
}

func (a *authService) ChangePasswordService(userId string, resetPasswordToken string, req *dto.ChangePasswordRequest) error {
	if req.Password != req.ConfirmPassword {
		a.logger.Error().Msg("password and confirm password doesn't match")
		return dto.Err_BAD_REQUEST_PASSWORD_DOESNT_MATCH
	}

	ctx := context.Background()
	user, err := a.authRepository.GetUserByUserId(userId)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("resetPasswordToken:%s", userId)

	rToken, err := a.authRepository.GetResource(ctx, key)
	if err != nil {
		a.logger.Error().Err(err).Msg("get token error")
		return err
	}
	if rToken != resetPasswordToken {
		a.logger.Error().Msg("token is not match")
		return dto.Err_UNAUTHORIZED_TOKEN_INVALID
	}
	hashedPassword, err := _utils.HashPassword(req.Password)
	if err != nil {
		return err
	}

	us := &upb.User{
		Id:               userId,
		FullName:         user.FullName,
		Image:            user.Image,
		Email:            user.Email,
		Password:         hashedPassword,
		Verified:         user.Verified,
		TwoFactorEnabled: user.TwoFactorEnabled,
	}
	_, err = a.userServiceClient.UpdateUser(ctx, us)
	if err != nil {
		return err
	}
	if err := a.authRepository.RemoveResource(ctx, key); err != nil {
		return err
	}
	return nil
}

func (a *authService) ResetPasswordService(email string) error {
	ctx := context.Background()
	user, err := a.authRepository.GetUserByEmail(email)
	if err != nil {
		return err
	}
	if !user.Verified {
		a.logger.Error().Msg("user is not verified")
		return dto.Err_UNAUTHORIZED_USER_NOT_VERIFIED
	}

	resetPasswordToken, err := a.g.GenerateToken()
	if err != nil {
		a.logger.Error().Err(err).Msg("error generate verification token")
		return dto.Err_INTERNAL_GENERATE_TOKEN
	}

	key := fmt.Sprintf("resetPasswordToken:%s", user.ID)
	if err := a.authRepository.SetResource(ctx, key, resetPasswordToken, 1*time.Hour); err != nil {
		a.logger.Error().Err(err).Msg("failed to set reset password token")
		return err
	}

	link := fmt.Sprintf("%s/%suserid=%s&resetPasswordToken=%s", viper.GetString("app.url"), viper.GetString("app.changepassword_url"), user.ID, resetPasswordToken)
	subject := fmt.Sprintf("%s.%s", viper.GetString("jetstream.notification.subject.mail"), user.ID)
	msg := &_dto.MailNotificationMessage{
		Receiver: []string{user.Email},
		MsgType:  "resetPassword",
		Message:  link,
	}
	marshalledMsg, err := json.Marshal(msg)
	if err != nil {
		a.logger.Error().Err(err).Msg("marshal data error")
		return err
	}
	_, err = a.js.Publish(ctx, subject, []byte(marshalledMsg))
	if err != nil {
		a.logger.Error().Err(err).Msg("publish notification error")
	}
	return nil
}

func (a *authService) ResendVerificationOTPService(email string) error {
	ctx := context.Background()
	user, err := a.authRepository.GetUserByEmail(email)
	if err != nil {
		a.logger.Error().Err(err).Msg("error from user_service")
		return err
	}
	if !user.Verified {
		a.logger.Error().Err(err).Msg("user is not verified")
		return dto.Err_UNAUTHORIZED_USER_NOT_VERIFIED
	}
	if !user.TwoFactorEnabled {
		a.logger.Error().Err(err).Msg("user is not activate 2FA")
		return dto.Err_UNAUTHORIZED_2FA_DISABLED
	}
	otp, err := a.g.GenerateOTP()
	if err != nil {
		a.logger.Error().Err(err).Msg("generate OTP error")
		return dto.Err_INTERNAL_GENERATE_OTP
	}
	key := fmt.Sprintf("OTP:%s", user.ID)
	if err := a.authRepository.SetResource(ctx, key, otp, 2*time.Minute); err != nil {
		a.logger.Error().Err(err).Msg("failed to set OTP")
		return err
	}

	subject := fmt.Sprintf("%s.%s", viper.GetString("jetstream.notification.subject.mail"), user.ID)
	msg := &_dto.MailNotificationMessage{
		Receiver: []string{user.Email},
		MsgType:  "OTP",
		Message:  otp,
	}
	marshalledMsg, err := json.Marshal(msg)
	if err != nil {
		a.logger.Error().Err(err).Msg("marshal data error")
		return err
	}
	_, err = a.js.Publish(ctx, subject, []byte(marshalledMsg))
	if err != nil {
		a.logger.Error().Err(err).Msg("publish notification error")
		return err
	}
	return nil
}

func (a *authService) VerifyOTPService(otp, email string) (string, error) {
	ctx := context.Background()
	user, err := a.authRepository.GetUserByEmail(email)
	if err != nil {
		a.logger.Error().Err(err).Msg("error from user_service")
		return "", err
	}
	key := fmt.Sprintf("OTP:%s", user.ID)
	rOTP, err := a.authRepository.GetResource(ctx, key)
	if err != nil {
		a.logger.Error().Err(err).Msg("error get otp from Redis")
		return "", err
	}
	if rOTP != otp {
		a.logger.Error().Err(dto.Err_UNAUTHORIZED_OTP_INVALID).Msg("OTP is not valid")
		return "", dto.Err_UNAUTHORIZED_OTP_INVALID
	}
	err = a.authRepository.RemoveResource(ctx, key)
	if err != nil {
		a.logger.Error().Err(err).Msg("error remove otp from Redis")
		return "", err
	}

	token, claims, err := jwt.GenerateToken(user.ID, 1*time.Hour)
	if err != nil {
		a.logger.Error().Err(err).Msg("error JWT Signing")
		return "", dto.Err_INTENAL_JWT_SIGNING
	}
	sessionKey := "session:" + claims.ID
	if err := a.authRepository.SetResource(ctx, sessionKey, token, 1*time.Hour); err != nil {
		a.logger.Error().Err(err).Msg("error saving token to Redis")
		return "", err
	}
	return token, nil
}

func (a *authService) ResendVerificationService(email string) error {
	ctx := context.Background()
	user, err := a.authRepository.GetUserByEmail(email)
	if err != nil {
		return err
	}
	if user.Verified {
		a.logger.Error().Msg("user already verified")
		return dto.Err_CONFLICT_USER_ALREADY_VERIFIED
	}
	verificationToken, err := a.g.GenerateToken()
	if err != nil {
		a.logger.Error().Err(err).Msg("error generate verification token")
		return dto.Err_INTERNAL_GENERATE_TOKEN
	}
	key := fmt.Sprintf("verificationToken:%s", user.ID)
	if err := a.authRepository.SetResource(ctx, key, verificationToken, 30*time.Minute); err != nil {
		a.logger.Error().Err(err).Msg("failed to set verification token")
		return err
	}
	link := fmt.Sprintf("%s/%suserid=%s&token=%s", viper.GetString("app.url"), viper.GetString("app.verification_url"), user.ID, verificationToken)
	subject := fmt.Sprintf("%s.%s", viper.GetString("jetstream.notification.subject.mail"), user.ID)
	msg := &_dto.MailNotificationMessage{
		Receiver: []string{email},
		MsgType:  "verification",
		Message:  link,
	}
	marshalledMsg, err := json.Marshal(msg)
	if err != nil {
		a.logger.Error().Err(err).Msg("marshal data error")
		return err
	}
	_, err = a.js.Publish(ctx, subject, []byte(marshalledMsg))
	if err != nil {
		a.logger.Error().Err(err).Msg("publish notification error")
		return dto.Err_INTERNAL_PUBLISH_MESSAGE
	}
	return nil
}

func (a *authService) VerifyEmailService(userId, token, changeToken string) error {
	ctx := context.Background()
	user, err := a.authRepository.GetUserByUserId(userId)
	if err != nil {
		return err
	}
	var key string
	var updatedUser *upb.User
	if changeToken != "" {
		key = fmt.Sprintf("changeEmailToken:%s", userId)
		rToken, err := a.authRepository.GetResource(ctx, key)
		if err != nil {
			a.logger.Error().Err(err).Msg("failed to get resource")
			return err
		}
		if changeToken != rToken {
			a.logger.Error().Msg("token not match")
			return dto.Err_UNAUTHORIZED_TOKEN_INVALID
		}
		newEmailkey := fmt.Sprintf("newEmail:%s", userId)
		newEmail, err := a.authRepository.GetResource(ctx, newEmailkey)
		if err != nil {
			a.logger.Error().Err(err).Msg("failed to get resource")
			return err
		}
		updatedUser = &upb.User{
			Id:               user.ID,
			FullName:         user.FullName,
			Image:            user.Image,
			Email:            newEmail,
			Password:         user.Password,
			Verified:         user.Verified,
			TwoFactorEnabled: user.TwoFactorEnabled,
		}
		_, err = a.userServiceClient.UpdateUser(ctx, updatedUser)
		if err != nil {
			a.logger.Error().Err(err).Msg("failed to update user")
			return err
		}
		err = a.authRepository.RemoveResource(ctx, key)
		if err != nil {
			a.logger.Error().Err(err).Msg("failed to remove resource")
			return err
		}
		err = a.authRepository.RemoveResource(ctx, newEmailkey)
		if err != nil {
			a.logger.Error().Err(err).Msg("failed to remove resource")
			return err
		}
	} else {
		if user.Verified {
			a.logger.Error().Msg("user already verified")
			return dto.Err_CONFLICT_USER_ALREADY_VERIFIED
		}
		key = fmt.Sprintf("verificationToken:%s", userId)
		rToken, err := a.authRepository.GetResource(ctx, key)
		if err != nil {
			a.logger.Error().Err(err).Msg("failed to get resource")
			return err
		}
		if token != rToken {
			a.logger.Error().Msg("token not match")
			return dto.Err_UNAUTHORIZED_TOKEN_INVALID
		}

		updatedUser = &upb.User{
			Id:               user.ID,
			FullName:         user.FullName,
			Image:            user.Image,
			Email:            user.Email,
			Password:         user.Password,
			Verified:         true,
			TwoFactorEnabled: false,
		}
		_, err = a.userServiceClient.UpdateUser(ctx, updatedUser)
		if err != nil {
			a.logger.Error().Err(err).Msg("failed to update user")
			return err
		}
		err = a.authRepository.RemoveResource(ctx, key)
		if err != nil {
			a.logger.Error().Err(err).Msg("failed to remove resource")
			return err
		}
	}
	return nil
}

func (a *authService) VerifyService(token string) (string, error) {
	c := context.Background()
	claims, err := jwt.ValidateJWT(token)
	if err != nil {
		a.logger.Error().Err(err).Msg("invalid jwt")
		return "", err
	}
	key := "session:" + claims.ID
	rToken, err := a.authRepository.GetResource(c, key)
	if err != nil {
		return "", err
	}
	if token != rToken {
		return "", dto.Err_UNAUTHORIZED_JWT_INVALID
	}

	return claims.UserId, nil
}

func (a *authService) LogoutService(token string) error {
	c := context.Background()
	claims, err := jwt.ValidateJWT(token)
	if err != nil {
		a.logger.Error().Err(err).Msg("invalid jwt")
		return err
	}
	key := "session:" + claims.ID
	err = a.authRepository.RemoveResource(c, key)
	if err != nil {
		return err
	}
	return nil
}

func (a *authService) RegisterService(req dto.RegisterRequest) error {
	if req.Password != req.ConfirmPassword {
		return dto.Err_BAD_REQUEST_PASSWORD_DOESNT_MATCH
	}
	ext := ""
	if req.Image != nil && req.Image.Filename != "" {
		ext = _utils.GetFileNameExtension(req.Image.Filename)
		if ext != "jpg" && ext != "jpeg" && ext != "png" {
			return dto.Err_BAD_REQUEST_WRONG_EXTENSION
		}
		if req.Image.Size > constant.MAX_UPLOAD_SIZE {
			return dto.Err_BAD_REQUEST_LIMIT_SIZE_EXCEEDED
		}
	}
	ctx := context.Background()
	exist, err := a.authRepository.GetUserByEmail(req.Email)
	if err != nil {
		if err != dto.Err_NOTFOUND_USER_NOT_FOUND {
			a.logger.Error().Err(err).Msg("Error Query Get User By Email")
			return err
		}
	}
	if exist != nil {
		a.logger.Error().Str("email", req.Email).Msg("User with this email exist")
		return dto.Err_CONFLICT_EMAIL_EXIST
	}
	password, err := _utils.HashPassword(req.Password)
	if err != nil {
		a.logger.Error().Err(err).Msg("Error hashing password")
	}

	var imageName *string
	if req.Image != nil && req.Image.Filename != "" {
		image, err := _utils.FileToByte(req.Image)
		if err != nil {
			a.logger.Error().Err(err).Msg("error converting image")
			return dto.Err_INTERNAL_CONVERT_IMAGE
		}
		imageReq := &fpb.Image{
			Image: image,
			Ext:   ext,
		}
		resp, err := a.fileServiceClient.SaveProfileImage(ctx, imageReq)
		if err != nil {
			a.logger.Error().Err(err).Msg("Error uploading image to file service")
			return err
		}
		imageName = _utils.StringPtr(resp.GetName())
	} else {
		imageName = nil
	}

	userId := a.g.GenerateUUID()
	user := &upb.User{
		Id:               userId,
		FullName:         strings.TrimSpace(req.FullName),
		Image:            imageName,
		Email:            req.Email,
		Password:         password,
		Verified:         false,
		TwoFactorEnabled: false,
	}
	_, err = a.userServiceClient.CreateUser(ctx, user)
	if err != nil && req.Image != nil && req.Image.Filename != "" {
		_, err := a.fileServiceClient.RemoveProfileImage(ctx, &fpb.ImageName{Name: *imageName})
		return err
	}
	verificationToken, err := a.g.GenerateToken()
	if err != nil {
		a.logger.Error().Err(err).Msg("error generate verification token")
		return dto.Err_INTERNAL_GENERATE_TOKEN
	}

	key := fmt.Sprintf("verificationToken:%s", userId)
	if err := a.authRepository.SetResource(ctx, key, verificationToken, 30*time.Minute); err != nil {
		a.logger.Error().Err(err).Msg("failed to set verification token")
		return err
	}
	go func() {
		link := fmt.Sprintf("%s/%suserid=%s&token=%s", viper.GetString("app.url"), viper.GetString("app.verification_url"), userId, verificationToken)
		subject := fmt.Sprintf("%s.%s", viper.GetString("jetstream.notification.subject.mail"), userId)
		msg := &_dto.MailNotificationMessage{
			Receiver: []string{user.Email},
			MsgType:  "verification",
			Message:  link,
		}
		marshalledMsg, err := json.Marshal(msg)
		if err != nil {
			a.logger.Error().Err(err).Msg("marshal data error")
			return
		}
		_, err = a.js.Publish(ctx, subject, []byte(marshalledMsg))
		if err != nil {
			a.logger.Error().Err(err).Msg("publish notification error")
		} else {
			a.logger.Info().Msgf("Published message to subject %s", subject)
		}
	}()
	return nil
}

func (a *authService) LoginService(req dto.LoginRequest) (string, error) {
	c := context.Background()
	user, err := a.authRepository.GetUserByEmail(req.Email)
	if err != nil {
		a.logger.Error().Err(err).Msg("Error Query Get User By Email")
		return "", err
	}
	if !user.Verified {
		a.logger.Error().Msgf("user not verified :%s", user.Email)
		return "", dto.Err_UNAUTHORIZED_USER_NOT_VERIFIED
	}

	ok := _utils.HashPasswordCompare(req.Password, user.Password)
	if !ok {
		a.logger.Error().Err(err).Msg("Password doesn't match")
		return "", dto.Err_UNAUTHORIZED_PASSWORD_DOESNT_MATCH
	}
	if user.TwoFactorEnabled {
		otp, err := a.g.GenerateOTP()
		if err != nil {
			a.logger.Error().Err(err).Msg("generate OTP error")
			return "", dto.Err_INTERNAL_GENERATE_OTP
		}
		key := fmt.Sprintf("OTP:%s", user.ID)
		if err := a.authRepository.SetResource(c, key, otp, 2*time.Minute); err != nil {
			a.logger.Error().Err(err).Msg("failed to set OTP")
			return "", err
		}

		go func() {
			subject := fmt.Sprintf("%s.%s", viper.GetString("jetstream.notification.subject.mail"), user.ID)
			msg := &_dto.MailNotificationMessage{
				Receiver: []string{user.Email},
				MsgType:  "OTP",
				Message:  otp,
			}
			marshalledMsg, err := json.Marshal(msg)
			if err != nil {
				a.logger.Error().Err(err).Msg("marshal data error")
				return
			}
			_, err = a.js.Publish(c, subject, []byte(marshalledMsg))
			if err != nil {
				a.logger.Error().Err(err).Msg("publish notification error")
			}
		}()
		return "", nil
	}

	token, claim, err := jwt.GenerateToken(user.ID, 1*time.Hour)
	if err != nil {
		a.logger.Error().Err(err).Msg("Error JWT Signing")
		return "", dto.Err_INTENAL_JWT_SIGNING
	}
	sessionKey := "session:" + claim.ID
	if err := a.authRepository.SetResource(c, sessionKey, token, 1*time.Hour); err != nil {
		a.logger.Error().Err(err).Msg("Error saving token to Redis")
		return "", err
	}
	return token, nil
}

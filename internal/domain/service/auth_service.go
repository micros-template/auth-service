package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	dto "github.com/micros-template/auth-service/internal/domain/dto"
	"github.com/micros-template/auth-service/internal/domain/repository"
	"github.com/micros-template/auth-service/internal/infrastructure/logger"
	_mq "github.com/micros-template/auth-service/internal/infrastructure/message-queue"
	"github.com/micros-template/auth-service/pkg/constant"
	"github.com/micros-template/auth-service/pkg/generators"
	"github.com/micros-template/auth-service/pkg/jwt"
	fpb "github.com/micros-template/proto-file/pkg/fpb"
	upb "github.com/micros-template/proto-user/pkg/upb"
	_dto "github.com/micros-template/sharedlib/dto"
	_utils "github.com/micros-template/sharedlib/utils"
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
		logEmitter        logger.LoggerInfra
	}
)

func New(authRepository repository.AuthRepository, userServiceClient upb.UserServiceClient, fileServiceClient fpb.FileServiceClient, logger zerolog.Logger, js _mq.Nats, g generators.RandomGenerator, logEmitter logger.LoggerInfra) AuthService {
	return &authService{
		authRepository:    authRepository,
		userServiceClient: userServiceClient,
		fileServiceClient: fileServiceClient,
		logger:            logger,
		js:                js,
		g:                 g,
		logEmitter:        logEmitter,
	}
}

func (a *authService) ChangePasswordService(userId string, resetPasswordToken string, req *dto.ChangePasswordRequest) error {
	if req.Password != req.ConfirmPassword {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", "password and confirm password doesn't match"); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
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
		return err
	}
	if rToken != resetPasswordToken {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", "resePasswordToken is not valid"); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
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
		go func() {
			if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("Update user failed. Err:%v", err.Error())); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
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
		go func() {
			if err := a.logEmitter.EmitLog("ERR", "User is not verified"); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		return dto.Err_UNAUTHORIZED_USER_NOT_VERIFIED
	}

	resetPasswordToken, err := a.g.GenerateToken()
	if err != nil {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("error generate verification token. Err:%v", err.Error())); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		return dto.Err_INTERNAL_GENERATE_TOKEN
	}

	key := fmt.Sprintf("resetPasswordToken:%s", user.ID)
	if err := a.authRepository.SetResource(ctx, key, resetPasswordToken, 1*time.Hour); err != nil {
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
		go func() {
			if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("marshal data error. Err:%v", err.Error())); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		return err
	}
	_, err = a.js.Publish(ctx, subject, []byte(marshalledMsg))
	if err != nil {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("publish notification error. Err:%v", err.Error())); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		if err := a.authRepository.RemoveResource(ctx, key); err != nil {
			go func() {
				if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("failed to remove reset password token. Err:%v", err.Error())); err != nil {
					a.logger.Error().Err(err).Msg("failed to emit log")
				}
			}()
		}
		return err
	}
	return nil
}

func (a *authService) ResendVerificationOTPService(email string) error {
	ctx := context.Background()
	user, err := a.authRepository.GetUserByEmail(email)
	if err != nil {
		return err
	}
	if !user.Verified {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", "User is not verified"); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		return dto.Err_UNAUTHORIZED_USER_NOT_VERIFIED
	}
	if !user.TwoFactorEnabled {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", "user is not activate 2FA"); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		return dto.Err_UNAUTHORIZED_2FA_DISABLED
	}
	otp, err := a.g.GenerateOTP()
	if err != nil {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("generate OTP error. Err:%v", err.Error())); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		return dto.Err_INTERNAL_GENERATE_OTP
	}
	key := fmt.Sprintf("OTP:%s", user.ID)
	if err := a.authRepository.SetResource(ctx, key, otp, 2*time.Minute); err != nil {
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
		go func() {
			if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("marshal data error. Err:%v", err.Error())); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		return err
	}
	_, err = a.js.Publish(ctx, subject, []byte(marshalledMsg))
	if err != nil {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("publish notification error. Err:%v", err.Error())); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		if err := a.authRepository.RemoveResource(ctx, key); err != nil {
			go func() {
				if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("failed to remove reset password token. Err:%v", err.Error())); err != nil {
					a.logger.Error().Err(err).Msg("failed to emit log")
				}
			}()
		}
		return err
	}
	return nil
}

func (a *authService) VerifyOTPService(otp, email string) (string, error) {
	ctx := context.Background()
	user, err := a.authRepository.GetUserByEmail(email)
	if err != nil {
		return "", err
	}
	key := fmt.Sprintf("OTP:%s", user.ID)
	rOTP, err := a.authRepository.GetResource(ctx, key)
	if err != nil {
		return "", err
	}
	if rOTP != otp {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("OTP is not valid. Err:%v", dto.Err_UNAUTHORIZED_OTP_INVALID.Error())); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		return "", dto.Err_UNAUTHORIZED_OTP_INVALID
	}
	err = a.authRepository.RemoveResource(ctx, key)
	if err != nil {
		return "", err
	}

	token, claims, err := jwt.GenerateToken(user.ID, 1*time.Hour)
	if err != nil {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("error JWT Signing. Err:%v", err.Error())); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		return "", dto.Err_INTENAL_JWT_SIGNING
	}
	sessionKey := "session:" + claims.ID
	if err := a.authRepository.SetResource(ctx, sessionKey, token, 1*time.Hour); err != nil {
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
		go func() {
			if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("user already verified. email:%s", email)); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		return dto.Err_CONFLICT_USER_ALREADY_VERIFIED
	}
	verificationToken, err := a.g.GenerateToken()
	if err != nil {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("error generate verification token. Err:%v", err.Error())); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		return dto.Err_INTERNAL_GENERATE_TOKEN
	}
	key := fmt.Sprintf("verificationToken:%s", user.ID)
	if err := a.authRepository.SetResource(ctx, key, verificationToken, 30*time.Minute); err != nil {
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
		go func() {
			if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("marshal data error. Err:%v", err.Error())); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		return err
	}
	_, err = a.js.Publish(ctx, subject, []byte(marshalledMsg))
	if err != nil {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("publish notification error. Err:%v", err.Error())); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		if err := a.authRepository.RemoveResource(ctx, key); err != nil {
			go func() {
				if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("failed to remove reset password token. Err:%v", err.Error())); err != nil {
					a.logger.Error().Err(err).Msg("failed to emit log")
				}
			}()
		}
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
			return err
		}
		if changeToken != rToken {
			go func() {
				if err := a.logEmitter.EmitLog("ERR", "changeEmailToken is invalid"); err != nil {
					a.logger.Error().Err(err).Msg("failed to emit log")
				}
			}()
			return dto.Err_UNAUTHORIZED_TOKEN_INVALID
		}
		newEmailkey := fmt.Sprintf("newEmail:%s", userId)
		newEmail, err := a.authRepository.GetResource(ctx, newEmailkey)
		if err != nil {
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
			go func() {
				if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("Update user failed. Err:%v", err.Error())); err != nil {
					a.logger.Error().Err(err).Msg("failed to emit log")
				}
			}()
			return err
		}
		err = a.authRepository.RemoveResource(ctx, key)
		if err != nil {
			return err
		}
		err = a.authRepository.RemoveResource(ctx, newEmailkey)
		if err != nil {
			return err
		}
	} else {
		if user.Verified {
			go func() {
				if err := a.logEmitter.EmitLog("ERR", "user already verified"); err != nil {
					a.logger.Error().Err(err).Msg("failed to emit log")
				}
			}()
			return dto.Err_CONFLICT_USER_ALREADY_VERIFIED
		}
		key = fmt.Sprintf("verificationToken:%s", userId)
		rToken, err := a.authRepository.GetResource(ctx, key)
		if err != nil {
			return err
		}
		if token != rToken {
			go func() {
				if err := a.logEmitter.EmitLog("ERR", "verificationeEmailToken is invalid"); err != nil {
					a.logger.Error().Err(err).Msg("failed to emit log")
				}
			}()
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
			go func() {
				if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("Update user failed. Err:%v", err.Error())); err != nil {
					a.logger.Error().Err(err).Msg("failed to emit log")
				}
			}()
			return err
		}
		err = a.authRepository.RemoveResource(ctx, key)
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *authService) VerifyService(token string) (string, error) {
	c := context.Background()
	claims, err := jwt.ValidateJWT(token)
	if err != nil {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("invalid jwt. Err:%v", err.Error())); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		return "", err
	}
	key := "session:" + claims.ID
	rToken, err := a.authRepository.GetResource(c, key)
	if err != nil {
		return "", err
	}
	if token != rToken {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", "invalid jwt. not match with state"); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		return "", dto.Err_UNAUTHORIZED_JWT_INVALID
	}

	return claims.UserId, nil
}

func (a *authService) LogoutService(token string) error {
	c := context.Background()
	claims, err := jwt.ValidateJWT(token)
	if err != nil {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("invalid jwt. Err:%v", err.Error())); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
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
		go func() {
			if err := a.logEmitter.EmitLog("ERR", "password and confirm password doesn't match"); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		return dto.Err_BAD_REQUEST_PASSWORD_DOESNT_MATCH
	}
	ext := ""
	if req.Image != nil && req.Image.Filename != "" {
		ext = _utils.GetFileNameExtension(req.Image.Filename)
		if ext != "jpg" && ext != "jpeg" && ext != "png" {
			go func() {
				if err := a.logEmitter.EmitLog("ERR", dto.Err_BAD_REQUEST_WRONG_EXTENSION.Error()); err != nil {
					a.logger.Error().Err(err).Msg("failed to emit log")
				}
			}()
			return dto.Err_BAD_REQUEST_WRONG_EXTENSION
		}
		if req.Image.Size > constant.MAX_UPLOAD_SIZE {
			go func() {
				if err := a.logEmitter.EmitLog("ERR", dto.Err_BAD_REQUEST_LIMIT_SIZE_EXCEEDED.Error()); err != nil {
					a.logger.Error().Err(err).Msg("failed to emit log")
				}
			}()
			return dto.Err_BAD_REQUEST_LIMIT_SIZE_EXCEEDED
		}
	}
	ctx := context.Background()
	exist, err := a.authRepository.GetUserByEmail(req.Email)
	if err != nil {
		if err != dto.Err_NOTFOUND_USER_NOT_FOUND {
			return err
		}
	}
	if exist != nil {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("User with this email exist. email: %s", req.Email)); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		return dto.Err_CONFLICT_EMAIL_EXIST
	}
	password, err := _utils.HashPassword(req.Password)
	if err != nil {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("Error hashing password. Err: %s", err.Error())); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		return dto.Err_INTERNAL_FAILED_HASH_PASSWORD
	}

	var imageName *string
	if req.Image != nil && req.Image.Filename != "" {
		image, err := _utils.FileToByte(req.Image)
		if err != nil {
			go func() {
				if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("error converting image. Err: %s", err.Error())); err != nil {
					a.logger.Error().Err(err).Msg("failed to emit log")
				}
			}()
			return dto.Err_INTERNAL_CONVERT_IMAGE
		}
		imageReq := &fpb.Image{
			Image: image,
			Ext:   ext,
		}
		resp, err := a.fileServiceClient.SaveProfileImage(ctx, imageReq)
		if err != nil {
			go func() {
				if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("Error uploading image to file service. err: %v", err.Error())); err != nil {
					a.logger.Error().Err(err).Msg("failed to emit log")
				}
			}()
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
		if _, err := a.fileServiceClient.RemoveProfileImage(ctx, &fpb.ImageName{Name: *imageName}); err != nil {
			go func() {
				if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("Error remove image via file service. err: %v", err.Error())); err != nil {
					a.logger.Error().Err(err).Msg("failed to emit log")
				}
			}()
		}
		return err
	}
	verificationToken, err := a.g.GenerateToken()
	if err != nil {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("error generate verification token. Err: %v", err.Error())); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		go func() {
			if _, err := a.userServiceClient.DeleteUser(context.Background(), &upb.UserId{
				UserId: userId,
			}); err != nil {
				if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("failed to delete user Err: %v", err.Error())); err != nil {
					a.logger.Error().Err(err).Msg("failed to emit log")
				}
			}
		}()
		return dto.Err_INTERNAL_GENERATE_TOKEN
	}

	key := fmt.Sprintf("verificationToken:%s", userId)
	if err := a.authRepository.SetResource(ctx, key, verificationToken, 30*time.Minute); err != nil {
		go func() {
			if _, err := a.userServiceClient.DeleteUser(context.Background(), &upb.UserId{
				UserId: userId,
			}); err != nil {
				if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("failed to delete user Err: %v", err.Error())); err != nil {
					a.logger.Error().Err(err).Msg("failed to emit log")
				}
			}
		}()
		return err
	}
	link := fmt.Sprintf("%s/%suserid=%s&token=%s", viper.GetString("app.url"), viper.GetString("app.verification_url"), userId, verificationToken)
	subject := fmt.Sprintf("%s.%s", viper.GetString("jetstream.notification.subject.mail"), userId)
	msg := &_dto.MailNotificationMessage{
		Receiver: []string{user.Email},
		MsgType:  "verification",
		Message:  link,
	}
	marshalledMsg, err := json.Marshal(msg)
	if err != nil {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("marshal data error. Err:%v", err.Error())); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		go func() {
			if _, err := a.userServiceClient.DeleteUser(context.Background(), &upb.UserId{
				UserId: userId,
			}); err != nil {
				if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("failed to delete user Err: %v", err.Error())); err != nil {
					a.logger.Error().Err(err).Msg("failed to emit log")
				}
			}
		}()
		return err
	}
	if _, err = a.js.Publish(ctx, subject, []byte(marshalledMsg)); err != nil {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("publish notification error. Err:%v", err.Error())); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		if err := a.authRepository.RemoveResource(ctx, key); err != nil {
			go func() {
				if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("failed to remove verificationEmailToken. Err:%v", err.Error())); err != nil {
					a.logger.Error().Err(err).Msg("failed to emit log")
				}
			}()
		}
		go func() {
			if _, err := a.userServiceClient.DeleteUser(context.Background(), &upb.UserId{
				UserId: userId,
			}); err != nil {
				if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("failed to delete user Err: %v", err.Error())); err != nil {
					a.logger.Error().Err(err).Msg("failed to emit log")
				}
			}
		}()
		return err
	}
	return nil
}

func (a *authService) LoginService(req dto.LoginRequest) (string, error) {
	c := context.Background()
	user, err := a.authRepository.GetUserByEmail(req.Email)
	if err != nil {
		return "", err
	}
	if !user.Verified {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", "user not verified"); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		return "", dto.Err_UNAUTHORIZED_USER_NOT_VERIFIED
	}

	ok := _utils.HashPasswordCompare(req.Password, user.Password)
	if !ok {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("Password doesn't match. email:%s", req.Email)); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		return "", dto.Err_UNAUTHORIZED_PASSWORD_DOESNT_MATCH
	}
	if user.TwoFactorEnabled {
		otp, err := a.g.GenerateOTP()
		if err != nil {
			if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("generate OTP error. Err: %s", err.Error())); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
			return "", dto.Err_INTERNAL_GENERATE_OTP
		}
		key := fmt.Sprintf("OTP:%s", user.ID)
		if err := a.authRepository.SetResource(c, key, otp, 2*time.Minute); err != nil {
			return "", err
		}

		subject := fmt.Sprintf("%s.%s", viper.GetString("jetstream.notification.subject.mail"), user.ID)
		msg := &_dto.MailNotificationMessage{
			Receiver: []string{user.Email},
			MsgType:  "OTP",
			Message:  otp,
		}
		marshalledMsg, err := json.Marshal(msg)
		if err != nil {
			go func() {
				if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("marshal data error. Err:%v", err.Error())); err != nil {
					a.logger.Error().Err(err).Msg("failed to emit log")
				}
			}()
			if err := a.authRepository.RemoveResource(context.Background(), key); err != nil {
				go func() {
					if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("failed to remove OTP. Err:%v", err.Error())); err != nil {
						a.logger.Error().Err(err).Msg("failed to emit log")
					}
				}()
			}
			return "", err
		}
		_, err = a.js.Publish(c, subject, []byte(marshalledMsg))
		if err != nil {
			go func() {
				if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("publish notification error. Err:%v", err.Error())); err != nil {
					a.logger.Error().Err(err).Msg("failed to emit log")
				}
			}()
			if err := a.authRepository.RemoveResource(context.Background(), key); err != nil {
				go func() {
					if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("failed to remove OTP. Err:%v", err.Error())); err != nil {
						a.logger.Error().Err(err).Msg("failed to emit log")
					}
				}()
			}
			return "", err
		}
		return "", nil
	}

	token, claim, err := jwt.GenerateToken(user.ID, 1*time.Hour)
	if err != nil {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("Error JWT Signing. Err:%v", err.Error())); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		return "", dto.Err_INTENAL_JWT_SIGNING
	}
	sessionKey := "session:" + claim.ID
	if err := a.authRepository.SetResource(c, sessionKey, token, 1*time.Hour); err != nil {
		return "", err
	}
	return token, nil
}

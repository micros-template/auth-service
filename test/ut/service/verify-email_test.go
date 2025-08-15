package service_test

import (
	"errors"
	"testing"
	"time"

	"github.com/micros-template/auth-service/internal/domain/service"
	"github.com/micros-template/auth-service/test/mocks"
	upb "github.com/micros-template/proto-user/pkg/upb"
	"github.com/micros-template/sharedlib/model"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type VerifyEmailServiceSuite struct {
	suite.Suite
	authService    service.AuthService
	mockAuthRepo   *mocks.MockAuthRepository
	mockUserClient *mocks.MockUserServiceClient
	mockLogEmitter *mocks.LoggerInfraMock
}

func (v *VerifyEmailServiceSuite) SetupSuite() {

	mockAuthRepo := new(mocks.MockAuthRepository)
	mockUserClient := new(mocks.MockUserServiceClient)
	mockFileClient := new(mocks.MockFileServiceClient)
	mockJetStream := new(mocks.MockNatsInfra)
	mockGenerator := new(mocks.MockRandomGenerator)
	mockLogEmitter := new(mocks.LoggerInfraMock)

	logger := zerolog.Nop()
	v.mockAuthRepo = mockAuthRepo
	v.mockUserClient = mockUserClient
	v.mockLogEmitter = mockLogEmitter
	v.authService = service.New(mockAuthRepo, mockUserClient, mockFileClient, logger, mockJetStream, mockGenerator, mockLogEmitter)
}

func (v *VerifyEmailServiceSuite) SetupTest() {
	v.mockAuthRepo.ExpectedCalls = nil
	v.mockUserClient.ExpectedCalls = nil
	v.mockLogEmitter.ExpectedCalls = nil

	v.mockAuthRepo.Calls = nil
	v.mockUserClient.Calls = nil
	v.mockLogEmitter.Calls = nil
}

func TestVerifyEmailServiceSuite(t *testing.T) {
	suite.Run(t, &VerifyEmailServiceSuite{})
}

func (v *VerifyEmailServiceSuite) TestAuthService_VerifyEmailService_SuccessVerifyEmail() {
	userId := "user-id-123"
	token := "valid-verification-token"

	mockUser := &model.User{
		ID:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         false,
		TwoFactorEnabled: false,
	}

	returnMessageUpdateUser := &upb.Status{Success: true}

	v.mockAuthRepo.On("GetUserByUserId", mock.Anything).Return(mockUser, nil)
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return(token, nil)
	v.mockUserClient.On("UpdateUser", mock.Anything, mock.Anything, mock.Anything).Return(returnMessageUpdateUser, nil)
	v.mockAuthRepo.On("RemoveResource", mock.Anything, mock.AnythingOfType("string")).Return(nil)

	err := v.authService.VerifyEmailService(userId, token, "")
	v.NoError(err)

	v.mockUserClient.AssertExpectations(v.T())
	v.mockAuthRepo.AssertExpectations(v.T())
}

func (v *VerifyEmailServiceSuite) TestAuthService_VerifyEmailService_SuccessChangeEmail() {
	userId := "user-id-123"
	changeToken := "valid-change-email-token"
	newEmail := "test2@example.com"
	mockUser := &model.User{
		ID:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         false,
		TwoFactorEnabled: false,
	}

	returnMessageUpdateUser := &upb.Status{Success: true}

	v.mockAuthRepo.On("GetUserByUserId", mock.Anything).Return(mockUser, nil)
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return(changeToken, nil)
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return(newEmail, nil)
	v.mockUserClient.On("UpdateUser", mock.Anything, mock.Anything, mock.Anything).Return(returnMessageUpdateUser, nil)
	v.mockAuthRepo.On("RemoveResource", mock.Anything, mock.AnythingOfType("string")).Return(nil)
	v.mockAuthRepo.On("RemoveResource", mock.Anything, mock.AnythingOfType("string")).Return(nil)

	err := v.authService.VerifyEmailService(userId, "", changeToken)
	v.NoError(err)

	v.mockUserClient.AssertExpectations(v.T())
	v.mockAuthRepo.AssertExpectations(v.T())
}

func (v *VerifyEmailServiceSuite) TestAuthService_VerifyEmailService_AlreadyVerified() {
	userId := "user-id-123"
	token := "valid-verification-token"

	mockUser := &model.User{
		ID:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         true,
		TwoFactorEnabled: false,
	}

	v.mockLogEmitter.On("EmitLog", "ERR", mock.Anything).Return(nil)
	v.mockAuthRepo.On("GetUserByUserId", mock.Anything).Return(mockUser, nil)

	err := v.authService.VerifyEmailService(userId, token, "")
	v.Error(err)
	v.mockAuthRepo.AssertExpectations(v.T())

	time.Sleep(time.Second)
	v.mockLogEmitter.AssertExpectations(v.T())
}

func (v *VerifyEmailServiceSuite) TestAuthService_VerifyEmailService_ExpiredToken() {
	userId := "user-id-123"
	token := "valid-verification-token"

	mockUser := &model.User{
		ID:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         false,
		TwoFactorEnabled: false,
	}

	v.mockAuthRepo.On("GetUserByUserId", mock.Anything).Return(mockUser, nil)
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return("", errors.New("not-found cause expired"))

	err := v.authService.VerifyEmailService(userId, token, "")
	v.Error(err)

	v.mockAuthRepo.AssertExpectations(v.T())
}

func (v *VerifyEmailServiceSuite) TestAuthService_VerifyEmailService_TokenNotMatch() {
	userId := "user-id-123"
	token := "invalid-verification-token"

	mockUser := &model.User{
		ID:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         false,
		TwoFactorEnabled: false,
	}

	v.mockAuthRepo.On("GetUserByUserId", mock.Anything).Return(mockUser, nil)
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return("valid-verification-token", nil)
	v.mockLogEmitter.On("EmitLog", "ERR", mock.Anything).Return(nil)

	err := v.authService.VerifyEmailService(userId, token, "")
	v.Error(err)

	v.mockAuthRepo.AssertExpectations(v.T())
	time.Sleep(time.Second)
	v.mockLogEmitter.AssertExpectations(v.T())
}

func (v *VerifyEmailServiceSuite) TestAuthService_VerifyEmailService_UserNotFoundWhenUpdating() {
	userId := "user-id-123"
	token := "valid-verification-token"

	mockUser := &model.User{
		ID:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         false,
		TwoFactorEnabled: false,
	}

	v.mockAuthRepo.On("GetUserByUserId", mock.Anything).Return(mockUser, nil)
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return(token, nil)
	v.mockUserClient.On("UpdateUser", mock.Anything, mock.Anything, mock.Anything).Return(nil, status.Error(codes.NotFound, "user-not-found"))
	v.mockLogEmitter.On("EmitLog", "ERR", mock.Anything).Return(nil)

	err := v.authService.VerifyEmailService(userId, token, "")
	v.Error(err)

	v.mockUserClient.AssertExpectations(v.T())
	v.mockAuthRepo.AssertExpectations(v.T())

	time.Sleep(time.Second)
	v.mockLogEmitter.AssertExpectations(v.T())
}

func (v *VerifyEmailServiceSuite) TestAuthService_VerifyEmailService_ExpiredChangeEmailToken() {
	userId := "user-id-123"
	changeToken := "valid-change-email-verification-token"

	mockUser := &model.User{
		ID:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         false,
		TwoFactorEnabled: false,
	}

	v.mockAuthRepo.On("GetUserByUserId", mock.Anything).Return(mockUser, nil)
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return("", errors.New("not-found cause expired"))

	err := v.authService.VerifyEmailService(userId, "", changeToken)
	v.Error(err)

	v.mockAuthRepo.AssertExpectations(v.T())
}

func (v *VerifyEmailServiceSuite) TestAuthService_VerifyEmailService_ChangeTokenNotMatch() {
	userId := "user-id-123"
	changeToken := "invalid-change-email-verification-token"

	mockUser := &model.User{
		ID:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         false,
		TwoFactorEnabled: false,
	}

	v.mockAuthRepo.On("GetUserByUserId", mock.Anything).Return(mockUser, nil)
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return("valid-change-email-verification-token", nil)
	v.mockLogEmitter.On("EmitLog", "ERR", mock.Anything).Return(nil)

	err := v.authService.VerifyEmailService(userId, "", changeToken)
	v.Error(err)

	v.mockAuthRepo.AssertExpectations(v.T())
	time.Sleep(time.Second)
	v.mockLogEmitter.AssertExpectations(v.T())
}

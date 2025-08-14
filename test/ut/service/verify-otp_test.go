package service_test

import (
	"errors"
	"testing"
	"time"

	"10.1.20.130/dropping/auth-service/internal/domain/dto"
	"10.1.20.130/dropping/auth-service/internal/domain/service"
	"10.1.20.130/dropping/auth-service/test/mocks"
	"10.1.20.130/dropping/sharedlib/model"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type VerifyOTPServiceSuite struct {
	suite.Suite
	authService    service.AuthService
	mockAuthRepo   *mocks.MockAuthRepository
	mockLogEmitter *mocks.LoggerServiceUtilMock
}

func (v *VerifyOTPServiceSuite) SetupSuite() {

	mockAuthRepo := new(mocks.MockAuthRepository)
	mockUserClient := new(mocks.MockUserServiceClient)
	mockFileClient := new(mocks.MockFileServiceClient)
	mockJetStream := new(mocks.MockNatsInfra)
	mockGenerator := new(mocks.MockRandomGenerator)
	mockLogEmitter := new(mocks.LoggerServiceUtilMock)

	logger := zerolog.Nop()
	v.mockAuthRepo = mockAuthRepo
	v.mockLogEmitter = mockLogEmitter
	v.authService = service.New(mockAuthRepo, mockUserClient, mockFileClient, logger, mockJetStream, mockGenerator, mockLogEmitter)
}

func (v *VerifyOTPServiceSuite) SetupTest() {
	v.mockAuthRepo.ExpectedCalls = nil
	v.mockLogEmitter.ExpectedCalls = nil

	v.mockAuthRepo.Calls = nil
	v.mockLogEmitter.Calls = nil
}

func TestVerifyOTPServiceSuite(t *testing.T) {
	suite.Run(t, &VerifyOTPServiceSuite{})
}

func (v *VerifyOTPServiceSuite) TestAuthService_VerifyOTPService_Success() {
	otp := "123456"
	email := "test@example.com"

	mockUser := &model.User{
		ID:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         true,
		TwoFactorEnabled: true,
	}

	v.mockAuthRepo.On("GetUserByEmail", mock.Anything).Return(mockUser, nil)
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return(otp, nil)
	v.mockAuthRepo.On("RemoveResource", mock.Anything, mock.AnythingOfType("string")).Return(nil)
	v.mockAuthRepo.On("SetResource", mock.Anything, mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil)

	token, err := v.authService.VerifyOTPService(otp, email)
	v.NotEmpty(token)
	v.NoError(err)

	v.mockAuthRepo.AssertExpectations(v.T())
}

func (v *VerifyOTPServiceSuite) TestAuthService_VerifyOTPService_UserNotFound() {
	otp := "123456"
	email := "test@example.com"

	v.mockAuthRepo.On("GetUserByEmail", mock.Anything).Return(nil, dto.Err_NOTFOUND_USER_NOT_FOUND)

	token, err := v.authService.VerifyOTPService(otp, email)
	v.Empty(token)
	v.Error(err)

	v.mockAuthRepo.AssertExpectations(v.T())
}

func (v *VerifyOTPServiceSuite) TestAuthService_VerifyOTPService_ExpiredOTP() {
	otp := "123456"
	email := "test@example.com"

	mockUser := &model.User{
		ID:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         true,
		TwoFactorEnabled: true,
	}

	v.mockAuthRepo.On("GetUserByEmail", mock.Anything).Return(mockUser, nil)
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return("", errors.New("token-not-found"))

	token, err := v.authService.VerifyOTPService(otp, email)

	v.Empty(token)
	v.Error(err)

	v.mockAuthRepo.AssertExpectations(v.T())
}

func (v *VerifyOTPServiceSuite) TestAuthService_VerifyOTPService_InvalidOTP() {
	otp := "123456"
	email := "test@example.com"

	mockUser := &model.User{
		ID:               "user-id-123",
		Email:            "test@example.com",
		Password:         "$2a$10$Nwjs8PdFOCnjbRM3x/2WAuEtqOSrm6wHByYaw0ZDp5mV7e560dIb6",
		Verified:         true,
		TwoFactorEnabled: true,
	}

	v.mockAuthRepo.On("GetUserByEmail", mock.Anything).Return(mockUser, nil)
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return("654321", nil)
	v.mockLogEmitter.On("EmitLog", "ERR", mock.Anything).Return(nil)

	token, err := v.authService.VerifyOTPService(otp, email)
	v.Empty(token)
	v.Error(err)

	v.mockAuthRepo.AssertExpectations(v.T())
	time.Sleep(time.Second)

	v.mockLogEmitter.AssertExpectations(v.T())
}

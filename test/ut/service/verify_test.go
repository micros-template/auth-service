package service_test

import (
	"errors"
	"testing"
	"time"

	"github.com/micros-template/auth-service/internal/domain/service"
	"github.com/micros-template/auth-service/test/mocks"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type VerifyServiceSuite struct {
	suite.Suite
	authService    service.AuthService
	mockAuthRepo   *mocks.MockAuthRepository
	mockLogEmitter *mocks.LoggerInfraMock
}

func (v *VerifyServiceSuite) SetupSuite() {

	mockAuthRepo := new(mocks.MockAuthRepository)
	mockUserClient := new(mocks.MockUserServiceClient)
	mockFileClient := new(mocks.MockFileServiceClient)
	mockJetStream := new(mocks.MockNatsInfra)
	mockGenerator := new(mocks.MockRandomGenerator)
	mockLogEmitter := new(mocks.LoggerInfraMock)

	logger := zerolog.Nop()
	v.mockAuthRepo = mockAuthRepo
	v.mockLogEmitter = mockLogEmitter
	v.authService = service.New(mockAuthRepo, mockUserClient, mockFileClient, logger, mockJetStream, mockGenerator, mockLogEmitter)
}

func (v *VerifyServiceSuite) SetupTest() {
	v.mockAuthRepo.ExpectedCalls = nil
	v.mockAuthRepo.Calls = nil
}

func TestVerifyServiceSuite(t *testing.T) {
	suite.Run(t, &VerifyServiceSuite{})
}

func (v *VerifyServiceSuite) TestAuthService_VerifyService_Success() {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidXNlci1pZC0xMjMiLCJpYXQiOjE3NTEzNjEzOTJ9.CwkzkHgPYAxd6TXG4_ooMFczGvjn3Qr2_7T6W6YCDgI"
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidXNlci1pZC0xMjMiLCJpYXQiOjE3NTEzNjEzOTJ9.CwkzkHgPYAxd6TXG4_ooMFczGvjn3Qr2_7T6W6YCDgI", nil)

	userId, err := v.authService.VerifyService(jwt)

	v.Equal(userId, "user-id-123")
	v.NoError(err)

	v.mockAuthRepo.AssertExpectations(v.T())
}

func (v *VerifyServiceSuite) TestAuthService_VerifyService_NotValidOrExpire() {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidXNlci1pZC0xMjMiLCJleHAiOjE3NTEzNjIwODgsImlhdCI6MTc1MTM2MjA4OH0.quJxCGSx9yQEhdHaZDFEQ7x_shNjb-nuE5FMqtuVKvA"
	v.mockLogEmitter.On("EmitLog", "ERR", mock.Anything).Return(nil)

	_, err := v.authService.VerifyService(jwt)
	v.Error(err)

	time.Sleep(time.Second)
	v.mockLogEmitter.AssertExpectations(v.T())
}

func (v *VerifyServiceSuite) TestAuthService_VerifyService_DifferentWithState() {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidXNlci1pZC0xMjMiLCJpYXQiOjE3NTEzNjEzOTJ9.CwkzkHgPYAxd6TXG4_ooMFczGvjn3Qr2_7T6W6YCDgI"
	returnedJwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidXNlci1pZC0xMjMiLCJpYXQiOjE3NTEzNjE5OTN9.hutDnLuLsqZSEtOmytC-x25Fria5ycPjd_4XC47C2uM"

	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return(returnedJwt, nil)
	v.mockLogEmitter.On("EmitLog", "ERR", mock.Anything).Return(nil)

	_, err := v.authService.VerifyService(jwt)

	v.Error(err)
	v.mockAuthRepo.AssertExpectations(v.T())

	time.Sleep(time.Second)
	v.mockLogEmitter.AssertExpectations(v.T())
}

func (v *VerifyServiceSuite) TestAuthService_VerifyService_NotFound() {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidXNlci1pZC0xMjMiLCJpYXQiOjE3NTEzNjEzOTJ9.CwkzkHgPYAxd6TXG4_ooMFczGvjn3Qr2_7T6W6YCDgI"
	v.mockAuthRepo.On("GetResource", mock.Anything, mock.AnythingOfType("string")).Return("", errors.New("notfound"))

	_, err := v.authService.VerifyService(jwt)

	v.Error(err)

	v.mockAuthRepo.AssertExpectations(v.T())
}

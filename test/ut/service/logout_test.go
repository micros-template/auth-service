package service_test

import (
	"testing"
	"time"

	"10.1.20.130/dropping/auth-service/internal/domain/service"
	"10.1.20.130/dropping/auth-service/test/mocks"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type LogoutServiceSuite struct {
	suite.Suite
	authService    service.AuthService
	mockAuthRepo   *mocks.MockAuthRepository
	mockUserClient *mocks.MockUserServiceClient
	mockFileClient *mocks.MockFileServiceClient
	mockJetStream  *mocks.MockNatsInfra
	mockGenerator  *mocks.MockRandomGenerator
	mockLogEmitter *mocks.LoggerInfraMock
}

func (l *LogoutServiceSuite) SetupSuite() {

	mockAuthRepo := new(mocks.MockAuthRepository)
	mockUserClient := new(mocks.MockUserServiceClient)
	mockFileClient := new(mocks.MockFileServiceClient)
	mockJetStream := new(mocks.MockNatsInfra)
	mockGenerator := new(mocks.MockRandomGenerator)
	mockLogEmitter := new(mocks.LoggerInfraMock)

	logger := zerolog.Nop()
	l.mockAuthRepo = mockAuthRepo
	l.mockUserClient = mockUserClient
	l.mockFileClient = mockFileClient
	l.mockJetStream = mockJetStream
	l.mockGenerator = mockGenerator
	l.mockLogEmitter = mockLogEmitter
	l.authService = service.New(mockAuthRepo, mockUserClient, mockFileClient, logger, mockJetStream, mockGenerator, mockLogEmitter)
}

func (l *LogoutServiceSuite) SetupTest() {
	l.mockAuthRepo.ExpectedCalls = nil
	l.mockUserClient.ExpectedCalls = nil
	l.mockFileClient.ExpectedCalls = nil
	l.mockJetStream.ExpectedCalls = nil
	l.mockGenerator.ExpectedCalls = nil
	l.mockLogEmitter.ExpectedCalls = nil

	l.mockAuthRepo.Calls = nil
	l.mockUserClient.Calls = nil
	l.mockFileClient.Calls = nil
	l.mockJetStream.Calls = nil
	l.mockGenerator.Calls = nil
	l.mockLogEmitter.Calls = nil
}

func TestLogoutServiceSuite(t *testing.T) {
	suite.Run(t, &LogoutServiceSuite{})
}

func (l *LogoutServiceSuite) TestAuthService_LogoutService_Success() {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidXNlci1pZC0xMjMiLCJpYXQiOjE3NTEzNjEzOTJ9.CwkzkHgPYAxd6TXG4_ooMFczGvjn3Qr2_7T6W6YCDgI"

	l.mockAuthRepo.On("RemoveResource", mock.Anything, mock.AnythingOfType("string")).Return(nil)

	err := l.authService.LogoutService(jwt)

	l.NoError(err)
	l.mockAuthRepo.AssertExpectations(l.T())
}
func (l *LogoutServiceSuite) TestAuthService_LogoutService_TokenInvalid() {
	jwt := "access-token"

	l.mockLogEmitter.On("EmitLog", "ERR", mock.Anything).Return(nil)
	err := l.authService.LogoutService(jwt)
	l.Error(err)

	time.Sleep(time.Second)
	l.mockLogEmitter.AssertExpectations(l.T())

}

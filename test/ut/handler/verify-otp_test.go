package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/micros-template/auth-service/internal/domain/dto"
	"github.com/micros-template/auth-service/internal/domain/handler"
	"github.com/micros-template/auth-service/test/mocks"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type VerifyOTPHandlerSuite struct {
	suite.Suite
	authHandler     handler.AuthHandler
	mockAuthService *mocks.MockAuthService
	mockLogEmitter  *mocks.LoggerInfraMock
}

func (l *VerifyOTPHandlerSuite) SetupSuite() {
	logger := zerolog.Nop()
	mockedAuthService := new(mocks.MockAuthService)
	mockedLogEmitter := new(mocks.LoggerInfraMock)

	l.mockAuthService = mockedAuthService
	l.mockLogEmitter = mockedLogEmitter
	l.authHandler = handler.New(mockedAuthService, mockedLogEmitter, logger)
}

func (l *VerifyOTPHandlerSuite) SetupTest() {
	l.mockAuthService.ExpectedCalls = nil
	l.mockLogEmitter.ExpectedCalls = nil
	l.mockAuthService.Calls = nil
	l.mockLogEmitter.Calls = nil
	gin.SetMode(gin.TestMode)
}

func TestVerifyOTPHandlerSuite(t *testing.T) {
	suite.Run(t, &VerifyOTPHandlerSuite{})
}

func (l *VerifyOTPHandlerSuite) TestAuthHandler_VerifyOTPHandler_Success() {
	reqBody := &bytes.Buffer{}

	input := dto.VerifyOTPRequest{
		Email: "test@example.com",
		OTP:   "123456",
	}

	encoder := gin.H{
		"email": "test@example.com",
		"otp":   "123456",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	request := httptest.NewRequest("POST", "/verify-otp", reqBody)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	l.mockLogEmitter.On("EmitLog", "INFO", mock.Anything).Return(nil)
	l.mockAuthService.On("VerifyOTPService", input.OTP, input.Email).Return("mocked-token", nil)
	l.authHandler.VerifyOTP(ctx)

	l.Equal(200, w.Code)
	l.Contains(w.Body.String(), "mocked-token")
	l.mockAuthService.AssertExpectations(l.T())

	time.Sleep(time.Second)
	l.mockLogEmitter.AssertExpectations(l.T())
}

func (l *VerifyOTPHandlerSuite) TestAuthHandler_VerifyOTPHandler_InvalidInput() {
	reqBody := &bytes.Buffer{}

	encoder := gin.H{
		"email": "test@example.com",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	request := httptest.NewRequest("POST", "/verify-otp", reqBody)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	l.mockLogEmitter.On("EmitLog", "ERR", mock.Anything).Return(nil)

	l.authHandler.VerifyOTP(ctx)

	l.Equal(400, w.Code)
	l.Contains(w.Body.String(), "invalid input")

	time.Sleep(time.Second)
	l.mockLogEmitter.AssertExpectations(l.T())
}

func (l *VerifyOTPHandlerSuite) TestAuthHandler_VerifyOTPHandler_InvalidOTP() {
	reqBody := &bytes.Buffer{}

	input := dto.VerifyOTPRequest{
		Email: "test@example.com",
		OTP:   "123456",
	}

	encoder := gin.H{
		"email": "test@example.com",
		"otp":   "123456",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	request := httptest.NewRequest("POST", "/verify-otp", reqBody)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	l.mockAuthService.On("VerifyOTPService", input.OTP, input.Email).Return("", dto.Err_UNAUTHORIZED_OTP_INVALID)
	l.authHandler.VerifyOTP(ctx)

	l.Equal(401, w.Code)
	l.Contains(w.Body.String(), dto.Err_UNAUTHORIZED_OTP_INVALID.Error())
	l.mockAuthService.AssertExpectations(l.T())
}

func (l *VerifyOTPHandlerSuite) TestAuthHandler_VerifyOTPHandler_ExpireOTP() {
	reqBody := &bytes.Buffer{}

	input := dto.VerifyOTPRequest{
		Email: "test@example.com",
		OTP:   "123456",
	}

	encoder := gin.H{
		"email": "test@example.com",
		"otp":   "123456",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	request := httptest.NewRequest("POST", "/verify-otp", reqBody)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	l.mockAuthService.On("VerifyOTPService", input.OTP, input.Email).Return("", dto.Err_NOTFOUND_KEY_NOTFOUND)
	l.authHandler.VerifyOTP(ctx)

	l.Equal(404, w.Code)
	l.Contains(w.Body.String(), "otp is invalid")
	l.mockAuthService.AssertExpectations(l.T())
}

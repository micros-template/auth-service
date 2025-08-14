package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"10.1.20.130/dropping/auth-service/internal/domain/dto"
	"10.1.20.130/dropping/auth-service/internal/domain/handler"
	"10.1.20.130/dropping/auth-service/test/mocks"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type ResetPasswordHandlerSuite struct {
	suite.Suite
	authHandler     handler.AuthHandler
	mockAuthService *mocks.MockAuthService
	mockLogEmitter  *mocks.LoggerInfraMock
}

func (r *ResetPasswordHandlerSuite) SetupSuite() {
	logger := zerolog.Nop()
	mockedAuthService := new(mocks.MockAuthService)
	mockedLogEmitter := new(mocks.LoggerInfraMock)

	r.mockAuthService = mockedAuthService
	r.mockLogEmitter = mockedLogEmitter
	r.authHandler = handler.New(mockedAuthService, mockedLogEmitter, logger)
}

func (r *ResetPasswordHandlerSuite) SetupTest() {
	r.mockAuthService.ExpectedCalls = nil
	r.mockLogEmitter.ExpectedCalls = nil

	r.mockAuthService.Calls = nil
	r.mockLogEmitter.Calls = nil
	gin.SetMode(gin.TestMode)
}

func TestResetPasswordHandlerSuite(t *testing.T) {
	suite.Run(t, &ResetPasswordHandlerSuite{})
}

func (r *ResetPasswordHandlerSuite) TestAuthHandler_ResetPasswordHandler_Success() {
	reqBody := &bytes.Buffer{}

	input := dto.ResetPasswordRequest{
		Email: "test@example.com",
	}

	encoder := gin.H{
		"email": "test@example.com",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	request := httptest.NewRequest("POST", "/reset-password", reqBody)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	r.mockAuthService.On("ResetPasswordService", input.Email).Return(nil)
	r.authHandler.ResetPassword(ctx)

	r.Equal(200, w.Code)
	r.Contains(w.Body.String(), "Reset password email has been sent")
	r.mockAuthService.AssertExpectations(r.T())
}

func (r *ResetPasswordHandlerSuite) TestAuthHandler_ResetPasswordHandler_MissingInput() {
	reqBody := &bytes.Buffer{}

	encoder := gin.H{}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	request := httptest.NewRequest("POST", "/reset-password", reqBody)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	r.mockLogEmitter.On("EmitLog", "ERR", mock.Anything).Return(nil)
	r.authHandler.ResetPassword(ctx)

	r.Equal(400, w.Code)
	r.Contains(w.Body.String(), "missing email")

	time.Sleep(time.Second)
	r.mockLogEmitter.AssertExpectations(r.T())
}

func (r *ResetPasswordHandlerSuite) TestAuthHandler_ResetPasswordHandler_UserNotFound() {
	reqBody := &bytes.Buffer{}

	input := dto.ResetPasswordRequest{
		Email: "test@example.com",
	}

	encoder := gin.H{
		"email": "test@example.com",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	request := httptest.NewRequest("POST", "/reset-password", reqBody)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = request

	r.mockAuthService.On("ResetPasswordService", input.Email).Return(dto.Err_NOTFOUND_USER_NOT_FOUND)
	r.authHandler.ResetPassword(ctx)

	r.Equal(404, w.Code)
	r.Contains(w.Body.String(), "user not found")
	r.mockAuthService.AssertExpectations(r.T())
}

package handler_test

import (
	"net/http"
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

type VerifyHandlerSuite struct {
	suite.Suite
	authHandler     handler.AuthHandler
	mockAuthService *mocks.MockAuthService
	mockLogEmitter  *mocks.LoggerServiceUtilMock
}

func (v *VerifyHandlerSuite) SetupSuite() {
	logger := zerolog.Nop()
	mockedAuthService := new(mocks.MockAuthService)
	mockedLogEmitter := new(mocks.LoggerServiceUtilMock)

	v.mockAuthService = mockedAuthService
	v.mockLogEmitter = mockedLogEmitter
	v.authHandler = handler.New(mockedAuthService, mockedLogEmitter, logger)
}

func (v *VerifyHandlerSuite) SetupTest() {
	v.mockAuthService.ExpectedCalls = nil
	v.mockLogEmitter.ExpectedCalls = nil
	v.mockAuthService.Calls = nil
	v.mockLogEmitter.Calls = nil
	gin.SetMode(gin.TestMode)
}

func TestVerifyHandlerSuite(t *testing.T) {
	suite.Run(t, &VerifyHandlerSuite{})
}

func (v *VerifyHandlerSuite) TestAuthHandler_VerifyHandler_Success() {
	token := "Bearer validtoken"
	userID := "12345"

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/verify", nil)
	ctx.Request.Header.Set("Authorization", token)

	v.mockAuthService.On("VerifyService", "validtoken").Return(userID, nil)

	v.authHandler.Verify(ctx)

	v.Equal(http.StatusNoContent, w.Code)
	v.Equal(`{"user_id":"12345"}`, w.Header().Get("User-Data"))
	v.mockAuthService.AssertExpectations(v.T())
}

func (v *VerifyHandlerSuite) TestAuthHandler_VerifyHandler_MissingToken() {
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/verify", nil)
	v.mockLogEmitter.On("EmitLog", "ERR", mock.Anything).Return(nil)

	v.authHandler.Verify(ctx)

	v.Equal(http.StatusUnauthorized, w.Code)
	v.Contains(w.Body.String(), "Token is missing")

	time.Sleep(time.Second)
	v.mockLogEmitter.AssertExpectations(v.T())
}

func (v *VerifyHandlerSuite) TestAuthHandler_VerifyHandler_NotFoundKey() {
	token := "Bearer notfoundtoken"
	v.mockAuthService.On("VerifyService", "notfoundtoken").Return("", dto.Err_NOTFOUND_KEY_NOTFOUND)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/verify", nil)
	ctx.Request.Header.Set("Authorization", token)

	v.authHandler.Verify(ctx)

	v.Equal(http.StatusUnauthorized, w.Code)
	v.Contains(w.Body.String(), dto.Err_NOTFOUND_KEY_NOTFOUND.Error())
}

func (v *VerifyHandlerSuite) TestAuthHandler_VerifyHandler_InvalidFormat() {
	token := "Bearer"

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/verify", nil)
	ctx.Request.Header.Set("Authorization", token)
	v.mockLogEmitter.On("EmitLog", "ERR", mock.Anything).Return(nil)

	v.authHandler.Logout(ctx)

	v.Equal(http.StatusUnauthorized, w.Code)

	time.Sleep(time.Second)
	v.mockLogEmitter.AssertExpectations(v.T())
}

func (v *VerifyHandlerSuite) TestAuthHandler_VerifyHandler_UnauthorizedJWTInvalid() {
	token := "Bearer invalidjwt"
	v.mockAuthService.On("VerifyService", "invalidjwt").Return("", dto.Err_UNAUTHORIZED_JWT_INVALID)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("GET", "/verify", nil)
	ctx.Request.Header.Set("Authorization", token)

	v.authHandler.Verify(ctx)

	v.Equal(http.StatusUnauthorized, w.Code)
	v.Contains(w.Body.String(), dto.Err_UNAUTHORIZED_JWT_INVALID.Error())
}

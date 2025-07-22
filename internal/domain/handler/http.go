package handler

import (
	"net/http"

	"10.1.20.130/dropping/auth-service/docs"
	"github.com/gin-gonic/gin"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func AuthRoutes(r *gin.Engine, ah AuthHandler) *gin.Engine {
	docs.SwaggerInfo.BasePath = "/api/v1/auth"
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))
	r.GET("/healthy", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, "Healthy")
	})
	{
		r.POST("/login", ah.Login)
		r.POST("/register", ah.Register)
		r.POST("/verify", ah.Verify)
		r.POST("/logout", ah.Logout)
		r.GET("/verify-email", ah.VerifyEmail)
		r.POST("/resend-verification-email", ah.ResendVerficationEmail)
		r.POST("/verify-otp", ah.VerifyOTP)
		r.POST("/resend-verification-otp", ah.ResendVerificationOTP)
		r.POST("/reset-password", ah.ResetPassword)
		r.PATCH("/change-password", ah.ChangePassword)
	}
	return r
}

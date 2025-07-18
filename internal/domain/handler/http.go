package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func AuthRoutes(r *gin.Engine, ah AuthHandler) *gin.Engine {
	{
		r.GET("/healthy", func(ctx *gin.Context) {
			ctx.JSON(http.StatusOK, "Healthy")
		})
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

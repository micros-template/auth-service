package router

import (
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/micros-template/log-service/pkg"
	middleware "github.com/micros-template/sharedlib/middleware"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

func New(logEmitter pkg.LogEmitter, zerolog zerolog.Logger) *gin.Engine {
	env := os.Getenv("ENV")
	if env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New()
	r.Use(middleware.AccessLogger(logEmitter, "auth_service", zerolog))

	allowOrigins := viper.GetString("server.cors.allow_origins")
	allowMethods := viper.GetString("server.cors.allow_methods")
	allowHeaders := viper.GetString("server.cors.allow_headers")
	exposeHeaders := viper.GetString("server.cors.expose_headers")
	allowCredentials := viper.GetBool("server.cors.allow_credential")
	maxAge := viper.GetInt("server.cors.max_age")
	r.Use(cors.New(cors.Config{
		AllowOrigins:     strings.Split(allowOrigins, ","),
		AllowMethods:     strings.Split(allowMethods, ","),
		AllowHeaders:     strings.Split(allowHeaders, ","),
		ExposeHeaders:    strings.Split(exposeHeaders, ","),
		AllowCredentials: allowCredentials,
		MaxAge:           time.Duration(maxAge),
	}))

	return r
}

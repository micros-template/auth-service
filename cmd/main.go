// @title Auth Service API
// @version 1.0
// @description Authentication service API for user management, registration, login, and verification
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @host localhost:8081
// @BasePath /api/v1/auth

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
package main

import (
	"context"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/micros-template/auth-service/cmd/bootstrap"
	"github.com/micros-template/auth-service/cmd/server"
	"github.com/spf13/viper"
)

func main() {
	log.SetOutput(io.Discard)
	container := bootstrap.Run()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	httpServerReady := make(chan bool)
	httpServerDone := make(chan struct{})
	httpServer := &server.Server{
		Container:   container,
		ServerReady: httpServerReady,
		Address:     ":" + viper.GetString("app.http.port"),
	}
	go func() {
		httpServer.Run(ctx)
		close(httpServerDone)
	}()

	<-httpServerReady

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGABRT, syscall.SIGTERM)

	<-sig
	cancel()
}

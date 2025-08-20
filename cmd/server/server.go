package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/micros-template/auth-service/internal/domain/handler"
	"github.com/micros-template/auth-service/internal/infrastructure/grpc"
	"github.com/micros-template/auth-service/internal/infrastructure/logger"
	event "github.com/micros-template/event-bus-client/pkg/event/user"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"go.uber.org/dig"
)

type Server struct {
	Container   *dig.Container
	ServerReady chan bool
	Address     string
}

func (s *Server) Run(ctx context.Context) {
	err := s.Container.Invoke(
		func(
			logger zerolog.Logger,
			router *gin.Engine,
			grpcClientManager *grpc.GRPCClientManager,
			redis *redis.Client,
			nc *nats.Conn,
			ah handler.AuthHandler,
			pgx *pgxpool.Pool,
			ue event.UserEventConsumer,
			js jetstream.JetStream,
			logEmitter logger.LoggerInfra,
		) {
			defer grpcClientManager.CloseAllConnections()
			defer func() {
				if err := redis.Close(); err != nil {
					logger.Error().Err(err).Msg("Failed to close Redis client")
				}
			}()
			defer func() {
				if err := nc.Drain(); err != nil {
					logger.Error().Err(err).Msg("Failed to drain nats client")
				}
			}()
			defer pgx.Close()

			router.Use(gin.Recovery())
			handler.AuthRoutes(router, ah)
			srv := &http.Server{
				Addr:              s.Address,
				Handler:           router,
				ReadHeaderTimeout: 5 * time.Second,
			}

			go func() {
				e := os.Getenv("ENV")
				switch e {
				case "test":
					if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
						go func() {
							if err := logEmitter.EmitLog("ERR", fmt.Sprintf("failed to listen ans serve http server:%v", err)); err != nil {
								logger.Error().Err(err).Msg("failed to emit log")
							}
						}()
						logger.Fatal().Err(err).Msg("Failed to listen and serve http server")
					}
				default:
					if err := srv.ListenAndServeTLS("./config/cert/server.crt", "./config/cert/server.key"); err != nil && err != http.ErrServerClosed {
						go func() {
							if err := logEmitter.EmitLog("ERR", fmt.Sprintf("failed to listen ans serve http server:%v", err)); err != nil {
								logger.Error().Err(err).Msg("failed to emit log")
							}
						}()
						logger.Fatal().Err(err).Msg("Failed to listen and serve http server")
					}
				}
			}()

			// init consumer here
			go ue.StartConsume()

			if s.ServerReady != nil {
				for range 50 {
					conn, err := net.DialTimeout("tcp", s.Address, 100*time.Millisecond)
					if err == nil {
						if err := conn.Close(); err != nil {
							if err := logEmitter.EmitLog("ERR", fmt.Sprintf("establish check connection failed to close:%v", err)); err != nil {
								logger.Error().Err(err).Msg("failed to emit log")
							}
							logger.Fatal().Err(err).Msg("establish check connection failed to close")
						}
						s.ServerReady <- true
						break
					}
					time.Sleep(100 * time.Millisecond)
				}
			}

			if err := logEmitter.EmitLog("INFO", fmt.Sprintf("HTTP Server Starting in port %s", s.Address)); err != nil {
				logger.Error().Err(err).Msg("failed to emit log")
			}
			logger.Info().Msgf("HTTP Server Starting in port %s", s.Address)

			<-ctx.Done()
			if err := logEmitter.EmitLog("INFO", "Shutting down HTTP server..."); err != nil {
				logger.Error().Err(err).Msg("failed to emit log")
			}
			logger.Info().Msg("Shutting down server...")

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := srv.Shutdown(ctx); err != nil {
				if err := logEmitter.EmitLog("ERR", fmt.Sprintf("HTTP Server forced to shutdown:%v", err)); err != nil {
					logger.Error().Err(err).Msg("failed to emit log")
				}
				logger.Fatal().Err(err).Msg("HTTP Server forced to shutdown")
			}
			if err := logEmitter.EmitLog("INFO", "HTTP server exiting..."); err != nil {
				logger.Error().Err(err).Msg("failed to emit log")
			}
			logger.Info().Msg("Server exiting...")
		})
	if err != nil {
		log.Fatalf("failed to initialize application: %v", err)
	}
}

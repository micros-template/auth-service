package server

import (
	"context"
	"log"
	"net"
	"net/http"
	"time"

	"10.1.20.130/dropping/auth-service/internal/domain/handler"
	"10.1.20.130/dropping/auth-service/internal/infrastructure/grpc"
	event "github.com/dropboks/event-bus-client/pkg/event/user"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
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
				if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					logger.Fatal().Err(err).Msg("Failed to listen and server http server")
				}
			}()

			// init consumer here
			go ue.StartConsume()

			logger.Info().Msgf("HTTP Server Starting in port %s", s.Address)

			if s.ServerReady != nil {
				for range 50 {
					conn, err := net.DialTimeout("tcp", s.Address, 100*time.Millisecond)
					if err == nil {
						if err := conn.Close(); err != nil {
							logger.Fatal().Err(err).Msg("establish check connection failed to close")
						}
						s.ServerReady <- true
						break
					}
					time.Sleep(100 * time.Millisecond)
				}
			}

			<-ctx.Done()
			logger.Info().Msg("Shutting down server...")

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := srv.Shutdown(ctx); err != nil {
				logger.Fatal().Err(err).Msg("Server forced to shutdown")
			}
			logger.Info().Msg("Server exiting...")
		})
	if err != nil {
		log.Fatalf("failed to initialize application: %v", err)
	}
}

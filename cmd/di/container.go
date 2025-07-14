package di

import (
	_cache "10.1.20.130/dropping/auth-service/config/cache"
	"10.1.20.130/dropping/auth-service/config/logger"
	mq "10.1.20.130/dropping/auth-service/config/message-queue"
	"10.1.20.130/dropping/auth-service/config/router"
	"10.1.20.130/dropping/auth-service/config/storage"
	"10.1.20.130/dropping/auth-service/internal/domain/handler"
	"10.1.20.130/dropping/auth-service/internal/domain/repository"
	"10.1.20.130/dropping/auth-service/internal/domain/service"
	cache "10.1.20.130/dropping/auth-service/internal/infrastructure/cache"
	"10.1.20.130/dropping/auth-service/internal/infrastructure/db"
	"10.1.20.130/dropping/auth-service/internal/infrastructure/grpc"
	_mq "10.1.20.130/dropping/auth-service/internal/infrastructure/message-queue"
	"10.1.20.130/dropping/auth-service/pkg/generators"
	"go.uber.org/dig"
)

func BuildContainer() *dig.Container {
	container := dig.New()
	// logger instance
	if err := container.Provide(logger.New); err != nil {
		panic("Failed to provide logger: " + err.Error())
	}
	// db connection
	if err := container.Provide(storage.New); err != nil {
		panic("Failed to provide database connection: " + err.Error())
	}
	// querier
	if err := container.Provide(db.NewQuerier); err != nil {
		panic("Failed to provide database connection: " + err.Error())
	}
	// nats client connection
	if err := container.Provide(mq.New); err != nil {
		panic("Failed to provide nats connection: " + err.Error())
	}
	if err := container.Provide(generators.NewRandomStringGenerator); err != nil {
		panic("Failed to provide random string generator: " + err.Error())
	}
	// jetstream connection
	if err := container.Provide(mq.NewJetstream); err != nil {
		panic("Failed to provide jetstream connection: " + err.Error())
	}
	// jetstream infrastructure
	if err := container.Provide(_mq.NewNatsInfrastructure); err != nil {
		panic("Failed to provide nats infrastructure: " + err.Error())
	}
	// user event consumer
	if err := container.Provide(_mq.NewUserEventConsumerInfra); err != nil {
		panic("Failed to provide user event consumer: " + err.Error())
	}
	// redis client connection
	if err := container.Provide(_cache.New); err != nil {
		panic("Failed to provide redis client connection: " + err.Error())
	}
	// redis infrastructure
	if err := container.Provide(cache.New); err != nil {
		panic("Failed to provide redis infra: " + err.Error())
	}
	// grpc client connection manager
	if err := container.Provide(grpc.NewGRPCClientManager); err != nil {
		panic("Failed to provide GRPC Client Manager: " + err.Error())
	}
	// user service grpc client
	if err := container.Provide(grpc.NewUserServiceConnection); err != nil {
		panic("Failed to provide user service grpc connection: " + err.Error())
	}
	// file service grpc client
	if err := container.Provide(grpc.NewFileServiceConnection); err != nil {
		panic("Failed to provide file service grpc connection: " + err.Error())
	}
	// auth repository
	if err := container.Provide(repository.New); err != nil {
		panic("Failed to provide repository: " + err.Error())
	}
	// auth service
	if err := container.Provide(service.New); err != nil {
		panic("Failed to provide repository: " + err.Error())
	}
	// auth handler
	if err := container.Provide(handler.New); err != nil {
		panic("Failed to provide repository: " + err.Error())
	}
	// router
	if err := container.Provide(router.New); err != nil {
		panic("Failed to provide gin router: " + err.Error())
	}
	return container
}

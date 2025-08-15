package bootstrap

import (
	"github.com/micros-template/auth-service/cmd/di"
	"github.com/micros-template/auth-service/config/env"
	"go.uber.org/dig"
)

func Run() *dig.Container {
	env.Load()
	container := di.BuildContainer()
	return container
}

package bootstrap

import (
	"10.1.20.130/dropping/auth-service/cmd/di"
	"10.1.20.130/dropping/auth-service/config/env"
	"go.uber.org/dig"
)

func Run() *dig.Container {
	env.Load()
	container := di.BuildContainer()
	return container
}

package logger

import (
	"context"

	"github.com/micros-template/log-service/pkg"
	ld "github.com/micros-template/log-service/pkg/dto"
)

type LoggerInfra interface {
	EmitLog(msgType, msg string) error
}

type loggerInfra struct {
	logEmitter pkg.LogEmitter
}

func NewLoggerInfra(logEmitter pkg.LogEmitter) LoggerInfra {
	return &loggerInfra{
		logEmitter: logEmitter,
	}
}

func (l *loggerInfra) EmitLog(msgType, msg string) error {
	if err := l.logEmitter.EmitLog(context.Background(), ld.LogMessage{
		Type:     msgType,
		Service:  "auth_service",
		Msg:      msg,
		Protocol: "SYSTEM",
	}); err != nil {
		return err
	}
	return nil
}

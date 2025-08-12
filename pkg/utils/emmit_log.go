package utils

import (
	"context"

	"10.1.20.130/dropping/log-management/pkg"
	ld "10.1.20.130/dropping/log-management/pkg/dto"
)

type LoggerServiceUtil interface {
	EmitLog(msgType, msg string) error
}

type loggerServiceUtil struct {
	logEmitter pkg.LogEmitter
}

func NewLoggerServiceUtil(logEmitter pkg.LogEmitter) LoggerServiceUtil {
	return &loggerServiceUtil{
		logEmitter: logEmitter,
	}
}

func (l *loggerServiceUtil) EmitLog(msgType, msg string) error {
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

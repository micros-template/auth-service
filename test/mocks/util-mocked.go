package mocks

import (
	"github.com/stretchr/testify/mock"
)

// LoggerServiceUtilMock is a testify mock for LoggerServiceUtil.
type LoggerServiceUtilMock struct {
	mock.Mock
}

func (m *LoggerServiceUtilMock) EmitLog(msgType, msg string) error {
	args := m.Called(msgType, msg)
	return args.Error(0)
}

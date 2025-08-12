package repository_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"10.1.20.130/dropping/auth-service/internal/domain/repository"
	"10.1.20.130/dropping/auth-service/test/mocks"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type SetResourceRepositorySuite struct {
	suite.Suite
	authRepository  repository.AuthRepository
	mockLogEmitter  *mocks.LoggerServiceUtilMock
	mockRedisClient *mocks.MockRedisCache
}

func (s *SetResourceRepositorySuite) SetupSuite() {

	logger := zerolog.Nop()
	redisClient := new(mocks.MockRedisCache)
	mockedLogEmitter := new(mocks.LoggerServiceUtilMock)
	pgxMock, err := pgxmock.NewPool()
	s.NoError(err)
	s.mockRedisClient = redisClient
	s.mockLogEmitter = mockedLogEmitter
	s.authRepository = repository.New(redisClient, pgxMock, mockedLogEmitter, logger)
}

func (s *SetResourceRepositorySuite) SetupTest() {
	s.mockRedisClient.ExpectedCalls = nil
	s.mockLogEmitter.ExpectedCalls = nil
	s.mockRedisClient.Calls = nil
	s.mockLogEmitter.Calls = nil
}

func TestSetResourceRepositorySuite(t *testing.T) {
	suite.Run(t, &SetResourceRepositorySuite{})
}

func (s *SetResourceRepositorySuite) TestAuthRepository_SetResource_Success() {
	key := "resource-key"
	value := "resource-value"
	dur := 1 * time.Millisecond
	ctx := context.Background()

	s.mockRedisClient.On("Set", mock.Anything, key, value, dur).Return(nil)

	err := s.authRepository.SetResource(ctx, key, value, dur)

	s.NoError(err)
	s.mockRedisClient.AssertExpectations(s.T())
}

func (s *SetResourceRepositorySuite) TestAuthRepository_SetResource_InternalError() {
	key := "resource-key"
	value := "resource-value"
	dur := 1 * time.Millisecond
	ctx := context.Background()

	s.mockRedisClient.On("Set", mock.Anything, key, value, dur).Return(errors.New("internal error"))
	s.mockLogEmitter.On("EmitLog", "ERR", mock.Anything).Return(nil)

	err := s.authRepository.SetResource(ctx, key, value, dur)

	s.Error(err)
	s.mockRedisClient.AssertExpectations(s.T())

	time.Sleep(time.Second)
	s.mockLogEmitter.AssertExpectations(s.T())
}

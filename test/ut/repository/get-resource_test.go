package repository_test

import (
	"context"
	"testing"
	"time"

	"10.1.20.130/dropping/auth-service/internal/domain/repository"
	"10.1.20.130/dropping/auth-service/test/mocks"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type GetResourceRepositorySuite struct {
	suite.Suite
	authRepository  repository.AuthRepository
	mockRedisClient *mocks.MockRedisCache
	mockLogEmitter  *mocks.LoggerServiceUtilMock
}

func (s *GetResourceRepositorySuite) SetupSuite() {

	logger := zerolog.Nop()
	redisClient := new(mocks.MockRedisCache)
	mockLogEmitter := new(mocks.LoggerServiceUtilMock)
	pgxMock, err := pgxmock.NewPool()
	s.NoError(err)
	s.mockRedisClient = redisClient
	s.mockLogEmitter = mockLogEmitter
	s.authRepository = repository.New(redisClient, pgxMock, mockLogEmitter, logger)
}

func (s *GetResourceRepositorySuite) SetupTest() {
	s.mockRedisClient.ExpectedCalls = nil
	s.mockLogEmitter.ExpectedCalls = nil

	s.mockRedisClient.Calls = nil
	s.mockLogEmitter.Calls = nil
}

func TestGetResourceRepositorySuite(t *testing.T) {
	suite.Run(t, &GetResourceRepositorySuite{})
}

func (s *GetResourceRepositorySuite) TestAuthRepository_GetResource_Success() {
	key := "resource-key"
	value := "resource-value"
	ctx := context.Background()
	s.mockRedisClient.On("Get", mock.Anything, key).Return(value, nil)

	val, err := s.authRepository.GetResource(ctx, key)

	s.NoError(err)
	s.NotEmpty(val)

	s.mockRedisClient.AssertExpectations(s.T())
}

func (s *GetResourceRepositorySuite) TestAuthRepository_GetResource_NotFound() {
	key := "resource-key"
	ctx := context.Background()

	s.mockRedisClient.On("Get", mock.Anything, key).Return("", redis.Nil)
	s.mockLogEmitter.On("EmitLog", "ERR", mock.Anything).Return(nil)

	val, err := s.authRepository.GetResource(ctx, key)

	s.Error(err)
	s.Empty(val)
	s.mockRedisClient.AssertExpectations(s.T())

	time.Sleep(time.Second)
	s.mockLogEmitter.AssertExpectations(s.T())
}

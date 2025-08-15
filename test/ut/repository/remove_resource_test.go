package repository_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/micros-template/auth-service/internal/domain/repository"
	"github.com/micros-template/auth-service/test/mocks"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type RemoveResourceRepositorySuite struct {
	suite.Suite
	authRepository  repository.AuthRepository
	mockRedisClient *mocks.MockRedisCache
	mockLogEmitter  *mocks.LoggerInfraMock
}

func (s *RemoveResourceRepositorySuite) SetupSuite() {

	logger := zerolog.Nop()
	redisClient := new(mocks.MockRedisCache)
	mockedLogEMitter := new(mocks.LoggerInfraMock)
	pgxMock, err := pgxmock.NewPool()

	s.NoError(err)
	s.mockRedisClient = redisClient
	s.mockLogEmitter = mockedLogEMitter
	s.authRepository = repository.New(redisClient, pgxMock, mockedLogEMitter, logger)
}

func (s *RemoveResourceRepositorySuite) SetupTest() {
	s.mockRedisClient.ExpectedCalls = nil
	s.mockLogEmitter.ExpectedCalls = nil
	s.mockRedisClient.Calls = nil
	s.mockLogEmitter.Calls = nil
}

func TestRemoveResourceRepositorySuite(t *testing.T) {
	suite.Run(t, &RemoveResourceRepositorySuite{})
}

func (s *RemoveResourceRepositorySuite) TestAuthRepository_RemoveResource_Success() {
	key := "resource-key"
	ctx := context.Background()

	s.mockRedisClient.On("Delete", mock.Anything, key).Return(nil)

	err := s.authRepository.RemoveResource(ctx, key)

	s.NoError(err)
	s.mockRedisClient.AssertExpectations(s.T())
}

func (s *RemoveResourceRepositorySuite) TestAuthRepository_RemoveResource_InternalError() {
	key := "resource-key"
	ctx := context.Background()

	s.mockRedisClient.On("Delete", mock.Anything, key).Return(errors.New("internal error"))
	s.mockLogEmitter.On("EmitLog", "ERR", mock.Anything).Return(nil)

	err := s.authRepository.RemoveResource(ctx, key)

	s.Error(err)
	s.mockRedisClient.AssertExpectations(s.T())

	time.Sleep(time.Second)
	s.mockLogEmitter.AssertExpectations(s.T())
}

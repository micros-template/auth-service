package repository_test

import (
	"fmt"
	"testing"
	"time"

	"10.1.20.130/dropping/auth-service/internal/domain/dto"
	"10.1.20.130/dropping/auth-service/internal/domain/repository"
	"10.1.20.130/dropping/auth-service/test/mocks"
	"10.1.20.130/dropping/sharedlib/model"
	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type GetUserByEmailRepositorySuite struct {
	suite.Suite
	authRepository  repository.AuthRepository
	mockRedisClient *mocks.MockRedisCache
	mockLogEmitter  *mocks.LoggerInfraMock
	mockPgx         pgxmock.PgxPoolIface
}

func (g *GetUserByEmailRepositorySuite) SetupSuite() {

	logger := zerolog.Nop()
	redisClient := new(mocks.MockRedisCache)
	mockedLogEmitter := new(mocks.LoggerInfraMock)
	pgxMock, err := pgxmock.NewPool()
	g.NoError(err)
	g.mockPgx = pgxMock
	g.mockRedisClient = redisClient
	g.mockLogEmitter = mockedLogEmitter
	g.authRepository = repository.New(redisClient, pgxMock, mockedLogEmitter, logger)
}

func (g *GetUserByEmailRepositorySuite) SetupTest() {
	g.mockRedisClient.ExpectedCalls = nil
	g.mockLogEmitter.ExpectedCalls = nil
	g.mockRedisClient.Calls = nil
	g.mockLogEmitter.ExpectedCalls = nil
}

func TestGetUserByEmailRepositorySuite(t *testing.T) {
	suite.Run(t, &GetUserByEmailRepositorySuite{})
}

func (g *GetUserByEmailRepositorySuite) TestAuthRepository_GetUserByEmail_Success() {
	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())
	image := "image.png"
	expectedUser := &model.User{
		ID:               email,
		FullName:         "test_user",
		Image:            &image,
		Email:            email,
		Password:         "hashedpassword",
		Verified:         true,
		TwoFactorEnabled: false,
	}

	rows := pgxmock.NewRows([]string{
		"id", "full_name", "image", "email", "password", "verified", "two_factor_enabled",
	}).AddRow(
		expectedUser.ID,
		expectedUser.FullName,
		expectedUser.Image,
		expectedUser.Email,
		expectedUser.Password,
		expectedUser.Verified,
		expectedUser.TwoFactorEnabled,
	)

	query := `SELECT id, full_name, image, email, password, verified, two_factor_enabled FROM users WHERE email = \$1`
	g.mockPgx.ExpectQuery(query).WithArgs(email).WillReturnRows(rows)

	user, err := g.authRepository.GetUserByEmail(email)
	g.NoError(err)
	g.Equal(expectedUser, user)
}

func (g *GetUserByEmailRepositorySuite) TestAuthRepository_GetUserByEmail_NotFound() {
	email := "notfound@example.com"
	query := `SELECT id, full_name, image, email, password, verified, two_factor_enabled FROM users WHERE email = \$1`
	g.mockPgx.ExpectQuery(query).WithArgs(email).WillReturnError(pgx.ErrNoRows)
	g.mockLogEmitter.On("EmitLog", "WARN", mock.Anything).Return(nil)

	user, err := g.authRepository.GetUserByEmail(email)
	g.Nil(user)
	g.ErrorIs(err, dto.Err_NOTFOUND_USER_NOT_FOUND)

	time.Sleep(time.Second)
	g.mockLogEmitter.AssertExpectations(g.T())
}

func (g *GetUserByEmailRepositorySuite) TestAuthRepository_GetUserByEmail_ScanError() {
	email := "scanerror@example.com"
	rows := pgxmock.NewRows([]string{
		"id", "full_name", "image", "email", "password", "verified", "two_factor_enabled",
	}).AddRow(
		1, // should be string, but int to cause scan error
		"Test User",
		"image.png",
		email,
		"hashedpassword",
		true,
		false,
	)
	query := `SELECT id, full_name, image, email, password, verified, two_factor_enabled FROM users WHERE email = \$1`
	g.mockPgx.ExpectQuery(query).WithArgs(email).WillReturnRows(rows)
	g.mockLogEmitter.On("EmitLog", "ERR", mock.Anything).Return(nil)

	user, err := g.authRepository.GetUserByEmail(email)
	g.Nil(user)
	g.ErrorIs(err, dto.Err_INTERNAL_FAILED_SCAN_USER)

	time.Sleep(time.Second)
	g.mockLogEmitter.AssertExpectations(g.T())
}

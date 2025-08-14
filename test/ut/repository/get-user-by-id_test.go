package repository_test

import (
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

type GetUserByIdRepositorySuite struct {
	suite.Suite
	authRepository  repository.AuthRepository
	mockRedisClient *mocks.MockRedisCache
	mockLogEmitter  *mocks.LoggerServiceUtilMock
	mockPgx         pgxmock.PgxPoolIface
}

func (g *GetUserByIdRepositorySuite) SetupSuite() {

	logger := zerolog.Nop()
	redisClient := new(mocks.MockRedisCache)
	mockedLogEmitter := new(mocks.LoggerServiceUtilMock)
	pgxMock, err := pgxmock.NewPool()
	g.NoError(err)
	g.mockPgx = pgxMock
	g.mockRedisClient = redisClient
	g.mockLogEmitter = mockedLogEmitter
	g.authRepository = repository.New(redisClient, pgxMock, mockedLogEmitter, logger)
}

func (g *GetUserByIdRepositorySuite) SetupTest() {
	g.mockRedisClient.ExpectedCalls = nil
	g.mockLogEmitter.ExpectedCalls = nil
	g.mockRedisClient.Calls = nil
	g.mockLogEmitter.Calls = nil
}

func TestGetUserByIdRepositorySuite(t *testing.T) {
	suite.Run(t, &GetUserByIdRepositorySuite{})
}

func (g *GetUserByIdRepositorySuite) TestAuthRepository_GetUserById_Success() {
	userId := "123"
	image := "image.png"
	expectedUser := &model.User{
		ID:               userId,
		FullName:         "John Doe",
		Image:            &image,
		Email:            "john@example.com",
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

	query := `SELECT id, full_name, image, email, password, verified, two_factor_enabled FROM users WHERE id = \$1`
	g.mockPgx.ExpectQuery(query).WithArgs(userId).WillReturnRows(rows)

	user, err := g.authRepository.GetUserByUserId(userId)
	g.NoError(err)
	g.Equal(expectedUser, user)
}

func (g *GetUserByIdRepositorySuite) TestAuthRepository_GetUserById_NotFound() {
	userId := "notfound"
	query := `SELECT id, full_name, image, email, password, verified, two_factor_enabled FROM users WHERE id = \$1`
	g.mockPgx.ExpectQuery(query).WithArgs(userId).WillReturnError(pgx.ErrNoRows)
	g.mockLogEmitter.On("EmitLog", "WARN", mock.Anything).Return(nil)

	user, err := g.authRepository.GetUserByUserId(userId)
	g.Nil(user)
	g.ErrorIs(err, dto.Err_NOTFOUND_USER_NOT_FOUND)
	time.Sleep(time.Second)
	g.mockLogEmitter.AssertExpectations(g.T())
}

func (g *GetUserByIdRepositorySuite) TestAuthRepository_GetUserById_ScanError() {
	userId := "123"
	rows := pgxmock.NewRows([]string{
		"id", "full_name", "image", "email", "password", "verified", "two_factor_enabled",
	}).AddRow(
		123, // should be string, but using int to cause scan error
		"John Doe",
		"image.png",
		"john@example.com",
		"hashedpassword",
		true,
		false,
	)
	query := `SELECT id, full_name, image, email, password, verified, two_factor_enabled FROM users WHERE id = \$1`
	g.mockPgx.ExpectQuery(query).WithArgs(userId).WillReturnRows(rows)
	g.mockLogEmitter.On("EmitLog", "ERR", mock.Anything).Return(nil)

	user, err := g.authRepository.GetUserByUserId(userId)
	g.Nil(user)
	g.ErrorIs(err, dto.Err_INTERNAL_FAILED_SCAN_USER)

	time.Sleep(time.Second)
	g.mockLogEmitter.AssertExpectations(g.T())
}

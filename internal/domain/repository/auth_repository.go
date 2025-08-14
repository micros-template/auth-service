package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"10.1.20.130/dropping/auth-service/internal/domain/dto"
	"10.1.20.130/dropping/auth-service/internal/infrastructure/cache"
	"10.1.20.130/dropping/auth-service/internal/infrastructure/db"
	"10.1.20.130/dropping/auth-service/pkg/utils"
	"10.1.20.130/dropping/sharedlib/model"
	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
)

type (
	AuthRepository interface {
		GetResource(context.Context, string) (string, error)
		SetResource(context.Context, string, string, time.Duration) error
		RemoveResource(context.Context, string) error
		GetUserByUserId(userId string) (*model.User, error)
		GetUserByEmail(email string) (*model.User, error)
	}
	authRepository struct {
		redisClient cache.RedisCache
		logger      zerolog.Logger
		querier     db.Querier
		logEmitter  utils.LoggerServiceUtil
	}
)

func New(r cache.RedisCache, querier db.Querier, logEmitter utils.LoggerServiceUtil, logger zerolog.Logger) AuthRepository {
	return &authRepository{
		redisClient: r,
		logger:      logger,
		querier:     querier,
		logEmitter:  logEmitter,
	}
}

func (a *authRepository) GetUserByEmail(email string) (*model.User, error) {
	var user model.User
	query, args, err := sq.Select("id", "full_name", "image", "email", "password", "verified", "two_factor_enabled").
		From("users").
		Where(sq.Eq{"email": email}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", dto.Err_INTERNAL_FAILED_BUILD_QUERY.Error()); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		return nil, dto.Err_INTERNAL_FAILED_BUILD_QUERY
	}

	row := a.querier.QueryRow(context.Background(), query, args...)
	err = row.Scan(&user.ID, &user.FullName, &user.Image, &user.Email, &user.Password, &user.Verified, &user.TwoFactorEnabled)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			go func() {
				if err := a.logEmitter.EmitLog("WARN", fmt.Sprintf("%s user_id: %s", dto.Err_NOTFOUND_USER_NOT_FOUND.Error(), user.ID)); err != nil {
					a.logger.Error().Err(err).Msg("failed to emit log")
				}
			}()
			return nil, dto.Err_NOTFOUND_USER_NOT_FOUND
		}
		go func() {
			if err := a.logEmitter.EmitLog("ERR", dto.Err_INTERNAL_FAILED_SCAN_USER.Error()); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		return nil, dto.Err_INTERNAL_FAILED_SCAN_USER
	}
	return &user, nil
}

func (a *authRepository) GetUserByUserId(userId string) (*model.User, error) {
	var user model.User
	query, args, err := sq.Select("id", "full_name", "image", "email", "password", "verified", "two_factor_enabled").
		From("users").
		Where(sq.Eq{"id": userId}).
		PlaceholderFormat(sq.Dollar).
		ToSql()
	if err != nil {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", dto.Err_INTERNAL_FAILED_BUILD_QUERY.Error()); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		return nil, dto.Err_INTERNAL_FAILED_BUILD_QUERY
	}
	row := a.querier.QueryRow(context.Background(), query, args...)
	err = row.Scan(&user.ID, &user.FullName, &user.Image, &user.Email, &user.Password, &user.Verified, &user.TwoFactorEnabled)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			go func() {
				if err := a.logEmitter.EmitLog("WARN", fmt.Sprintf("%s user_id: %s", dto.Err_NOTFOUND_USER_NOT_FOUND.Error(), user.ID)); err != nil {
					a.logger.Error().Err(err).Msg("failed to emit log")
				}
			}()
			return nil, dto.Err_NOTFOUND_USER_NOT_FOUND
		}
		go func() {
			if err := a.logEmitter.EmitLog("ERR", dto.Err_INTERNAL_FAILED_SCAN_USER.Error()); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		return nil, dto.Err_INTERNAL_FAILED_SCAN_USER
	}
	return &user, nil
}

func (a *authRepository) GetResource(c context.Context, key string) (string, error) {
	v, err := a.redisClient.Get(c, key)
	if err != nil {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("key: %s - get resource error. err: %v", key, err.Error())); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		if err == redis.Nil {
			return "", dto.Err_NOTFOUND_KEY_NOTFOUND
		}
		return "", dto.Err_INTERNAL_GET_RESOURCE
	}
	return v, nil
}

func (a *authRepository) RemoveResource(c context.Context, key string) error {
	if err := a.redisClient.Delete(c, key); err != nil {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("key: %s - remove resource error. err: %v", key, err.Error())); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		return dto.Err_INTERNAL_DELETE_RESOURCE
	}
	return nil
}

func (a *authRepository) SetResource(c context.Context, key, value string, duration time.Duration) error {
	err := a.redisClient.Set(c, key, value, duration)
	if err != nil {
		go func() {
			if err := a.logEmitter.EmitLog("ERR", fmt.Sprintf("key: %s - set resource error. err: %v", key, err.Error())); err != nil {
				a.logger.Error().Err(err).Msg("failed to emit log")
			}
		}()
		return dto.Err_INTERNAL_SET_RESOURCE
	}
	return nil
}

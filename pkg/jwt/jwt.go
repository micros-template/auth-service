package jwt

import (
	"time"

	"10.1.20.130/dropping/auth-service/internal/domain/dto"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/spf13/viper"
)

func GenerateToken(userId string, timeDuration time.Duration) (string, *Claims, error) {
	jwtKey := []byte(viper.GetString("jwt.secret_key"))
	var expirationTime *jwt.NumericDate
	if timeDuration > 0 {
		expirationTime = jwt.NewNumericDate(time.Now().Add(timeDuration))
	}

	claims := &Claims{
		UserId: userId,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: expirationTime,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    viper.GetString("app.name"),
			ID:        uuid.NewString(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(jwtKey)
	if err != nil {
		return "", nil, err
	}
	return signed, claims, nil
}

func ValidateJWT(tokenStr string) (*Claims, error) {
	jwtKey := []byte(viper.GetString("jwt.secret_key"))
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		return nil, dto.Err_UNAUTHORIZED_JWT_INVALID
	}
	return claims, nil
}

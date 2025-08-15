package generators

import (
	"crypto/rand"

	"github.com/google/uuid"
	_utils "github.com/micros-template/sharedlib/utils"
)

type (
	RandomGenerator interface {
		GenerateUUID() string
		GenerateToken() (string, error)
		GenerateOTP() (string, error)
	}
	randomGenerator struct{}
)

func NewRandomStringGenerator() RandomGenerator {
	return &randomGenerator{}
}

func (g *randomGenerator) GenerateUUID() string {
	return uuid.New().String()
}

func (g *randomGenerator) GenerateToken() (string, error) {
	return _utils.RandomString64()
}

func (g *randomGenerator) GenerateOTP() (string, error) {
	const otpLength = 6
	const digits = "0123456789"
	otp := make([]byte, otpLength)
	_, err := rand.Read(otp)
	if err != nil {
		return "", err
	}
	for i := range otpLength {
		otp[i] = digits[otp[i]%10]
	}
	return string(otp), nil
}

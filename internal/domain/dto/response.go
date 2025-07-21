package dto

import (
	"errors"
)

var (
	LOGIN_SUCCESS                = "Login Success"
	VERIFICATION_SUCCESS         = "Verification Success"
	REGISTER_SUCCESS             = "Register Success. Check your email for verification."
	RESEND_VERIFICATION_SUCCESS  = "Check your email for verification"
	OTP_VERIFICATION_SUCCESS     = "OTP is Valid"
	OTP_SENT_SUCCESS             = "OTP Has been sent to linked email"
	RESET_PASSWORD_EMAIL_SUCCESS = "Reset password email has been sent"
	CHANGE_PASSWORD_SUCCESS      = "password changed"
)

var (
	Err_BAD_REQUEST                       = errors.New("invalid input")
	Err_BAD_REQUEST_PASSWORD_DOESNT_MATCH = errors.New("password and confirm password doesn't match")
	Err_BAD_REQUEST_WRONG_EXTENSION       = errors.New("error file extension, support jpg, jpeg, and png")
	Err_BAD_REQUEST_LIMIT_SIZE_EXCEEDED   = errors.New("max size exceeded: 6mb")

	Err_CONFLICT_EMAIL_EXIST           = errors.New("user with this email exist")
	Err_CONFLICT_USER_ALREADY_VERIFIED = errors.New("user is already verified")

	Err_UNAUTHORIZED_PASSWORD_DOESNT_MATCH = errors.New("email or password is wrong")
	Err_UNAUTHORIZED_JWT_INVALID           = errors.New("token is invalid")
	Err_UNAUTHORIZED_TOKEN_INVALID         = errors.New("token is invalid")
	Err_UNAUTHORIZED_USER_NOT_VERIFIED     = errors.New("user is not verified")
	Err_UNAUTHORIZED_2FA_DISABLED          = errors.New("2FA is disabled")
	Err_UNAUTHORIZED_OTP_INVALID           = errors.New("OTP is invalid")

	Err_NOTFOUND_USER_NOT_FOUND = errors.New("user not found")
	Err_NOTFOUND_KEY_NOTFOUND   = errors.New("resource is not found")

	Err_INTENAL_JWT_SIGNING         = errors.New("jwt error signing")
	Err_INTERNAL_SET_RESOURCE       = errors.New("failed save resource")
	Err_INTERNAL_DELETE_RESOURCE    = errors.New("failed to delete resource")
	Err_INTERNAL_GET_RESOURCE       = errors.New("failed to get resource")
	Err_INTERNAL_CONVERT_IMAGE      = errors.New("error processing image")
	Err_INTERNAL_GENERATE_TOKEN     = errors.New("error generate verification token")
	Err_INTERNAL_GENERATE_OTP       = errors.New("error generate OTP")
	Err_INTERNAL_PUBLISH_MESSAGE    = errors.New("error publish email")
	Err_INTERNAL_FAILED_BUILD_QUERY = errors.New("failed to build query")
	Err_INTERNAL_FAILED_SCAN_USER   = errors.New("failed to scan user")
)

type (
	GlobalInternalServerErrorExample struct {
		StatusCode uint16 `json:"status_code" example:"500"`
		Message    string `json:"message" example:"internal server error"`
	}
	GlobalUnauthorizedErrorExample struct {
		StatusCode uint16 `json:"status_code" example:"401"`
		Message    string `json:"message" example:"unauthorized"`
	}
	GlobalUserNotFoundExample struct {
		StatusCode uint16 `json:"status_code" example:"404"`
		Message    string `json:"message" example:"user not found"`
	}
	GlobalInvalidInputExample struct {
		StatusCode uint16 `json:"status_code" example:"400"`
		Message    string `json:"message" example:"invalid input"`
	}
	GlobalMissingEmailExample struct {
		StatusCode uint16 `json:"status_code" example:"400"`
		Message    string `json:"message" example:"missing email"`
	}
	ResponseError struct {
		StatusCode uint16 `json:"status_code"`
		Message    string `json:"message"`
	}

	ResponseSuccess struct {
		StatusCode uint16      `json:"status_code"`
		Message    string      `json:"message"`
		Data       interface{} `json:"data"`
	}
	LoginSuccesExample struct {
		StatusCode uint16 `json:"status_code" example:"200"`
		Message    string `json:"message" example:"Login Success"`
		Data       string `json:"data" example:"token"`
	}
	RegisterSuccessExample struct {
		StatusCode uint16 `json:"status_code" example:"201"`
		Message    string `json:"message" example:"Register Success. Check your email for verification."`
		Data       string `json:"data" example:"null"`
	}
	RegisterBadRequestExample struct {
		StatusCode uint16 `json:"status_code" example:"400"`
		Message    string `json:"message" example:"wrong image ext, image limit sized exceeded, password doesn't match"`
	}
	RegisterConflictExample struct {
		StatusCode uint16 `json:"status_code" example:"409"`
		Message    string `json:"message" example:"user with this email exist"`
	}

	VerifyEmailSuccessExample struct {
		StatusCode uint16 `json:"status_code" example:"200"`
		Message    string `json:"message" example:"Verification Success"`
		Data       string `json:"data" example:"null"`
	}

	VerifyEmailConflictExample struct {
		StatusCode uint16 `json:"status_code" example:"409"`
		Message    string `json:"message" example:"user is already verified"`
	}

	ResendVerificationEmailSuccessExample struct {
		StatusCode uint16 `json:"status_code" example:"200"`
		Message    string `json:"message" example:"Check your email for verification"`
		Data       string `json:"data" example:"null"`
	}
	VerifyOTPSuccessExample struct {
		StatusCode uint16 `json:"status_code" example:"200"`
		Message    string `json:"message" example:"OTP is Valid"`
		Data       string `json:"data" example:"token"`
	}
	VerifyOTPUnauthorizedExample struct {
		StatusCode uint16 `json:"status_code" example:"401"`
		Message    string `json:"message" example:"OTP is invalid"`
	}
	ResendVerificationOTPSuccessExample struct {
		StatusCode uint16 `json:"status_code" example:"200"`
		Message    string `json:"message" example:"OTP Has been sent to linked email"`
		Data       string `json:"data" example:"null"`
	}
	ResetPasswordSuccessExample struct {
		StatusCode uint16 `json:"status_code" example:"200"`
		Message    string `json:"message" example:"Reset password email has been sent"`
		Data       string `json:"data" example:"null"`
	}
	ChangePasswordSuccessExample struct {
		StatusCode uint16 `json:"status_code" example:"200"`
		Message    string `json:"message" example:"password changed"`
		Data       string `json:"data" example:"null"`
	}
)

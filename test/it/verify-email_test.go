package service_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/spf13/viper"

	"github.com/gin-gonic/gin"
	"github.com/micros-template/auth-service/test/helper"
	_helper "github.com/micros-template/sharedlib/test/helper"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
)

type VerifyEmailITSuite struct {
	suite.Suite
	ctx context.Context

	network                      *testcontainers.DockerNetwork
	gatewayContainer             *_helper.GatewayContainer
	userPgContainer              *_helper.SQLContainer
	authPgContainer              *_helper.SQLContainer
	redisContainer               *_helper.CacheContainer
	minioContainer               *_helper.StorageContainer
	natsContainer                *_helper.MessageQueueContainer
	authContainer                *_helper.AuthServiceContainer
	userServiceContainer         *_helper.UserServiceContainer
	fileServiceContainer         *_helper.FileServiceContainer
	notificationServiceContainer *_helper.NotificationServiceContainer
	mailHogContainer             *_helper.MailContainer
}

func (v *VerifyEmailITSuite) SetupSuite() {
	log.Println("Setting up integration test suite for VerifyEmailITSuite")
	v.ctx = context.Background()

	viper.SetConfigName("config.test")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("../../")
	if err := viper.ReadInConfig(); err != nil {
		panic("failed to read config")
	}

	// spawn sharedNetwork
	v.network = _helper.StartNetwork(v.ctx)

	// spawn user db
	userPgContainer, err := _helper.StartSQLContainer(_helper.SQLParameterOption{
		Context:                 v.ctx,
		SharedNetwork:           v.network.Name,
		ImageName:               viper.GetString("container.postgresql_image"),
		ContainerName:           "test_user_db",
		SQLInitScriptPath:       viper.GetString("script.init_sql"),
		SQLInitInsideScriptPath: "/docker-entrypoint-initdb.d/init-db.sql",
		WaitingSignal:           "database system is ready to accept connections",
		Env: map[string]string{
			"POSTGRES_DB":       viper.GetString("database.name"),
			"POSTGRES_USER":     viper.GetString("database.user"),
			"POSTGRES_PASSWORD": viper.GetString("database.password"),
		},
	})
	if err != nil {
		log.Fatalf("failed starting postgres container: %s", err)
	}
	v.userPgContainer = userPgContainer

	// spawn auth db
	authPgContainer, err := _helper.StartSQLContainer(_helper.SQLParameterOption{
		Context:                 v.ctx,
		SharedNetwork:           v.network.Name,
		ImageName:               viper.GetString("container.postgresql_image"),
		ContainerName:           "test_auth_db",
		SQLInitScriptPath:       viper.GetString("script.init_sql"),
		SQLInitInsideScriptPath: "/docker-entrypoint-initdb.d/init-db.sql",
		WaitingSignal:           "database system is ready to accept connections",
		Env: map[string]string{
			"POSTGRES_DB":       viper.GetString("database.name"),
			"POSTGRES_USER":     viper.GetString("database.user"),
			"POSTGRES_PASSWORD": viper.GetString("database.password"),
		},
	})
	if err != nil {
		log.Fatalf("failed starting postgres container: %s", err)
	}
	v.authPgContainer = authPgContainer

	// spawn redis
	rContainer, err := _helper.StartCacheContainer(_helper.CacheParameterOption{
		Context:       v.ctx,
		SharedNetwork: v.network.Name,
		ImageName:     viper.GetString("container.redis_image"),
		ContainerName: "test_redis",
		WaitingSignal: "6379/tcp",
		Cmd:           []string{"redis-server", "--requirepass", viper.GetString("redis.password")},
		Env: map[string]string{
			"REDIS_PASSWORD": viper.GetString("redis.password"),
		},
	})
	if err != nil {
		log.Fatalf("failed starting redis container: %s", err)
	}
	v.redisContainer = rContainer

	mContainer, err := _helper.StartStorageContainer(_helper.StorageParameterOption{
		Context:       v.ctx,
		SharedNetwork: v.network.Name,
		ImageName:     viper.GetString("container.minio_image"),
		ContainerName: "test-minio",
		WaitingSignal: "API:",
		Cmd:           []string{"server", "/data"},
		Env: map[string]string{
			"MINIO_ROOT_USER":     viper.GetString("minio.credential.user"),
			"MINIO_ROOT_PASSWORD": viper.GetString("minio.credential.password"),
		},
	})
	if err != nil {
		log.Fatalf("failed starting minio container: %s", err)
	}
	v.minioContainer = mContainer

	// spawn nats
	nContainer, err := _helper.StartMessageQueueContainer(_helper.MessageQueueParameterOption{
		Context:            v.ctx,
		SharedNetwork:      v.network.Name,
		ImageName:          viper.GetString("container.nats_image"),
		ContainerName:      "test_nats",
		MQConfigPath:       viper.GetString("script.nats_server"),
		MQInsideConfigPath: "/etc/nats/nats.conf",
		WaitingSignal:      "Server is ready",
		MappedPort:         []string{"4221:4221/tcp"},
		Cmd: []string{
			"-c", "/etc/nats/nats.conf",
			"--name", "nats",
			"-p", "4221",
		},
		Env: map[string]string{
			"NATS_USER":     viper.GetString("nats.credential.user"),
			"NATS_PASSWORD": viper.GetString("nats.credential.password"),
		},
	})
	if err != nil {
		log.Fatalf("failed starting minio container: %s", err)
	}
	v.natsContainer = nContainer

	aContainer, err := _helper.StartAuthServiceContainer(_helper.AuthServiceParameterOption{
		Context:       v.ctx,
		SharedNetwork: v.network.Name,
		ImageName:     viper.GetString("container.auth_service_image"),
		ContainerName: "test_auth_service",
		WaitingSignal: "HTTP Server Starting in port",
		Cmd:           []string{"/auth_service"},
		Env:           map[string]string{"ENV": "test"},
	})
	if err != nil {
		log.Fatalf("failed starting auth service container: %s", err)
	}
	v.authContainer = aContainer

	fContainer, err := _helper.StartFileServiceContainer(_helper.FileServiceParameterOption{
		Context:       v.ctx,
		SharedNetwork: v.network.Name,
		ImageName:     viper.GetString("container.file_service_image"),
		ContainerName: "test_file_service",
		WaitingSignal: "gRPC server running in port",
		Cmd:           []string{"/file_service"},
		Env:           map[string]string{"ENV": "test"},
	})
	if err != nil {
		log.Fatalf("failed starting file service container: %s", err)
	}
	v.fileServiceContainer = fContainer

	// spawn user service
	uContainer, err := _helper.StartUserServiceContainer(_helper.UserServiceParameterOption{
		Context:       v.ctx,
		SharedNetwork: v.network.Name,
		ImageName:     viper.GetString("container.user_service_image"),
		ContainerName: "test_user_service",
		WaitingSignal: "gRPC server running in port",
		Cmd:           []string{"/user_service"},
		Env:           map[string]string{"ENV": "test"},
	})
	if err != nil {
		log.Fatalf("failed starting user service container: %s", err)
	}
	v.userServiceContainer = uContainer

	noContainer, err := _helper.StartNotificationServiceContainer(_helper.NotificationServiceParameterOption{
		Context:       v.ctx,
		SharedNetwork: v.network.Name,
		ImageName:     viper.GetString("container.notification_service_image"),
		ContainerName: "test_notification_service",
		WaitingSignal: "subscriber for notification is running",
		Cmd:           []string{"/notification_service"},
		Env:           map[string]string{"ENV": "test"},
	})
	if err != nil {
		log.Fatalf("failed starting notification service container: %s", err)
	}
	v.notificationServiceContainer = noContainer

	mailContainer, err := _helper.StartMailContainer(_helper.MailParameterOption{
		Context:       v.ctx,
		SharedNetwork: v.network.Name,
		ImageName:     viper.GetString("container.mailhog_image"),
		ContainerName: "mailhog",
		WaitingSignal: "1025/tcp",
		MappedPort:    []string{"1025:1025/tcp", "8025:8025/tcp"},
	})
	if err != nil {
		log.Fatalf("failed starting mailhog container: %s", err)
	}
	v.mailHogContainer = mailContainer

	gatewayContainer, err := _helper.StartGatewayContainer(_helper.GatewayParameterOption{
		Context:                   v.ctx,
		SharedNetwork:             v.network.Name,
		ImageName:                 viper.GetString("container.gateway_image"),
		ContainerName:             "test_gateway",
		NginxConfigPath:           viper.GetString("script.nginx"),
		NginxInsideConfigPath:     "/etc/nginx/conf.d/default.conf",
		GrpcErrorConfigPath:       viper.GetString("script.grpc_error"),
		GrpcErrorInsideConfigPath: "/etc/nginx/conf.d/errors.grpc_conf",
		WaitingSignal:             "Configuration complete; ready for start up",
		MappedPort:                []string{"9090:80/tcp", "50051:50051/tcp"},
	})
	if err != nil {
		log.Fatalf("failed starting gateway container: %s", err)
	}
	v.gatewayContainer = gatewayContainer
	time.Sleep(time.Second)
}

func (v *VerifyEmailITSuite) TearDownSuite() {
	if err := v.userPgContainer.Terminate(v.ctx); err != nil {
		log.Fatalf("error terminating user postgres container: %s", err)
	}
	if err := v.authPgContainer.Terminate(v.ctx); err != nil {
		log.Fatalf("error terminating auth postgres container: %s", err)
	}
	if err := v.redisContainer.Terminate(v.ctx); err != nil {
		log.Fatalf("error terminating redis container: %s", err)
	}
	if err := v.minioContainer.Terminate(v.ctx); err != nil {
		log.Fatalf("error terminating minio container: %s", err)
	}
	if err := v.natsContainer.Terminate(v.ctx); err != nil {
		log.Fatalf("error terminating nats container: %s", err)
	}
	if err := v.authContainer.Terminate(v.ctx); err != nil {
		log.Fatalf("error terminating auth service container: %s", err)
	}
	if err := v.userServiceContainer.Terminate(v.ctx); err != nil {
		log.Fatalf("error terminating user service container: %s", err)
	}
	if err := v.fileServiceContainer.Terminate(v.ctx); err != nil {
		log.Fatalf("error terminating file service container: %s", err)
	}
	if err := v.notificationServiceContainer.Terminate(v.ctx); err != nil {
		log.Fatalf("error terminating notification service container: %s", err)
	}
	if err := v.mailHogContainer.Terminate(v.ctx); err != nil {
		log.Fatalf("error terminating mailhog container: %s", err)
	}
	if err := v.gatewayContainer.Terminate(v.ctx); err != nil {
		log.Fatalf("error terminating gateway container: %s", err)
	}

	log.Println("Tear Down integration test suite for VerifyEmailITSuite")
}
func TestVerifyEmailITSuite(t *testing.T) {
	suite.Run(t, &VerifyEmailITSuite{})
}

func (v *VerifyEmailITSuite) TestVerifyEmailIT_Success() {
	// register
	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())

	request := helper.Register(email, v.T())

	client := http.Client{}
	registerResponse, err := client.Do(request)
	v.NoError(err)
	registerResponseBody, err := io.ReadAll(registerResponse.Body)
	v.NoError(err)

	v.Equal(http.StatusCreated, registerResponse.StatusCode)
	v.Contains(string(registerResponseBody), "Register Success. Check your email for verification.")

	regex := `http://localhost:9090/api/v1/auth/verify-email\?userid=[^&]+&token=[^"']+`
	link := helper.RetrieveDataFromEmail(email, regex, "mail", v.T())

	time.Sleep(time.Second) //give a time for auth_db update the user

	// verify email
	verifyRequest, err := http.NewRequest(http.MethodGet, link, nil)
	v.NoError(err)

	verifyResponse, err := client.Do(verifyRequest)
	v.NoError(err)

	verifyBody, err := io.ReadAll(verifyResponse.Body)
	v.NoError(err)

	v.Equal(http.StatusOK, verifyResponse.StatusCode)
	v.Contains(string(verifyBody), "Verification Success")
}

func (v *VerifyEmailITSuite) TestVerifyEmailIT_MissingQUery() {

	client := http.Client{}
	verifyRequest, err := http.NewRequest(http.MethodGet, "http://localhost:9090/api/v1/auth/verify-email?", nil)
	v.NoError(err)

	verifyResponse, err := client.Do(verifyRequest)
	v.NoError(err)

	verifyBody, err := io.ReadAll(verifyResponse.Body)
	v.NoError(err)

	v.Equal(http.StatusBadRequest, verifyResponse.StatusCode)
	v.Contains(string(verifyBody), "invalid input")
}

func (v *VerifyEmailITSuite) TestVerifyEmailIT_TokenInvalid() {
	// register
	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())

	request := helper.Register(email, v.T())

	client := http.Client{}
	registerResponse, err := client.Do(request)
	v.NoError(err)
	registerResponseBody, err := io.ReadAll(registerResponse.Body)
	v.NoError(err)

	v.Equal(http.StatusCreated, registerResponse.StatusCode)
	v.Contains(string(registerResponseBody), "Register Success. Check your email for verification.")

	// get the first link
	regex := `http://localhost:9090/api/v1/auth/verify-email\?userid=[^&]+&token=[^"']+`
	link := helper.RetrieveDataFromEmail(email, regex, "mail", v.T())

	time.Sleep(time.Second) //give a time for auth_db update the user

	// resend verification
	reqBody := &bytes.Buffer{}

	encoder := gin.H{
		"email": email,
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	resendVerification, err := http.NewRequest(http.MethodPost, "http://localhost:9090/api/v1/auth/resend-verification-email", reqBody)
	v.NoError(err)

	resendVerificationResponse, err := client.Do(resendVerification)

	v.NoError(err)
	resendVerificationResponseBody, err := io.ReadAll(resendVerificationResponse.Body)
	v.NoError(err)

	v.Equal(http.StatusCreated, registerResponse.StatusCode)
	v.Contains(string(resendVerificationResponseBody), "Check your email for verification")

	// request with link
	verifyRequest, err := http.NewRequest(http.MethodGet, link, nil)
	v.NoError(err)

	verifyResponse, err := client.Do(verifyRequest)
	v.NoError(err)

	verifyBody, err := io.ReadAll(verifyResponse.Body)
	v.NoError(err)

	v.Equal(http.StatusUnauthorized, verifyResponse.StatusCode)
	v.Contains(string(verifyBody), "token is invalid")
}

func (v *VerifyEmailITSuite) TestVerifyEmailIT_AlreadyVerified() {
	// register
	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())
	request := helper.Register(email, v.T())

	client := http.Client{}
	registerResponse, err := client.Do(request)
	v.NoError(err)
	registerResponseBody, err := io.ReadAll(registerResponse.Body)
	v.NoError(err)

	v.Equal(http.StatusCreated, registerResponse.StatusCode)
	v.Contains(string(registerResponseBody), "Register Success. Check your email for verification.")

	time.Sleep(time.Second) //give a time for auth_db update the user

	regex := `http://localhost:9090/api/v1/auth/verify-email\?userid=[^&]+&token=[^"']+`
	link := helper.RetrieveDataFromEmail(email, regex, "mail", v.T())

	// verify email
	verifyRequest, err := http.NewRequest(http.MethodGet, link, nil)
	v.NoError(err)

	verifyResponse, err := client.Do(verifyRequest)
	v.NoError(err)

	verifyBody, err := io.ReadAll(verifyResponse.Body)
	v.NoError(err)

	v.Equal(http.StatusOK, verifyResponse.StatusCode)
	v.Contains(string(verifyBody), "Verification Success")

	secondVerifyRequest, err := http.NewRequest(http.MethodGet, link, nil)
	v.NoError(err)

	secondVerifyResponse, err := client.Do(secondVerifyRequest)
	v.NoError(err)

	secondVerifyBody, err := io.ReadAll(secondVerifyResponse.Body)
	v.NoError(err)

	v.Equal(http.StatusConflict, secondVerifyResponse.StatusCode)
	v.Contains(string(secondVerifyBody), "user is already verified")

}

// this is not applicable due to expired is take a long time

// func (v *VerifyEmailITSuite) TestVerifyEmailIT_KeyNotFound() {
// 	// register
// 	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())
// 	request := helper.Register(email, v.T())

// 	client := http.Client{}
// 	registerResponse, err := client.Do(request)
// 	v.NoError(err)
// 	registerResponseBody, err := io.ReadAll(registerResponse.Body)
// 	v.NoError(err)

// 	v.Equal(http.StatusCreated, registerResponse.StatusCode)
// 	v.Contains(string(registerResponseBody), "Register Success. Check your email for verification.")

// 	time.Sleep(time.Second) //give a time for auth_db update the user

// 	// verify email
// 	regex := `http://localhost:8081/verify-email\?userid=[^&]+&token=[^"']+`
// 	link := helper.RetrieveDataFromEmail(email, regex, "mail", v.T())

// 	useridRe := regexp.MustCompile(`userid=([^&]+)`)
// 	matches := useridRe.FindStringSubmatch(link)
// 	v.True(len(matches) > 1, "userid not found in link")
// 	userid := matches[1]

// 	logg := zerolog.Nop()
// 	red, err := c.New(logg)
// 	v.NoError(err)
// 	redCache := cache.New(red, logg)

// 	key := fmt.Sprintf("verificationToken:%s", userid)
// 	err = redCache.Delete(v.ctx, key)
// 	v.NoError(err)

// 	verifyRequest, err := http.NewRequest(http.MethodGet, link, nil)
// 	v.NoError(err)

// 	verifyResponse, err := client.Do(verifyRequest)
// 	v.NoError(err)

// 	verifyBody, err := io.ReadAll(verifyResponse.Body)
// 	v.NoError(err)

// 	v.Equal(http.StatusNotFound, verifyResponse.StatusCode)
// 	v.Contains(string(verifyBody), "verification token is not found")
// }

func (v *VerifyEmailITSuite) TestVerifyEmailIT_UserNotFound() {
	link := "http://localhost:9090/api/v1/auth/verify-email?userid=examplerandom&token=random-token-that-is-not-valid"
	client := http.Client{}
	re := regexp.MustCompile(`userid=([^&]+)`)
	randomUserID := fmt.Sprintf("random-%d", time.Now().UnixNano())
	modifiedLink := re.ReplaceAllString(link, fmt.Sprintf("userid=%s", randomUserID))

	verifyRequest, err := http.NewRequest(http.MethodGet, modifiedLink, nil)
	v.NoError(err)

	verifyResponse, err := client.Do(verifyRequest)
	v.NoError(err)

	verifyBody, err := io.ReadAll(verifyResponse.Body)
	v.NoError(err)

	v.Equal(http.StatusNotFound, verifyResponse.StatusCode)
	v.Contains(string(verifyBody), "user not found")
}

func (v *VerifyEmailITSuite) TestVerifyEmailIT_ChangeTokenSuccess() {
	// - register
	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())

	request := helper.Register(email, v.T())

	client := http.Client{}
	registerResponse, err := client.Do(request)
	v.NoError(err)
	registerResponseBody, err := io.ReadAll(registerResponse.Body)
	v.NoError(err)

	v.Equal(http.StatusCreated, registerResponse.StatusCode)
	v.Contains(string(registerResponseBody), "Register Success. Check your email for verification.")

	time.Sleep(time.Second) //give a time for auth_db update the user

	regex := `http://localhost:9090/api/v1/auth/verify-email\?userid=[^&]+&token=[^"']+`
	link := helper.RetrieveDataFromEmail(email, regex, "mail", v.T())

	// - verify-email
	verifyRequest, err := http.NewRequest(http.MethodGet, link, nil)
	v.NoError(err)

	verifyResponse, err := client.Do(verifyRequest)
	v.NoError(err)

	verifyBody, err := io.ReadAll(verifyResponse.Body)
	v.NoError(err)

	v.Equal(http.StatusOK, verifyResponse.StatusCode)
	v.Contains(string(verifyBody), "Verification Success")

	time.Sleep(time.Second) //give a time for auth_db update the user

	// - login
	reqBody := &bytes.Buffer{}

	encoder := gin.H{
		"email":    email,
		"password": "password123",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	req, err := http.NewRequest(http.MethodPost, "http://localhost:9090/api/v1/auth/login", reqBody)
	v.NoError(err)

	response, err := client.Do(req)
	v.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	v.NoError(err)

	v.Equal(http.StatusOK, response.StatusCode)
	v.Contains(string(byteBody), "Login Success")

	// - verify
	var respData map[string]interface{}
	err = json.Unmarshal(byteBody, &respData)
	v.NoError(err)

	jwt, ok := respData["data"].(string)
	v.True(ok, "expected jwt token in data field")

	// update email
	newEmail := fmt.Sprintf("test+updated+%d@example.com", time.Now().UnixNano())
	updateBody := &bytes.Buffer{}
	updatePayload := gin.H{
		"email": newEmail,
	}
	_ = json.NewEncoder(updateBody).Encode(updatePayload)

	// - update email in the user endpoint
	updateReq, err := http.NewRequest(http.MethodPatch, "http://localhost:9090/api/v1/user/email", updateBody)
	updateReq.Header.Set("Authorization", "Bearer "+jwt)
	v.NoError(err)

	updateResp, err := client.Do(updateReq)
	v.NoError(err)

	updateRespBody, err := io.ReadAll(updateResp.Body)

	v.NoError(err)
	v.Equal(http.StatusOK, updateResp.StatusCode)
	v.Contains(string(updateRespBody), "verify to change email")

	// get the link from email in mailhog
	regex = `http://localhost:9090/api/v1/auth/verify-email\?userid=[^&]+&changeEmailToken=[^"']+`
	link = helper.RetrieveDataFromEmail(newEmail, regex, "mail", v.T())

	// verify new email
	verifyRequest, err = http.NewRequest(http.MethodGet, link, nil)
	v.NoError(err)
	verifyResponse, err = client.Do(verifyRequest)
	v.NoError(err)
	verifyBody, err = io.ReadAll(verifyResponse.Body)
	v.NoError(err)
	v.Equal(http.StatusOK, verifyResponse.StatusCode)
	v.Contains(string(verifyBody), "Verification Success")
}

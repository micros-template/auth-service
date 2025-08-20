package service_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"testing"
	"time"

	"github.com/spf13/viper"

	"github.com/gin-gonic/gin"
	"github.com/micros-template/auth-service/test/helper"
	_helper "github.com/micros-template/sharedlib/test/helper"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
)

type LoginITSuite struct {
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

func (l *LoginITSuite) SetupSuite() {

	log.Println("Setting up integration test suite for LoginITSuite")
	l.ctx = context.Background()

	viper.SetConfigName("config.test")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("../../")
	if err := viper.ReadInConfig(); err != nil {
		panic("failed to read config")
	}
	// spawn sharedNetwork
	l.network = _helper.StartNetwork(l.ctx)

	// spawn user db
	userPgContainer, err := _helper.StartSQLContainer(_helper.SQLParameterOption{
		Context:                 l.ctx,
		SharedNetwork:           l.network.Name,
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
	l.userPgContainer = userPgContainer

	// spawn auth db
	authPgContainer, err := _helper.StartSQLContainer(_helper.SQLParameterOption{
		Context:                 l.ctx,
		SharedNetwork:           l.network.Name,
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
	l.authPgContainer = authPgContainer

	// spawn redis
	rContainer, err := _helper.StartCacheContainer(_helper.CacheParameterOption{
		Context:       l.ctx,
		SharedNetwork: l.network.Name,
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
	l.redisContainer = rContainer

	mContainer, err := _helper.StartStorageContainer(_helper.StorageParameterOption{
		Context:       l.ctx,
		SharedNetwork: l.network.Name,
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
	l.minioContainer = mContainer

	// spawn nats
	nContainer, err := _helper.StartMessageQueueContainer(_helper.MessageQueueParameterOption{
		Context:            l.ctx,
		SharedNetwork:      l.network.Name,
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
	l.natsContainer = nContainer

	aContainer, err := _helper.StartAuthServiceContainer(_helper.AuthServiceParameterOption{
		Context:       l.ctx,
		SharedNetwork: l.network.Name,
		ImageName:     viper.GetString("container.auth_service_image"),
		ContainerName: "test_auth_service",
		WaitingSignal: "HTTP Server Starting in port",
		Cmd:           []string{"/auth_service"},
		Env:           map[string]string{"ENV": "test"},
	})
	if err != nil {
		log.Fatalf("failed starting auth service container: %s", err)
	}
	l.authContainer = aContainer

	fContainer, err := _helper.StartFileServiceContainer(_helper.FileServiceParameterOption{
		Context:       l.ctx,
		SharedNetwork: l.network.Name,
		ImageName:     viper.GetString("container.file_service_image"),
		ContainerName: "test_file_service",
		WaitingSignal: "gRPC server running in port",
		Cmd:           []string{"/file_service"},
		Env:           map[string]string{"ENV": "test"},
	})
	if err != nil {
		log.Fatalf("failed starting file service container: %s", err)
	}
	l.fileServiceContainer = fContainer

	// spawn user service
	uContainer, err := _helper.StartUserServiceContainer(_helper.UserServiceParameterOption{
		Context:       l.ctx,
		SharedNetwork: l.network.Name,
		ImageName:     viper.GetString("container.user_service_image"),
		ContainerName: "test_user_service",
		WaitingSignal: "gRPC server running in port",
		Cmd:           []string{"/user_service"},
		Env:           map[string]string{"ENV": "test"},
	})
	if err != nil {
		log.Fatalf("failed starting user service container: %s", err)
	}
	l.userServiceContainer = uContainer

	noContainer, err := _helper.StartNotificationServiceContainer(_helper.NotificationServiceParameterOption{
		Context:       l.ctx,
		SharedNetwork: l.network.Name,
		ImageName:     viper.GetString("container.notification_service_image"),
		ContainerName: "test_notification_service",
		WaitingSignal: "subscriber for notification is running",
		Cmd:           []string{"/notification_service"},
		Env:           map[string]string{"ENV": "test"},
	})
	if err != nil {
		log.Fatalf("failed starting notification service container: %s", err)
	}
	l.notificationServiceContainer = noContainer

	mailContainer, err := _helper.StartMailContainer(_helper.MailParameterOption{
		Context:       l.ctx,
		SharedNetwork: l.network.Name,
		ImageName:     viper.GetString("container.mailhog_image"),
		ContainerName: "mailhog",
		WaitingSignal: "1025/tcp",
		MappedPort:    []string{"1025:1025/tcp", "8025:8025/tcp"},
	})
	if err != nil {
		log.Fatalf("failed starting mailhog container: %s", err)
	}
	l.mailHogContainer = mailContainer

	gatewayContainer, err := _helper.StartGatewayContainer(_helper.GatewayParameterOption{
		Context:                   l.ctx,
		SharedNetwork:             l.network.Name,
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
	l.gatewayContainer = gatewayContainer
	time.Sleep(time.Second)

}

func (l *LoginITSuite) TearDownSuite() {
	if err := l.userPgContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating user postgres container: %s", err)
	}
	if err := l.authPgContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating auth postgres container: %s", err)
	}
	if err := l.redisContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating redis container: %s", err)
	}
	if err := l.minioContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating minio container: %s", err)
	}
	if err := l.natsContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating nats container: %s", err)
	}
	if err := l.authContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating auth service container: %s", err)
	}
	if err := l.userServiceContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating user service container: %s", err)
	}
	if err := l.fileServiceContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating file service container: %s", err)
	}
	if err := l.notificationServiceContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating notification service container: %s", err)
	}
	if err := l.mailHogContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating mailhog container: %s", err)
	}
	if err := l.gatewayContainer.Terminate(l.ctx); err != nil {
		log.Fatalf("error terminating gateway container: %s", err)
	}
	log.Println("Tear Down integration test suite for LoginITSuite")
}
func TestLoginITSuite(t *testing.T) {
	suite.Run(t, &LoginITSuite{})
}

func (l *LoginITSuite) TestLoginIT_Success() {
	// register
	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())
	request := helper.Register(email, l.T())

	client := http.Client{}
	response, err := client.Do(request)
	l.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	l.NoError(err)

	l.Equal(http.StatusCreated, response.StatusCode)
	l.Contains(string(byteBody), "Register Success. Check your email for verification.")

	if err := response.Body.Close(); err != nil {
		l.T().Errorf("error closing response body: %v", err)
	}

	time.Sleep(time.Second) //give a time for auth_db update the user

	// verify email
	regex := `http://localhost:9090/api/v1/auth/verify-email\?userid=[^&]+&token=[^"']+`
	link := helper.RetrieveDataFromEmail(email, regex, "mail", l.T())

	verifyRequest, err := http.NewRequest(http.MethodGet, link, nil)
	l.NoError(err)

	verifyResponse, err := client.Do(verifyRequest)
	l.NoError(err)

	verifyBody, err := io.ReadAll(verifyResponse.Body)
	l.NoError(err)

	l.Equal(http.StatusOK, verifyResponse.StatusCode)
	l.Contains(string(verifyBody), "Verification Success")

	time.Sleep(time.Second) //give a time for auth_db update the user

	// login
	request = helper.Login(email, l.T())

	client = http.Client{}
	response, err = client.Do(request)
	l.NoError(err)

	byteBody, err = io.ReadAll(response.Body)

	l.Equal(http.StatusOK, response.StatusCode)
	l.NoError(err)
	l.Contains(string(byteBody), "Login Success")
	if err := response.Body.Close(); err != nil {
		l.T().Errorf("error closing response body: %v", err)
	}
}

func (l *LoginITSuite) TestLoginIT_Success2FA() {

	// register
	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())
	request := helper.Register(email, l.T())

	client := http.Client{}
	response, err := client.Do(request)
	l.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	l.NoError(err)

	l.Equal(http.StatusCreated, response.StatusCode)
	l.Contains(string(byteBody), "Register Success. Check your email for verification.")
	if err := response.Body.Close(); err != nil {
		l.T().Errorf("error closing response body: %v", err)
	}
	time.Sleep(time.Second) //give a time for auth_db update the user

	// verify email
	regex := `http://localhost:9090/api/v1/auth/verify-email\?userid=[^&]+&token=[^"']+`
	link := helper.RetrieveDataFromEmail(email, regex, "mail", l.T())

	verifyRequest, err := http.NewRequest(http.MethodGet, link, nil)
	l.NoError(err)

	verifyResponse, err := client.Do(verifyRequest)
	l.NoError(err)

	verifyBody, err := io.ReadAll(verifyResponse.Body)
	l.NoError(err)

	l.Equal(http.StatusOK, verifyResponse.StatusCode)
	l.Contains(string(verifyBody), "Verification Success")

	time.Sleep(time.Second) //give a time for auth_db update the user

	// login
	request = helper.Login(email, l.T())

	client = http.Client{}
	response, err = client.Do(request)
	l.NoError(err)

	byteBody, err = io.ReadAll(response.Body)

	l.Equal(http.StatusOK, response.StatusCode)
	l.NoError(err)
	l.Contains(string(byteBody), "Login Success")

	var respData map[string]interface{}
	err = json.Unmarshal(byteBody, &respData)
	l.NoError(err)

	jwt, ok := respData["data"].(string)
	l.True(ok, "expected jwt token in data field")

	// updateuser enable 2FA
	reqBody := &bytes.Buffer{}

	formWriter := multipart.NewWriter(reqBody)
	_ = formWriter.WriteField("full_name", "test-full-name")
	_ = formWriter.WriteField("two_factor_enabled", "true")
	if err := formWriter.Close(); err != nil {
		log.Fatal("failed to close form writer")
	}

	request, err = http.NewRequest(http.MethodPatch, "http://localhost:9090/api/v1/user/", reqBody)
	request.Header.Set("Content-Type", formWriter.FormDataContentType())
	request.Header.Set("Authorization", "Bearer "+jwt)

	l.NoError(err)

	client = http.Client{}
	response, err = client.Do(request)
	l.NoError(err)

	byteBody, err = io.ReadAll(response.Body)

	l.Equal(http.StatusOK, response.StatusCode)
	l.NoError(err)
	l.Contains(string(byteBody), "success update profile data")

	time.Sleep(time.Second) //give a time for auth_db update the user

	// login
	request = helper.Login(email, l.T())

	client = http.Client{}
	response, err = client.Do(request)
	l.NoError(err)

	byteBody, err = io.ReadAll(response.Body)

	l.Equal(http.StatusOK, response.StatusCode)
	l.NoError(err)
	l.Contains(string(byteBody), "OTP Has been sent to linked email")

	// check email for otp
	regex = `<div class="otp">\s*([0-9]{4,8})\s*</div>`
	otp := helper.RetrieveDataFromEmail(email, regex, "otp", l.T())
	l.NotEmpty(otp)

	// verify otp
	reqBody = &bytes.Buffer{}

	encoder := gin.H{
		"email": email,
		"otp":   otp,
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	req, err := http.NewRequest(http.MethodPost, "http://localhost:9090/api/v1/auth/verify-otp", reqBody)
	l.NoError(err)

	client = http.Client{}
	response, err = client.Do(req)
	l.NoError(err)

	byteBody, err = io.ReadAll(response.Body)

	l.Equal(http.StatusOK, response.StatusCode)
	l.NoError(err)
	l.Contains(string(byteBody), "OTP is Valid")
}

func (l *LoginITSuite) TestLoginIT_MissingBody() {

	reqBody := &bytes.Buffer{}

	encoder := gin.H{
		"email": "test2@example.com",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	req, err := http.NewRequest(http.MethodPost, "http://localhost:9090/api/v1/auth/login", reqBody)
	l.NoError(err)

	client := http.Client{}
	response, err := client.Do(req)
	l.NoError(err)

	byteBody, err := io.ReadAll(response.Body)

	l.Equal(http.StatusBadRequest, response.StatusCode)
	l.NoError(err)
	l.Contains(string(byteBody), "invalid input")
	if err := response.Body.Close(); err != nil {
		l.T().Errorf("error closing response body: %v", err)
	}
}

func (l *LoginITSuite) TestLoginIT_NotVerified() {
	// register
	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())
	request := helper.Register(email, l.T())

	client := http.Client{}
	response, err := client.Do(request)
	l.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	l.NoError(err)

	l.Equal(http.StatusCreated, response.StatusCode)
	l.Contains(string(byteBody), "Register Success. Check your email for verification.")
	if err := response.Body.Close(); err != nil {
		l.T().Errorf("error closing response body: %v", err)
	}

	time.Sleep(time.Second) //give a time for auth_db update the user

	// login
	request = helper.Login(email, l.T())

	client = http.Client{}
	response, err = client.Do(request)
	l.NoError(err)

	byteBody, err = io.ReadAll(response.Body)

	l.Equal(http.StatusUnauthorized, response.StatusCode)
	l.NoError(err)
	l.Contains(string(byteBody), "user is not verified")
	if err := response.Body.Close(); err != nil {
		l.T().Errorf("error closing response body: %v", err)
	}
}

func (l *LoginITSuite) TestLoginIT_PasswordDoesntMatch() {
	// register
	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())
	request := helper.Register(email, l.T())

	client := http.Client{}
	response, err := client.Do(request)
	l.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	l.NoError(err)

	l.Equal(http.StatusCreated, response.StatusCode)
	l.Contains(string(byteBody), "Register Success. Check your email for verification.")
	if err := response.Body.Close(); err != nil {
		l.T().Errorf("error closing response body: %v", err)
	}

	time.Sleep(time.Second) //give a time for auth_db update the user

	// verify email
	regex := `http://localhost:9090/api/v1/auth/verify-email\?userid=[^&]+&token=[^"']+`
	link := helper.RetrieveDataFromEmail(email, regex, "mail", l.T())

	verifyRequest, err := http.NewRequest(http.MethodGet, link, nil)
	l.NoError(err)

	verifyResponse, err := client.Do(verifyRequest)
	l.NoError(err)

	verifyBody, err := io.ReadAll(verifyResponse.Body)
	l.NoError(err)

	l.Equal(http.StatusOK, verifyResponse.StatusCode)
	l.Contains(string(verifyBody), "Verification Success")

	time.Sleep(time.Second) //give a time for auth_db update the user

	// login
	reqBody := &bytes.Buffer{}

	encoder := gin.H{
		"email":    email,
		"password": "password1234",
	}
	_ = json.NewEncoder(reqBody).Encode(encoder)

	req, err := http.NewRequest(http.MethodPost, "http://localhost:9090/api/v1/auth/login", reqBody)
	l.NoError(err)

	client = http.Client{}
	response, err = client.Do(req)
	l.NoError(err)

	byteBody, err = io.ReadAll(response.Body)

	l.Equal(http.StatusUnauthorized, response.StatusCode)
	l.NoError(err)
	l.Contains(string(byteBody), "email or password is wrong")
	if err := response.Body.Close(); err != nil {
		l.T().Errorf("error closing response body: %v", err)
	}
}

func (l *LoginITSuite) TestLoginIT_UserNotfound() {
	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())

	request := helper.Login(email, l.T())
	client := http.Client{}
	response, err := client.Do(request)
	l.NoError(err)

	byteBody, err := io.ReadAll(response.Body)

	l.Equal(http.StatusNotFound, response.StatusCode)
	l.NoError(err)
	l.Contains(string(byteBody), "user not found")
	if err := response.Body.Close(); err != nil {
		l.T().Errorf("error closing response body: %v", err)
	}
}

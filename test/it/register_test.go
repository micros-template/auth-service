package service_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"testing"
	"time"

	"github.com/spf13/viper"

	"github.com/micros-template/auth-service/test/helper"
	_helper "github.com/micros-template/sharedlib/test/helper"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
)

type RegisterITSuite struct {
	suite.Suite
	ctx context.Context

	network              *testcontainers.DockerNetwork
	gatewayContainer     *_helper.GatewayContainer
	userPgContainer      *_helper.SQLContainer
	authPgContainer      *_helper.SQLContainer
	redisContainer       *_helper.CacheContainer
	minioContainer       *_helper.StorageContainer
	natsContainer        *_helper.MessageQueueContainer
	authContainer        *_helper.AuthServiceContainer
	userServiceContainer *_helper.UserServiceContainer
	fileServiceContainer *_helper.FileServiceContainer
}

func (r *RegisterITSuite) SetupSuite() {
	log.Println("Setting up integration test suite for RegisterITSuite")
	r.ctx = context.Background()

	viper.SetConfigName("config.test")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("../../")
	if err := viper.ReadInConfig(); err != nil {
		panic("failed to read config")
	}

	// spawn sharedNetwork
	r.network = _helper.StartNetwork(r.ctx)
	// spawn user db
	userPgContainer, err := _helper.StartSQLContainer(_helper.SQLParameterOption{
		Context:                 r.ctx,
		SharedNetwork:           r.network.Name,
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
	r.userPgContainer = userPgContainer

	// spawn auth db
	authPgContainer, err := _helper.StartSQLContainer(_helper.SQLParameterOption{
		Context:                 r.ctx,
		SharedNetwork:           r.network.Name,
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
	r.authPgContainer = authPgContainer

	// spawn redis
	rContainer, err := _helper.StartCacheContainer(_helper.CacheParameterOption{
		Context:       r.ctx,
		SharedNetwork: r.network.Name,
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
	r.redisContainer = rContainer

	mContainer, err := _helper.StartStorageContainer(_helper.StorageParameterOption{
		Context:       r.ctx,
		SharedNetwork: r.network.Name,
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
	r.minioContainer = mContainer

	// spawn nats
	nContainer, err := _helper.StartMessageQueueContainer(_helper.MessageQueueParameterOption{
		Context:            r.ctx,
		SharedNetwork:      r.network.Name,
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
	r.natsContainer = nContainer

	aContainer, err := _helper.StartAuthServiceContainer(_helper.AuthServiceParameterOption{
		Context:       r.ctx,
		SharedNetwork: r.network.Name,
		ImageName:     viper.GetString("container.auth_service_image"),
		ContainerName: "test_auth_service",
		WaitingSignal: "HTTP Server Starting in port",
		Cmd:           []string{"/auth_service"},
		Env:           map[string]string{"ENV": "test"},
	})
	if err != nil {
		log.Fatalf("failed starting auth service container: %s", err)
	}
	r.authContainer = aContainer

	fContainer, err := _helper.StartFileServiceContainer(_helper.FileServiceParameterOption{
		Context:       r.ctx,
		SharedNetwork: r.network.Name,
		ImageName:     viper.GetString("container.file_service_image"),
		ContainerName: "test_file_service",
		WaitingSignal: "gRPC server running in port",
		Cmd:           []string{"/file_service"},
		Env:           map[string]string{"ENV": "test"},
	})
	if err != nil {
		log.Fatalf("failed starting file service container: %s", err)
	}
	r.fileServiceContainer = fContainer

	// spawn user service
	uContainer, err := _helper.StartUserServiceContainer(_helper.UserServiceParameterOption{
		Context:       r.ctx,
		SharedNetwork: r.network.Name,
		ImageName:     viper.GetString("container.user_service_image"),
		ContainerName: "test_user_service",
		WaitingSignal: "gRPC server running in port",
		Cmd:           []string{"/user_service"},
		Env:           map[string]string{"ENV": "test"},
	})
	if err != nil {
		log.Fatalf("failed starting user service container: %s", err)
	}
	r.userServiceContainer = uContainer

	gatewayContainer, err := _helper.StartGatewayContainer(_helper.GatewayParameterOption{
		Context:                   r.ctx,
		SharedNetwork:             r.network.Name,
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
	r.gatewayContainer = gatewayContainer
	time.Sleep(time.Second)

}
func (r *RegisterITSuite) TearDownSuite() {
	if err := r.userPgContainer.Terminate(r.ctx); err != nil {
		log.Fatalf("error terminating user postgres container: %s", err)
	}
	if err := r.authPgContainer.Terminate(r.ctx); err != nil {
		log.Fatalf("error terminating auth postgres container: %s", err)
	}
	if err := r.redisContainer.Terminate(r.ctx); err != nil {
		log.Fatalf("error terminating redis container: %s", err)
	}
	if err := r.minioContainer.Terminate(r.ctx); err != nil {
		log.Fatalf("error terminating minio container: %s", err)
	}
	if err := r.natsContainer.Terminate(r.ctx); err != nil {
		log.Fatalf("error terminating nats container: %s", err)
	}
	if err := r.authContainer.Terminate(r.ctx); err != nil {
		log.Fatalf("error terminating auth service container: %s", err)
	}
	if err := r.userServiceContainer.Terminate(r.ctx); err != nil {
		log.Fatalf("error terminating user service container: %s", err)
	}
	if err := r.fileServiceContainer.Terminate(r.ctx); err != nil {
		log.Fatalf("error terminating file service container: %s", err)
	}
	if err := r.gatewayContainer.Terminate(r.ctx); err != nil {
		log.Fatalf("error terminating gateway container: %s", err)
	}
	log.Println("Tear Down integration test suite for RegisterITSuite")
}
func TestRegisterITSuite(t *testing.T) {
	suite.Run(t, &RegisterITSuite{})
}

func (r *RegisterITSuite) TestRegisterIT_Success() {
	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())
	request := helper.Register(email, r.T())
	client := http.Client{}
	response, err := client.Do(request)
	r.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	r.NoError(err)

	r.Equal(http.StatusCreated, response.StatusCode)
	r.Contains(string(byteBody), "Register Success. Check your email for verification.")
	if err := response.Body.Close(); err != nil {
		r.T().Errorf("error closing response body: %v", err)
	}
}

func (r *RegisterITSuite) TestRegisterIT_MissingBody() {
	reqBody := &bytes.Buffer{}

	formWriter := multipart.NewWriter(reqBody)
	_ = formWriter.WriteField("email", "test@example.com")
	_ = formWriter.WriteField("password", "password123")
	_ = formWriter.WriteField("confirm_password", "password123")
	if err := formWriter.Close(); err != nil {
		log.Fatal("failed to close form writer")
	}
	request, err := http.NewRequest(http.MethodPost, "http://localhost:9090/api/v1/auth/register", reqBody)
	request.Header.Set("Content-Type", formWriter.FormDataContentType())
	r.NoError(err)

	client := http.Client{}
	response, err := client.Do(request)
	r.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	r.NoError(err)

	r.Equal(http.StatusBadRequest, response.StatusCode)
	r.Contains(string(byteBody), "invalid input")
	if err := response.Body.Close(); err != nil {
		r.T().Errorf("error closing response body: %v", err)
	}
}

func (r *RegisterITSuite) TestRegisterIT_EmailAlreadyExist() {
	email := fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())
	request := helper.Register(email, r.T())

	client := http.Client{}
	response, err := client.Do(request)
	r.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	r.NoError(err)

	r.Equal(http.StatusCreated, response.StatusCode)
	r.Contains(string(byteBody), "Register Success. Check your email for verification.")
	if err := response.Body.Close(); err != nil {
		r.T().Errorf("error closing response body: %v", err)
	}
	time.Sleep(time.Second)

	secRequest := helper.Register(email, r.T())

	client = http.Client{}
	secResponse, err := client.Do(secRequest)
	r.NoError(err)

	secByteBody, err := io.ReadAll(secResponse.Body)
	r.NoError(err)

	r.Equal(http.StatusConflict, secResponse.StatusCode)
	r.Contains(string(secByteBody), "user with this email exist")
	if err := response.Body.Close(); err != nil {
		r.T().Errorf("error closing response body: %v", err)
	}
}

func (r *RegisterITSuite) TestRegisterIT_WrongExtension() {
	reqBody := &bytes.Buffer{}

	formWriter := multipart.NewWriter(reqBody)
	_ = formWriter.WriteField("full_name", "test-full-name")
	_ = formWriter.WriteField("email", "test2@example.com")
	_ = formWriter.WriteField("password", "password123")
	_ = formWriter.WriteField("confirm_password", "password123")

	fileWriter, _ := formWriter.CreateFormFile("image", "test.webp")
	_, err := fileWriter.Write([]byte("fake image data"))
	r.NoError(err)
	if err != nil {
		log.Fatal("failed to create image data")
	}
	if err := formWriter.Close(); err != nil {
		log.Fatal("failed to close form writer")
	}

	request, err := http.NewRequest(http.MethodPost, "http://localhost:9090/api/v1/auth/register", reqBody)
	request.Header.Set("Content-Type", formWriter.FormDataContentType())
	r.NoError(err)

	client := http.Client{}
	response, err := client.Do(request)
	r.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	r.NoError(err)

	r.Equal(http.StatusBadRequest, response.StatusCode)
	r.Contains(string(byteBody), "error file extension, support jpg, jpeg, and png")
	if err := response.Body.Close(); err != nil {
		r.T().Errorf("error closing response body: %v", err)
	}
}

func (r *RegisterITSuite) TestRegisterIT_LimitSizeExceeded() {
	reqBody := &bytes.Buffer{}

	formWriter := multipart.NewWriter(reqBody)
	_ = formWriter.WriteField("full_name", "test-full-name")
	_ = formWriter.WriteField("email", "test3@example.com")
	_ = formWriter.WriteField("password", "password123")
	_ = formWriter.WriteField("confirm_password", "password123")
	fileWriter, _ := formWriter.CreateFormFile("image", "test.png")
	largeData := make([]byte, 8*1024*1024)
	_, err := fileWriter.Write(largeData)
	r.NoError(err)
	if err != nil {
		log.Fatal("failed to create image data")
	}
	if err := formWriter.Close(); err != nil {
		log.Fatal("failed to close form writer")
	}

	request, err := http.NewRequest(http.MethodPost, "http://localhost:9090/api/v1/auth/register", reqBody)
	request.Header.Set("Content-Type", formWriter.FormDataContentType())
	r.NoError(err)

	client := http.Client{}
	response, err := client.Do(request)
	r.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	r.NoError(err)

	r.Equal(http.StatusBadRequest, response.StatusCode)
	r.Contains(string(byteBody), "max size exceeded: 6mb")
	if err := response.Body.Close(); err != nil {
		r.T().Errorf("error closing response body: %v", err)
	}
}

func (r *RegisterITSuite) TestRegisterIT_PasswordAndConfirmPasswordDoesntMatch() {
	reqBody := &bytes.Buffer{}

	formWriter := multipart.NewWriter(reqBody)
	_ = formWriter.WriteField("full_name", "test-full-name")
	_ = formWriter.WriteField("email", "test4@example.com")
	_ = formWriter.WriteField("password", "password123")
	_ = formWriter.WriteField("confirm_password", "password1234")

	fileWriter, _ := formWriter.CreateFormFile("image", "test.jpg")
	_, err := fileWriter.Write([]byte("fake image data"))
	r.NoError(err)
	if err != nil {
		log.Fatal("failed to create image data")
	}
	if err := formWriter.Close(); err != nil {
		log.Fatal("failed to close form writer")
	}

	request, err := http.NewRequest(http.MethodPost, "http://localhost:9090/api/v1/auth/register", reqBody)
	request.Header.Set("Content-Type", formWriter.FormDataContentType())
	r.NoError(err)

	client := http.Client{}
	response, err := client.Do(request)
	r.NoError(err)

	byteBody, err := io.ReadAll(response.Body)
	r.NoError(err)

	r.Equal(http.StatusBadRequest, response.StatusCode)
	r.Contains(string(byteBody), "password and confirm password doesn't match")
	if err := response.Body.Close(); err != nil {
		r.T().Errorf("error closing response body: %v", err)
	}
}

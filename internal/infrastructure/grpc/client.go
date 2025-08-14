package grpc

import (
	fileProto "10.1.20.130/dropping/proto-file/pkg/fpb"
	userProto "10.1.20.130/dropping/proto-user/pkg/upb"
	"github.com/spf13/viper"
)

func NewUserServiceConnection(manager *GRPCClientManager) userProto.UserServiceClient {
	userServiceConnection := manager.GetConnection(viper.GetString("app.grpc.service.user_service"))
	userServiceClient := userProto.NewUserServiceClient(userServiceConnection)
	return userServiceClient
}

func NewFileServiceConnection(manager *GRPCClientManager) fileProto.FileServiceClient {
	fileServiceConnection := manager.GetConnection(viper.GetString("app.grpc.service.file_service"))
	fileServiceClient := fileProto.NewFileServiceClient(fileServiceConnection)
	return fileServiceClient
}

#!/bin/sh

mkdir -p ./bin/dist

service_name="auth_service"

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "./bin/dist/$service_name" ./cmd
wait

echo "Building Docker image for $service_name:test" >/dev/stderr
docker build -t "10.1.20.130:5001/dropping/auth-service:test" --build-arg BIN_NAME=$service_name -f Dockerfile .

rm -rf ./bin/dist
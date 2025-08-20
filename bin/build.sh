#!/bin/sh

mkdir -p ./bin/dist

service_name="auth_service"
full_image_name="docker-registry.anandadf.my.id/micros-template/$service_name"

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o "./bin/dist/$service_name" ./cmd
wait

if ! command -v upx >/dev/null 2>&1; then
  echo "UPX not found. Installing..."
  apk update && apk add upx
fi

upx --best --lzma ./bin/dist/$service_name
wait

VERSION=$(cat VERSION)
echo "Building Docker image for $service_name:$VERSION" >/dev/stderr
docker build -t "$service_name:$VERSION" --build-arg BIN_NAME=$service_name -f Dockerfile .

registry_image="$full_image_name:$VERSION"
echo "${HARBOR_ROBOT_PASSWORD}" | docker login https://docker-registry.anandadf.my.id -u "${HARBOR_ROBOT_USERNAME}" --password-stdin


echo "Tagging image as $registry_image" >/dev/stderr
docker tag "$service_name:$VERSION" "$registry_image"
docker push "$registry_image"

echo "Tagging image as $full_image_name:latest" >/dev/stderr
docker tag "$service_name:$VERSION" "$full_image_name:latest"
docker push "$full_image_name:latest"

echo "Removing local image and tagged image" >/dev/stderr
docker rmi "$service_name:$VERSION"
docker rmi "$registry_image"
docker rmi "$full_image_name:latest"

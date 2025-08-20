#!/bin/sh


service_name="notification_service"
full_image_name="docker-registry.anandadf.my.id/micros-template/$service_name"

echo "Removing test in local" >/dev/stderr
docker rmi "$full_image_name:test"

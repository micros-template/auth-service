#!/bin/sh

echo "Removing test in local" >/dev/stderr
docker rmi "$CI_REGISTRY_IMAGE:test"

#!/bin/bash

set -e

cd ..
make docker-image DOCKER_IMAGE_TAG=$2

docker tag cilium/cilium:$2 $1/cilium/cilium:$2
docker tag cilium/cilium:$2 $1/cilium/cilium-dev:$2
docker tag cilium/operator:$2 $1/cilium/operator:$2

docker push $1/cilium/cilium:$2
docker push $1/cilium/cilium-dev:$2
docker push $1/cilium/operator:$2

#!/bin/bash
set -ev

DOCKER_TAG=trusona/forgerock-example:latest

docker build -t ${DOCKER_TAG} example/
docker run -p 8080:80 -e OPENAM_HOST=openam.lab.trusona.net ${DOCKER_TAG}
#!/bin/bash

set -e

if [ -z "$ARTIFACTORY_PASSWORD" ] || [ -z "$ARTIFACTORY_USERNAME" ] || [ -z "$FORGEROCK_MAVEN_USERNAME" ] || [ -z "$FORGEROCK_MAVEN_PASSWORD" ]; then
  echo "You must set the variables ARTIFACTORY_USERNAME, ARTIFACTORY_PASSWORD, FORGEROCK_MAVEN_USERNAME and FORGEROCK_MAVEN_PASSWORD"
  exit 1
fi

dir=$(dirname $0)/../data

cat ${dir}/settings.xml.template | \
  sed "s/\${artifactoryUsername}/${ARTIFACTORY_USERNAME}/g" | \
  sed "s/\${artifactoryPassword}/${ARTIFACTORY_PASSWORD}/g" | \
  sed "s/\${forgerockMavenUsername}/${FORGEROCK_MAVEN_USERNAME}/g" | \
  sed "s/\${forgerockMavenPassword}/${FORGEROCK_MAVEN_PASSWORD}/g" \
  > ${dir}/settings.xml



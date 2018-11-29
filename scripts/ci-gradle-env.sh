#!/usr/bin/env bash

set -e

mkdir -p ~/.gradle

echo "org.gradle.jvmargs=-Xmx2048M" >> ~/.gradle/gradle.properties

echo "ARTIFACTORY_USERNAME=${ARTIFACTORY_USERNAME}" >> ~/.gradle/gradle.properties
echo "ARTIFACTORY_PASSWORD=${ARTIFACTORY_PASSWORD}" >> ~/.gradle/gradle.properties

echo "RELEASES_REPO=${RELEASES_REPO}" >> ~/.gradle/gradle.properties
echo "SNAPSHOTS_REPO=${SNAPSHOTS_REPO}" >> ~/.gradle/gradle.properties
echo "CONTEXT_REPO_ROOT=${CONTEXT_REPO_ROOT}" >> ~/.gradle/gradle.properties

echo "FORGEROCK_MAVEN_USERNAME=${FORGEROCK_MAVEN_USERNAME}" >> ~/.gradle/gradle.properties
echo "FORGEROCK_MAVEN_PASSWORD=${FORGEROCK_MAVEN_PASSWORD}" >> ~/.gradle/gradle.properties


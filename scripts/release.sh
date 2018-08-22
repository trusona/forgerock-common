#!/usr/bin/env bash

## Create a release tag for travis to publish for us

set -e

if [ ! -f pom.xml ]; then
  echo "Error: Cannot find POM. Run from the root of the repository"
  exit -1
fi

CURRENT_BRANCH=$(git branch | grep "*" | awk '{print $2}')

if [ ! ${CURRENT_BRANCH} == master ]; then
  echo "Oops! We need to be on the 'master' branch to create a release"
  exit 1
fi

GIT_STATUS=$(git status -s)

if [ -n "${GIT_STATUS}" ]; then
  echo "Repository is not clean. Resolve the following uncomitted changes:"
  echo ${GIT_STATUS}
  exit -1
fi

PLUGIN_VERSION=$(mvn org.apache.maven.plugins:maven-help-plugin:3.1.0:evaluate -Dexpression=project.version 2>/dev/null | egrep -ve "\[.*\]")
TAG_NAME="v${PLUGIN_VERSION}"

git tag -f -a ${TAG_NAME} -m "release ${TAG_NAME}"

echo -n "Do you want to publish version ${PLUGIN_VERSION} now? [y/N]: "
read RESPONSE

if [ "${RESPONSE}" == y ] || [ "${RESPONSE}" == Y ]; then
  git push --set-upstream origin ${TAG_NAME} -f
else
  echo -e "Run the following command to publish release:\n"
  echo -e "git push --set-upstream origin ${TAG_NAME} \n"
fi

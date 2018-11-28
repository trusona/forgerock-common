#!/usr/bin/env bash

## Create a release tag for travis to publish for us
##
## Run with "./scripts/release.sh"
##
## OR if you've enabled git signing, run with "./scripts/release.sh --sign"
##

set -e

c_sign=
t_sign=

if [ -n $1 ]; then
  c_sign="-S"
  t_sign="-s"
fi

if [ ! -f gradlew ]; then
  echo "Error: Cannot find gradle wrapper. Run from the root of the repository." && exit -1
fi

git checkout -q master && git pull --quiet

GIT_STATUS=$(git status -s)

if [ -n "${GIT_STATUS}" ]; then
  echo "Repository is not clean. Resolve the following uncomitted changes:"
  echo ${GIT_STATUS}
  exit -2
fi

CURRENT_VERSION=`./gradlew -q version | grep SNAPSHOT`

if [ -z "${CURRENT_VERSION}" ]; then
  echo "Error: Version '$CURRENT_VERSION' is not a SNAPSHOT. Aborting." && exit -3
fi

RELEASE_VERSION=`echo ${CURRENT_VERSION} | cut -d- -f1`

echo -n "Do you want to publish version ${RELEASE_VERSION} now? [y/N]: "
read RESPONSE

if [[ $RESPONSE == y ]] || [[ $RESPONSE == Y ]]; then
  git checkout -q -b release-${RELEASE_VERSION}

  sed -e s/'version "${CURRENT_VERSION}"'/'version "${RELEASE_VERSION}"'/g -i build.gradle

  git commit -m "release version ${RELEASE_VERSION}" $c_sign build.gradle
  git tag $t_sign -a release-${RELEASE_VERSION} -m "release version ${RELEASE_VERSION}"

  git push -q --set-upstream origin release-${RELEASE_VERSION}
  git push -q --tags -f

  git checkout -q master
  NEXT_VERSION="`./bin/semver-tool bump patch $RELEASE_VERSION`-SNAPSHOT"

  sed -e s/'version "${CURRENT_VERSION}"'/'version "${NEXT_VERSION}"'/g -i build.gradle

  git commit -m "Bumping to next snapshot version $NEXT_VERSION" $c_sign build.gradle
  git push -q --set-upstream origin master

fi


## Setting up Gradle

1. If it does not already exist, create a `.gradle` directory in your home directory like this:

```bash
mkdir -p ~/.gradle
```

2. Create a file named `gradle.properties` at `~/.gradle/gradle.properties` with the following content:

```text
ARTIFACTORY_USERNAME=<YOUR_ARTIFACTORY_USERNAME>
ARTIFACTORY_PASSWORD=<YOUR_ARTIFACTORY_USERNAME>
FORGEROCK_MAVEN_USERNAME=<YOUR_FORGEROCK_MAVEN_USERNAME>
FORGEROCK_MAVEN_PASSWORD=<YOUR_FORGEROCK_MAVEN_PASSWORD>
CONTEXT_REPO_ROOT=https://trusona.jfrog.io/trusona/
```

3. Replace the text `<...>` with the relevant information.

## Setting up NPM

1. Update your `~/.npmrc` file with your Trusona Artifactory credentials

```bash
cat <<EOF > ~/.npmrc
@trusona:registry=https://trusona.jfrog.io/trusona/api/npm/npm
//trusona.jfrog.io/trusona/api/npm/:_password="$(echo -ne $ARTIFACTORY_PASSWORD | base64 -w 0)"
//trusona.jfrog.io/trusona/api/npm/:username=$ARTIFACTORY_USERNAME
//trusona.jfrog.io/trusona/api/npm/:email=$ARTIFACTORY_EMAIL
//trusona.jfrog.io/trusona/api/npm/:always-auth=true
EOF
```

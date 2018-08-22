## Setting up Maven

### Setting up Maven for Forgerock

Download settings.xml file from ForgeRock backstage after you've logged in `http://maven.forgerock.org/repo/private-releases/settings.xml` and put it in `~/.m2/settings.xml`

### Setting up Maven for Trusona

1. Create a master password in Maven:

```bash
$ mvn --encrypt-master-password $master_password
{hfVXK9Wxn+kH0/fzpwehZboNEgLI=}
```

2. Create `~/.m2/settings-security.xml` with the following:

```xml
<settingsSecurity>
  <master>{hfVXK9Wxn+kH0/fzpwehZboNEgLI=}</master>
</settingsSecurity>
```

3. Encrypt your Artifactory password:

```bash
$ mvn --encrypt-password $artifactory_password
{XuPqXqg2xkgH8a1yPGGznvpEbQuPgaJvg9wXPE2Zytsi8xJbim5KoK3Juk7SULpA==}
```

4. Add to `~/.m2/settings.xml` with Artifactory information:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<settings xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.1.0 http://maven.apache.org/xsd/settings-1.1.0.xsd" xmlns="http://maven.apache.org/SETTINGS/1.1.0"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <servers>
    <server>
      <username>$artifactory_username</username>
      <password>{XuPqXqg2xkgH8a1yPGGznvpEbQuPgaJvg9wXPE2Zytsi8xJbim5KoK3Juk7SULpA==}</password>
      <id>sdk-snapshots-local</id>
    </server>
  </servers>
  <profiles>
    <profile>
      <id>trusona</id>
      <repositories>
        <repository>
          <id>sdk-snapshots-local</id>
          <url>https://trusona.jfrog.io/trusona/sdk-snapshots</url>
            <releases>
                <enabled>true</enabled>
                <checksumPolicy>fail</checksumPolicy>
            </releases>
            <snapshots>
                <enabled>false</enabled>
                <checksumPolicy>warn</checksumPolicy>
            </snapshots>
        </repository>
      </repositories>
    </profile>
  </profiles>
  <activeProfiles>
    <activeProfile>trusona</activeProfile>
  </activeProfiles>
</settings>
```

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

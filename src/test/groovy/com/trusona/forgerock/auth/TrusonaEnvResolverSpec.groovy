package com.trusona.forgerock.auth

import com.trusona.sdk.TrusonaEnvironment
import spock.lang.Specification

class TrusonaEnvResolverSpec extends Specification {

  TrusonaEnvResolver sut

  def setup() {
    sut = new TrusonaEnvResolver()
  }

  def "getEnvironment should default to Production"() {
    when:
    def res = sut.getEnvironment()

    then:
    res == TrusonaEnvironment.PRODUCTION
  }

  def "getEnvironment should return UAT when the property -Dtrusona.environment=UAT"() {
    given:
    System.setProperty("trusona.environment", uat)

    when:
    def res = sut.getEnvironment()

    then:
    res == TrusonaEnvironment.UAT

    where:
    uat << ["UAT", "uat"]
  }

  def "getEnvironment should return PRODUCTION if a bad value is set"() {
    given:
    System.setProperty("trusona.environment", badValues)

    when:
    def res = sut.getEnvironment()

    then:
    res == TrusonaEnvironment.PRODUCTION

    where:
    badValues << ["", "foo", "Bar", "prod", "production"]
  }
}
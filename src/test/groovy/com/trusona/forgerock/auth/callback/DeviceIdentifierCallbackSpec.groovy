package com.trusona.forgerock.auth.callback

import com.trusona.sdk.resources.dto.Trusonafication
import spock.lang.Specification

class DeviceIdentifierCallbackSpec extends Specification {

  DeviceIdentifierCallback sut


  def setup() {
    sut = new DeviceIdentifierCallback("jones")
  }

  def "isValid should return true when the userIdentifier is not null or blank"() {
    when:
    def res = sut.isValid()

    then:
    res
  }

  def "isValid should return false when the identifier is blank or null"() {
    given:
    sut = new DeviceIdentifierCallback(badUserIdentifier)

    when:
    def res = sut.isValid()

    then:
    !res

    where:
    badUserIdentifier << [ null, '', '   ' ]
  }

  def "fillIdentifier should set the user identifier"() {
    given:
    def partialTrusonafication = Trusonafication.essential()

    when:
    def builder = sut.fillIdentifier(partialTrusonafication)
    def res = builder.action("foo").resource("bar").build()

    then:
    res.deviceIdentifier == "jones"
  }
}
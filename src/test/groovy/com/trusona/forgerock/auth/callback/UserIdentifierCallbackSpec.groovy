package com.trusona.forgerock.auth.callback

import com.trusona.sdk.resources.dto.Trusonafication
import spock.lang.Specification

class UserIdentifierCallbackSpec extends Specification {

  UserIdentifierCallback sut


  def setup() {
    sut = new UserIdentifierCallback("jones")
  }

  def "isValid should return true when the userIdentifier is not null or blank"() {
    when:
    def res = sut.isValid()

    then:
    res
  }

  def "isValid should return false when the identifier is blank or null"() {
    given:
    sut = new UserIdentifierCallback(badUserIdentifier)

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
    res.userIdentifier == "jones"
  }
}
package com.trusona.forgerock.auth.callback

import com.trusona.sdk.resources.dto.Trusonafication
import spock.lang.Specification

class TrucodeIdCallbackSpec extends Specification {

  UUID trucodeId
  TrucodeIdCallback sut

  def setup() {
    trucodeId = UUID.randomUUID()
    sut = new TrucodeIdCallback(trucodeId)
  }

  def "isValid should return true if trucodeId is not null"() {
    when:
    def res = sut.isValid()

    then:
    res
  }

  def "isValid should return false if trucodeId is null"() {
    given:
    sut = new TrucodeIdCallback(null)

    when:
    def res = sut.isValid()

    then:
    !res
  }

  def "fillIdentifier should set the trucodeId"() {
    given:
    def partialTruso = Trusonafication.essential()

    when:
    def builder = sut.fillIdentifier(partialTruso)
    def res = builder.action("foo").resource("bar").build()

    then:
    res.truCodeId == trucodeId
  }
}
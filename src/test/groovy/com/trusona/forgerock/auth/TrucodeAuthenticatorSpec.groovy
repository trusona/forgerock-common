package com.trusona.forgerock.auth

import com.trusona.sdk.resources.TrusonaApi
import com.trusona.sdk.resources.dto.Trusonafication
import com.trusona.sdk.resources.dto.TrusonaficationResult
import spock.lang.Specification

import static com.trusona.sdk.resources.dto.TrusonaficationStatus.ACCEPTED
import static com.trusona.sdk.resources.dto.TrusonaficationStatus.ACCEPTED_AT_LOWER_LEVEL
import static com.trusona.sdk.resources.dto.TrusonaficationStatus.EXPIRED
import static com.trusona.sdk.resources.dto.TrusonaficationStatus.INVALID
import static com.trusona.sdk.resources.dto.TrusonaficationStatus.IN_PROGRESS

class TrucodeAuthenticatorSpec extends Specification {

  TrusonaApi mockTrusona

  TrucodeAuthenticator sut

  def setup() {
    mockTrusona = Mock(TrusonaApi)
    sut = new TrucodeAuthenticator(mockTrusona)
  }

  def "should return a Principal when Trusonafication is accepted"() {
    given:
    def trucodeId = UUID.randomUUID()
    def trusonaficationId = UUID.randomUUID()
    def action = "eat"
    def resource = "tacos"

    def expectedTrusonafication = Trusonafication.essential()
      .truCode(trucodeId)
      .action(action)
      .resource(resource)
      .build()

    mockTrusona.createTrusonafication(expectedTrusonafication) >> new TrusonaficationResult(trusonaficationId, IN_PROGRESS, null, null);
    mockTrusona.getTrusonaficationResult(trusonaficationId) >> new TrusonaficationResult(trusonaficationId, ACCEPTED, "foobar", null)

    when:
    def res = sut.authenticate(trucodeId, action, resource)

    then:
    res.isPresent()
    res.get().name == 'foobar'
  }

  def "should return nothing when a Trusonafication is not accepted"() {
    given:
    def trucodeId = UUID.randomUUID()
    def trusonaficationId = UUID.randomUUID()
    def action = "eat"
    def resource = "tacos"

    def expectedTrusonafication = Trusonafication.essential()
      .truCode(trucodeId)
      .action(action)
      .resource(resource)
      .build()

    mockTrusona.createTrusonafication(expectedTrusonafication) >> new TrusonaficationResult(trusonaficationId, IN_PROGRESS, null, null);
    mockTrusona.getTrusonaficationResult(trusonaficationId) >> new TrusonaficationResult(trusonaficationId, status, "foobar", null)

    when:
    def res = sut.authenticate(trucodeId, action, resource)

    then:
    !res.isPresent()

    where:
    status << [ EXPIRED, INVALID, ACCEPTED_AT_LOWER_LEVEL ]
  }

  def "should return nothing when createTrusonafication returns INVALID"() {
    given:
    def trucodeId = UUID.randomUUID()
    def trusonaficationId = UUID.randomUUID()
    def action = "eat"
    def resource = "tacos"

    def expectedTrusonafication = Trusonafication.essential()
      .truCode(trucodeId)
      .action(action)
      .resource(resource)
      .build()

    mockTrusona.createTrusonafication(expectedTrusonafication) >> new TrusonaficationResult(trusonaficationId, INVALID, null, null);

    when:
    def res = sut.authenticate(trucodeId, action, resource)

    then:
    !res.isPresent()
    0 * mockTrusona.getTrusonaficationResult(_)

    where:
    status << [ EXPIRED, INVALID, ACCEPTED_AT_LOWER_LEVEL ]
  }
}
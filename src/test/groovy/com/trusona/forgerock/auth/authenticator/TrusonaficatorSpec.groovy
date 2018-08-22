package com.trusona.forgerock.auth.authenticator

import com.sun.identity.authentication.spi.AuthLoginException
import com.trusona.forgerock.auth.callback.TrusonaCallback
import com.trusona.sdk.resources.TrusonaApi
import com.trusona.sdk.resources.dto.Trusonafication
import com.trusona.sdk.resources.dto.TrusonaficationResult
import com.trusona.sdk.resources.exception.TrusonaException
import spock.lang.Specification
import spock.lang.Unroll

import static com.trusona.sdk.resources.dto.TrusonaficationStatus.*

class TrusonaficatorSpec extends Specification {

  Authenticator sut
  TrusonaApi mockTrusona
  TrusonaCallback callback

  def setup() {
    sut = new Trusonaficator(mockTrusona = Mock(TrusonaApi), "tacos", "jones")
    callback = Mock(TrusonaCallback)
  }

  def "createTrusonafication should create a Trusonafication"() {
    given:
    def trusonafication = Trusonafication.essential()
        .truCode(UUID.randomUUID())
        .action("tacos")
        .resource("jones")
        .build()

    def trusonaficationResult = new TrusonaficationResult(
        UUID.randomUUID(),
        IN_PROGRESS,
        UUID.randomUUID().toString(),
        null
    )

    mockTrusona.createTrusonafication(trusonafication) >> trusonaficationResult

    when:
    def res = sut.createTrusonafication(callback)

    then:
    1 * callback.fillIdentifier(_ as Trusonafication.IdentifierStep) >> Trusonafication.essential()
        .truCode(trusonafication.getTruCodeId())

    res == trusonaficationResult.getTrusonaficationId()
  }

  def "createTrusonafication should raise an AuthLoginException when an API error occurs"() {
    given:
    callback.fillIdentifier(_ as Trusonafication.IdentifierStep) >> Trusonafication.essential()
        .truCode(UUID.randomUUID())

    mockTrusona.createTrusonafication(_) >> { throw new TrusonaException("tacos") }

    when:
    sut.createTrusonafication(callback)

    then:
    thrown(AuthLoginException)
  }

  @Unroll
  def "createTrusonafication should raise an AuthLoginException when Trusonafication status is #status.inspect()"() {
    given:
    callback.fillIdentifier(_ as Trusonafication.IdentifierStep) >> Trusonafication.essential()
        .truCode(UUID.randomUUID())

    mockTrusona.createTrusonafication(_) >> new TrusonaficationResult(
        UUID.randomUUID(), status, "tacos", null)

    when:
    sut.createTrusonafication(callback)

    then:
    thrown(AuthLoginException)

    where:
    status << [
        ACCEPTED,
        ACCEPTED_AT_HIGHER_LEVEL,
        ACCEPTED_AT_LOWER_LEVEL,
        EXPIRED,
        INVALID,
        REJECTED
    ]
  }

  def "getTrusonaficationResult should return a result"() {
    given:
    def trusonaficationResult = new TrusonaficationResult(UUID.randomUUID(), ACCEPTED, "tacos", null)
    mockTrusona.getTrusonaficationResult(trusonaficationResult.trusonaficationId) >> trusonaficationResult

    when:
    def res = sut.getTrusonaficationResult(trusonaficationResult.trusonaficationId)

    then:
    res == trusonaficationResult
  }

  def "getTrusonaficationResult should raise an AuthLoginException when an API error occurs"() {
    given:
    mockTrusona.getTrusonaficationResult(_) >> { throw new TrusonaException("tacos") }

    when:
    sut.getTrusonaficationResult(UUID.randomUUID())

    then:
    thrown(AuthLoginException)
  }
}
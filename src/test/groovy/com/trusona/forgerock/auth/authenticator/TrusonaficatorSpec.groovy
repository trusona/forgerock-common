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
  static UUID TEST_TRUCODE_ID = UUID.randomUUID()

  class CallbackStub implements TrusonaCallback {
    @Override
    Trusonafication.ActionStep fillIdentifier(Trusonafication.IdentifierStep trusonafication) {
      return trusonafication.truCode(TEST_TRUCODE_ID)
    }

    @Override
    boolean isValid() {
      return false
    }
  }

  TrusonaApi mockTrusona
  TrusonaCallback callback

  def setup() {
    callback = new CallbackStub()
  }

  def "createTrusonafication should create an ES Trusonafication by default"() {
    given:
    def sut = new Trusonaficator(mockTrusona = Mock(TrusonaApi), "tacos", "jones")
    def trusonafication = Trusonafication.essential()
        .truCode(TEST_TRUCODE_ID)
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
    res == trusonaficationResult.getTrusonaficationId()
  }

  def "createTrusonafication should create an ES Trusonafication if authentication level is set to ESSENTIAL"() {
    given:
    def sut = new Trusonaficator(mockTrusona = Mock(TrusonaApi), "tacos", "jones", Trusonaficator.AuthenticationLevel.ESSENTIAL)
    def trusonafication = Trusonafication.essential()
      .truCode(TEST_TRUCODE_ID)
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
    res == trusonaficationResult.getTrusonaficationId()
  }

  def "createTrusonafication should create an EX Trusonafication if authentication level is set to EXECUTIVE"() {
    given:
    def sut = new Trusonaficator(mockTrusona = Mock(TrusonaApi), "tacos", "jones", Trusonaficator.AuthenticationLevel.EXECUTIVE)
    def trusonafication = Trusonafication.executive()
      .truCode(TEST_TRUCODE_ID)
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
    res == trusonaficationResult.getTrusonaficationId()
  }

  def "createTrusonafication should raise an AuthLoginException when an API error occurs"() {
    given:
    def sut = new Trusonaficator(mockTrusona = Mock(TrusonaApi), "tacos", "jones")

    mockTrusona.createTrusonafication(_) >> { throw new TrusonaException("tacos") }

    when:
    sut.createTrusonafication(callback)

    then:
    thrown(AuthLoginException)
  }

  @Unroll
  def "createTrusonafication should raise an AuthLoginException when Trusonafication status is #status.inspect()"() {
    given:
    def sut = new Trusonaficator(mockTrusona = Mock(TrusonaApi), "tacos", "jones")

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
    def sut = new Trusonaficator(mockTrusona = Mock(TrusonaApi), "tacos", "jones")
    def trusonaficationResult = new TrusonaficationResult(UUID.randomUUID(), ACCEPTED, "tacos", null)
    mockTrusona.getTrusonaficationResult(trusonaficationResult.trusonaficationId) >> trusonaficationResult

    when:
    def res = sut.getTrusonaficationResult(trusonaficationResult.trusonaficationId)

    then:
    res == trusonaficationResult
  }

  def "getTrusonaficationResult should raise an AuthLoginException when an API error occurs"() {
    given:
    def sut = new Trusonaficator(mockTrusona = Mock(TrusonaApi), "tacos", "jones")
    mockTrusona.getTrusonaficationResult(_) >> { throw new TrusonaException("tacos") }

    when:
    sut.getTrusonaficationResult(UUID.randomUUID())

    then:
    thrown(AuthLoginException)
  }
}
package com.trusona.forgerock.auth.principal

import com.sun.identity.idm.AMIdentity
import com.trusona.client.TrusonaClient
import com.trusona.client.dto.response.UserResponse
import com.trusona.sdk.resources.dto.TrusonaficationResult
import com.trusona.sdk.resources.dto.TrusonaficationStatus
import spock.lang.Specification

class DefaultPrincipalMapperSpec extends Specification {

  DefaultPrincipalMapper sut
  Date farFuture

  def setup() {
    sut = new DefaultPrincipalMapper(Mock(TrusonaClient), Mock(IdentityFinder))
    farFuture = new Date(System.currentTimeMillis() + 60 * 60 * 1000)
  }

  def "mapPrincipal should return the mapped SDK principal if the user identifier is tilted"() {
    when:
    def res = sut.mapPrincipal(Mock(TrusonaficationResult))

    then:
    1 * _.successful >> true
    1 * _.expiresAt >> new Date(System.currentTimeMillis() + 3600000)
    1 * _.userIdentifier >> "jones"
    1 * _.findForgeRockUser("jones") >> Mock(AMIdentity)
    1 * _.name >> "jones-uid"
    0 * _

    and:
    res.isPresent()
    res.get().name == "jones-uid"
  }

  def "mapPrincipal should return the mapped APP principal if the user identifier is from the Trusona App"() {
    when:
    def res = sut.mapPrincipal(Mock(TrusonaficationResult))

    then:
    1 * _.successful >> true
    1 * _.expiresAt >> new Date(System.currentTimeMillis() + 3600000)
    1 * _.userIdentifier >> "trusonaId:jones"
    1 * _.getUser("jones") >> Optional.of(Mock(UserResponse))
    1 * _.emails >> ["jones@example.net", "bob@africa.com"]
    1 * _.findForgeRockUser("jones@example.net") >> Mock(AMIdentity)
    1 * _.name >> "jones-uid"
    0 * _

    and:
    res.isPresent()
    res.get().name == "jones-uid"
  }

  def "mapPrincipal should return an empty optional when the trusonafication is not successful"() {
    given:
    def trusoResult = new TrusonaficationResult(UUID.randomUUID(), TrusonaficationStatus.ACCEPTED, "jones", farFuture) {
      @Override
      boolean isSuccessful() {
        false
      }
    }

    when:
    def res = sut.mapPrincipal(trusoResult)

    then:
    !res.isPresent()
  }

  def "mapPrincipal should return an empty optional when the user identifier is null"() {
    given:
    def trusoResult = new TrusonaficationResult(UUID.randomUUID(), TrusonaficationStatus.ACCEPTED, null, farFuture) {
      @Override
      boolean isSuccessful() {
        true
      }
    }

    when:
    def res = sut.mapPrincipal(trusoResult)

    then:
    !res.isPresent()
  }

  def "mapPrincipal should return an empty optional when the trusonafication expired more than a minute ago"() {
    given:
    def aWhileAgo = new Date(System.currentTimeMillis() - 60 * 60 * 1000)
    def trusoResult = new TrusonaficationResult(UUID.randomUUID(), TrusonaficationStatus.ACCEPTED, "jones", aWhileAgo)

    when:
    def res = sut.mapPrincipal(trusoResult)

    then:
    !res.isPresent()
  }

  def "mapPrincipal should return a principal when the trusonafication is successful and expired about 30 seconds ago"() {
    when:
    def res = sut.mapPrincipal(Mock(TrusonaficationResult))

    then:
    1 * _.successful >> true
    1 * _.expiresAt >> new Date(System.currentTimeMillis() - (30 * 1000))
    1 * _.userIdentifier >> "jones"
    1 * _.findForgeRockUser("jones") >> Mock(AMIdentity)
    1 * _.name >> "jones-uid"
    0 * _

    and:
    res.isPresent()
  }

  def "mapPrincipal should return first email if ForgeRock identity user is not found"() {
    when:
    def result = sut.mapPrincipal(Mock(TrusonaficationResult))

    then:
    1 * _.successful >> true
    1 * _.expiresAt >> new Date(System.currentTimeMillis() + 3600000)
    1 * _.userIdentifier >> "trusonaId:0123456789"
    1 * _.getUser("0123456789") >> [(Mock(UserResponse))]
    (1.._) * _.emails >> ["jones@example.net", "bob@africa.com"]
    1 * _.findForgeRockUser('jones@example.net') >> null
    1 * _.findForgeRockUser('bob@africa.com') >> null
    0 * _

    and:
    result.get().name == "jones@example.net"
  }

  def "mapPrincipal should return ForgeRock identity when is found"() {
    when:
    def result = sut.mapPrincipal(Mock(TrusonaficationResult))

    then:
    1 * _.successful >> true
    1 * _.expiresAt >> new Date(System.currentTimeMillis() + 3600000)
    1 * _.userIdentifier >> "trusonaId:0123456789"
    1 * _.getUser("0123456789") >> [(Mock(UserResponse))]
    (1.._) * _.emails >> ["jones@example.net", "bob@africa.com"]
    1 * _.findForgeRockUser('jones@example.net') >> null
    1 * _.findForgeRockUser('bob@africa.com') >> Mock(AMIdentity)
    1 * _.name >> "909090"
    0 * _

    and:
    result.get().name == "909090"
  }

  def "mapPrincipal should return an empty principal when the Trusona user is not found"() {
    when:
    def result = sut.mapPrincipal(Mock(TrusonaficationResult))

    then:
    1 * _.successful >> true
    1 * _.expiresAt >> new Date(System.currentTimeMillis() + 3600000)
    1 * _.userIdentifier >> "trusonaId:0123456789"
    1 * _.getUser("0123456789") >> []
    0 * _

    and:
    !result.present
  }

  def "mapPrincipal should return the userIdentifier"() {
    given:
    def trusoResult = new TrusonaficationResult(UUID.randomUUID(), TrusonaficationStatus.ACCEPTED, "jones", new Date())

    when:
    def res = sut.mapPrincipal(trusoResult)

    then:
    res.isPresent()
    res.get().name == "jones"
  }
}

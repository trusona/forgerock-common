package com.trusona.forgerock.auth.callback

import com.sun.identity.authentication.callbacks.HiddenValueCallback
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback
import spock.lang.Specification

import javax.security.auth.callback.Callback
import javax.security.auth.callback.ChoiceCallback
import javax.security.auth.callback.NameCallback

class DefaultCallbackParserSpec extends Specification {

  DefaultCallbackParser sut
  NameCallback identifierCallback
  ChoiceCallback choiceCallback
  Callback[] callbacks

  def setup() {
    sut = new DefaultCallbackParser()

    identifierCallback = new NameCallback("identifier")

    def choices = [ "user_identifier", "device_identifier", "trucode_id" ]
    choiceCallback = new ChoiceCallback(
      "identifier type",
      (String[]) choices.toArray(),
      0,
      false
    )

    callbacks = new Callback[2]
    callbacks[0] = identifierCallback
    callbacks[1] = choiceCallback

  }

  def "parseCallback should return a UserIdentifierCallback when a user_identifier is provided"() {
    given:
    identifierCallback.setName("jones")
    choiceCallback.setSelectedIndex(0)

    when:
    def res = sut.getTrusonaCallback(callbacks)

    then:
    res.isPresent()
    res.get() instanceof UserIdentifierCallback
    res.get().isValid()
    res.get().userIdentifier == 'jones'
  }

  def "parseCallback should return a DeviceIdentifierCallback when a device_identifier is provided"() {
    given:
    identifierCallback.setName("foobar")
    choiceCallback.setSelectedIndex(1)

    when:
    def res = sut.getTrusonaCallback(callbacks)

    then:
    res.isPresent()
    res.get() instanceof DeviceIdentifierCallback
    res.get().isValid()
    res.get().deviceIdentifier == 'foobar'
  }

  def "parseCallback should return a TrucodeIdCallback when a trucode_id is provided"() {
    given:
    def trucodeId = UUID.randomUUID()
    identifierCallback.setName(trucodeId.toString())
    choiceCallback.setSelectedIndex(2)

    when:
    def res = sut.getTrusonaCallback(callbacks)

    then:
    res.isPresent()
    res.get() instanceof TrucodeIdCallback
    res.get().isValid()
    res.get().trucodeId == trucodeId
  }

  def "parseCallback should return an empty Optional when trucode is not a UUID"() {
    given:
    identifierCallback.setName("foobar")
    choiceCallback.setSelectedIndex(2)

    when:
    def res = sut.getTrusonaCallback(callbacks)

    then:
    !res.isPresent()
  }

  def "parseCallback should return a TrucodeIdCallback when we get a trucode_id from a QR"() {
    given:
    def trucodeId = UUID.randomUUID()

    def trucodeCallback = new HiddenValueCallback("truCodeId")
    trucodeCallback.setValue(trucodeId.toString())

    def trucodeCallbacks = new Callback[5]
    trucodeCallbacks[0] = new ScriptTextOutputCallback("foo")
    trucodeCallbacks[1] = trucodeCallback
    trucodeCallbacks[2] = new HiddenValueCallback("error")
    trucodeCallbacks[3] = new HiddenValueCallback("payload")
    trucodeCallbacks[4] = new HiddenValueCallback("trusonaficationId")

    when:
    def res = sut.getTrusonaCallback(trucodeCallbacks)

    then:
    res.isPresent()
    res.get() instanceof TrucodeIdCallback
    res.get().valid
    res.get().trucodeId == trucodeId
  }

  def "getCallbackValue should get the value for the callback"() {
    given:
    def callback = new HiddenValueCallback("foo")
    callback.setValue(value)

    when:
    def res = sut.getCallbackValue(callback)

    then:
    res == value

    where:
    value << ["bar", "fizz", "buzz", "", null ]
  }

  // This is to work around a bug in forgerock where empty values get replaced with the id. -tom
  def "getCallbackValue should return an emtpy string when the value == the id"() {
    given:
    def callback = new HiddenValueCallback("foo")
    callback.setValue("foo")

    when:
    def res = sut.getCallbackValue(callback)

    then:
    res == ""
  }
}

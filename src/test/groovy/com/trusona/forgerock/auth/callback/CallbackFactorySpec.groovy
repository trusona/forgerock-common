package com.trusona.forgerock.auth.callback

import spock.lang.Specification

class CallbackFactorySpec extends Specification {

  CallbackFactory sut = new CallbackFactory("websdk", "deeplink", "callbackId")

  def "makeScriptCallback should return a callback that has our bundled JS"() {
    when:
    def res = sut.makeScriptCallback("app.renderTrucode();")

    then:
    res.message.contains("this is a test")
    res.message.contains("var app = new TrusonaFR(websdk, 'deeplink', 'callbackId');")
    res.message.contains("app.renderTrucode();")
  }

  def "getRedirectCallback should return a Redirect URL for the deeplink"() {
    when:
    def res = sut.makeRedirectCallback("somePayload")

    then:
    res.method == "GET"
    res.redirectUrl == "deeplink?payload=somePayload" /* another forgerock bug workaround */
    res.redirectData["payload"] == 'somePayload'
  }


  def "should use trusona-app.net if not deeplink url is provided"() {
    given:
    sut = new CallbackFactory("websdk", deeplinkUrl, "trucodeId")

    when:
    def res = sut.makeRedirectCallback("payload")

    then:
    res.redirectUrl.startsWith("https://trusona-app.net/idp")

    where:
    deeplinkUrl << [ null, "", "   " ]
  }
}

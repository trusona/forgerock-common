import Trusona from 'trusona-trucode';
import { Browser, LocalStorage } from '@trusona/deeplink';
import jQuery from 'jquery';

class TrusonaFR {
  constructor(truCodeConfig, deeplinkUrl, trucodeElementId) {
    this.deeplinkUrl = deeplinkUrl;
    this.truCodeConfig = truCodeConfig;
    this.jQuery = jQuery;
    this.browser = new Browser(window);
    this.localStorage = new LocalStorage(window);

    this.trucodeElement = window.document.getElementById(trucodeElementId);
    this.truCodeInput = window.document.getElementById('truCodeId');
    this.errorInput = window.document.getElementById('error');
    this.payloadInput = window.document.getElementById('payload');
    this.trusonaficationIdInput = window.document.getElementById('trusonaficationId');
    this.submitBtn = this.jQuery('input[type=submit]');
  }

  run() {
    this.submitBtn.hide();
    if (this.browser.userAgent.supportsDeeplink()) {
      this.loadTrusonaficationCookie();
      if (this.trusonaficationIdInput.value) {
        this.submitBtn.trigger('click');
      } else {
        Trusona.createTruCode(this.truCodeConfig, this.doOnCreate.bind(this));
      }
    } else {
      Trusona.renderTruCode({
        truCodeConfig: this.truCodeConfig,
        truCodeElement: this.trucodeElement,
        onPaired: this.doOnPaired.bind(this),
        onError: this.doOnError.bind(this),
      });
    }
  }

  doOnCreate(trucode) {
    this.truCodeInput.value = trucode.id;
    this.payloadInput.value = trucode.payload;
    this.submitBtn.trigger('click');
  }

  doOnPaired(trucodeId) {
    this.truCodeInput.value = trucodeId;
    this.submitBtn.trigger('click');
  }

  doOnError() {
    this.errorInput.value = 'Error from Trusona.renderTruCode';
    this.submitBtn.trigger('click');
  }

  saveTrusonaficationCookie(trusonaficationId) {
    this.localStorage.set('trusonaficationId', trusonaficationId);
    // in the case where the browser uses a universal link and goes straight into the app
    // without navigating away, reload the page after a delay (i.e. when they return from the app)
    // so that the auth flow restarts, then reads the trusonafication id from local storage and
    // continues on, like it would in the case where the browser went to trusona-app.net and then
    // came back.
    window.setTimeout(() => {
      window.location.reload(false);
    }, 1000);
  }

  loadTrusonaficationCookie() {
    this.trusonaficationIdInput.value = this.localStorage.get('trusonaficationId');
    this.localStorage.clear('trusonaficationId');
  }
}

export default TrusonaFR;

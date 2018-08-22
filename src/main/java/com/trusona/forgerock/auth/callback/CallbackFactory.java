package com.trusona.forgerock.auth.callback;

import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.authentication.spi.RedirectCallback;
import com.trusona.forgerock.auth.TrusonaDebug;
import okio.Okio;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.util.Collections;
import java.util.Optional;

public class CallbackFactory {
  private static final String JS_RESOURCE = "main.bundle.js";
  private static final String HTTP_GET = "GET";
  private static final String DEFAULT_DEEPLINK_URL = "https://trusona-app.net/idp";

  private final String webSdkConfig;
  private final String deeplinkUrl;
  private final String trucodeElementId;

  public CallbackFactory(String webSdkConfig, String deeplinkUrl, String trucodeElementId) {
    this.webSdkConfig = webSdkConfig;
    this.trucodeElementId = trucodeElementId;
    this.deeplinkUrl = Optional.ofNullable(deeplinkUrl)
      .filter(StringUtils::isNotBlank)
      .orElse(DEFAULT_DEEPLINK_URL);
  }

  public ScriptTextOutputCallback makeScriptCallback(String command) {
    StringBuilder scriptBuilder = new StringBuilder();

    try {
      scriptBuilder.append(Okio.buffer(Okio.source(getClass().getClassLoader().getResourceAsStream(JS_RESOURCE))).readUtf8());
    }
    catch (IOException e) {
      TrusonaDebug.getInstance().error("Error loading javascript", e);
    }

    scriptBuilder.append("\n");
    scriptBuilder.append(String.format("var app = new TrusonaFR(%s, '%s', '%s');%n", webSdkConfig, deeplinkUrl, trucodeElementId));
    scriptBuilder.append(command);

    return new ScriptTextOutputCallback(scriptBuilder.toString());
  }

  public RedirectCallback makeRedirectCallback(String payload) {
    TrusonaDebug.getInstance().message("Building Redirect Callback with deeplinkUrl => {} payload => {}", deeplinkUrl, payload);

    return new RedirectCallback(
      String.format("%s?payload=%s", deeplinkUrl, payload),
      Collections.singletonMap("payload", payload),
      HTTP_GET);
  }
}


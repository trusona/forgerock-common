package com.trusona.forgerock.auth;

import java.net.MalformedURLException;
import java.net.URL;

public class Constants {
  //These values must match what we are looking for in index.js!!
  public static final String TRUCODE_ID = "truCodeId";
  public static final String ERROR = "error";
  public static final String PAYLOAD = "payload";
  public static final String TRUSONAFICATION_ID = "trusonaficationId";

  public static final String WAIT_TIME     = "5000";
  public static final String CALLBACK_ZERO = "callback_0";

  public static final URL ENDPOINT_URL_UAT = staticUrl("https://api.staging.trusona.net");
  public static final URL ENDPOINT_URL_PRODUCTION = staticUrl("https://api.trusona.net");

  private static URL staticUrl(String urlString) {
    URL url;
    try {
      url = new URL(urlString);
    }
    catch (MalformedURLException e) {
      throw new RuntimeException("Precompiled, static URL was malformed... contact Trusona and have them get their stuff together");
    }
    return url;
  }
}

package com.trusona.forgerock.auth;

import com.trusona.sdk.TrusonaEnvironment;

import java.util.Optional;

public class TrusonaEnvResolver {
  private static final String TRUSONA_ENVIRONMENT = "trusona.environment";
  private static final String UAT = "uat";

  public TrusonaEnvironment getEnvironment() {
    return Optional.ofNullable(System.getProperty(TRUSONA_ENVIRONMENT))
      .map(String::toLowerCase)
      .filter(s -> s.equals(UAT))
      .map(s -> TrusonaEnvironment.UAT)
      .orElse(TrusonaEnvironment.PRODUCTION);
  }
}

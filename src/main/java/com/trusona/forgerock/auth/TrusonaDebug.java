package com.trusona.forgerock.auth;

import com.sun.identity.shared.debug.Debug;

public class TrusonaDebug {
  private static final Debug DEBUG;

  static {
    DEBUG = Debug.getInstance("TrusonaAuth");
    DEBUG.setDebug(Debug.MESSAGE);
  }

  private TrusonaDebug() {
  }

  public static Debug getInstance() {
    return DEBUG;
  }
}
package com.trusona.forgerock.auth.callback;

import com.trusona.sdk.resources.dto.Trusonafication;
import org.apache.commons.lang3.StringUtils;

public class UserIdentifierCallback implements TrusonaCallback {
  private String userIdentifier;

  public UserIdentifierCallback(String userIdentifier) {
    this.userIdentifier = userIdentifier;
  }

  @Override
  public Trusonafication.ActionStep fillIdentifier(Trusonafication.IdentifierStep trusonafication) {
    return trusonafication.userIdentifier(userIdentifier);
  }

  @Override
  public boolean isValid() {
    return StringUtils.trimToNull(userIdentifier) != null;
  }
}
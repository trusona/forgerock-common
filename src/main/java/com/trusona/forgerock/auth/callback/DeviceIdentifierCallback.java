package com.trusona.forgerock.auth.callback;

import com.trusona.sdk.resources.dto.Trusonafication;
import org.apache.commons.lang3.StringUtils;

public class DeviceIdentifierCallback implements TrusonaCallback {
  private String deviceIdentifier;

  public DeviceIdentifierCallback(String deviceIdentifier) {
    this.deviceIdentifier = deviceIdentifier;
  }

  @Override
  public Trusonafication.ActionStep fillIdentifier(Trusonafication.IdentifierStep trusonafication) {
    return trusonafication.deviceIdentifier(deviceIdentifier);
  }

  @Override
  public boolean isValid() {
    return StringUtils.trimToNull(deviceIdentifier) != null;
  }
}
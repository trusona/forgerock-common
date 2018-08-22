package com.trusona.forgerock.auth.callback;


import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.authentication.spi.RedirectCallback;
import com.trusona.forgerock.auth.TrusonaDebug;
import org.apache.commons.lang3.StringUtils;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ChoiceCallback;
import javax.security.auth.callback.NameCallback;
import java.util.Collections;
import java.util.Optional;
import java.util.UUID;

public class DefaultCallbackParser implements CallbackParser {
  private static final String USER_IDENTIFIER = "user_identifier";
  private static final String DEVICE_IDENTIFIER = "device_identifier";
  private static final String TRUCODE_ID = "trucode_id";

  @Override
  public Optional<TrusonaCallback> getTrusonaCallback(Callback[] callbacks) {
    TrusonaCallback trusonaCallback = null;

    if (callbacks.length == 2) {
      NameCallback identifierCallback = (NameCallback) callbacks[0];
      ChoiceCallback typeCallback = (ChoiceCallback) callbacks[1];

      String identifierType = typeCallback.getChoices()[typeCallback.getSelectedIndexes()[0]];

      TrusonaDebug.getInstance().message(String.format("Got an identifier of %s and a type of %s", identifierCallback.getName(), identifierType));

      switch (identifierType) {
        case USER_IDENTIFIER:
          trusonaCallback = new UserIdentifierCallback(identifierCallback.getName());
          break;

        case DEVICE_IDENTIFIER:
          trusonaCallback = new DeviceIdentifierCallback(identifierCallback.getName());
          break;

        case TRUCODE_ID:
          try {
            trusonaCallback = new TrucodeIdCallback(UUID.fromString(identifierCallback.getName()));
          }
          catch (IllegalArgumentException e) {
            TrusonaDebug.getInstance().error("Trucode was not a UUID", e);
          }
          break;
      }
    }
    else if (callbacks.length == 5) {
      HiddenValueCallback trucodeIdCallback = (HiddenValueCallback) callbacks[1];
      UUID trucodeId = UUID.fromString(trucodeIdCallback.getValue());

      try {
        trusonaCallback = new TrucodeIdCallback(trucodeId);
      }
      catch (IllegalArgumentException e) {
        TrusonaDebug.getInstance().error("Trucode was not a UUID", e);
      }
    }

    return Optional.ofNullable(trusonaCallback);
  }

  @Override
  public String getCallbackValue(HiddenValueCallback callback) {
    return callback.getId().equals(callback.getValue()) ? "" : callback.getValue();
  }
}
package com.trusona.forgerock.auth.callback;

import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.authentication.spi.RedirectCallback;

import javax.security.auth.callback.Callback;
import java.util.Optional;

public interface CallbackParser {
  Optional<TrusonaCallback> getTrusonaCallback(Callback[] callbacks);

  String getCallbackValue(HiddenValueCallback callback);
}

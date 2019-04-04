package com.trusona.forgerock.auth.callback;

import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import java.util.Optional;
import javax.security.auth.callback.Callback;

public interface CallbackParser {

  Optional<TrusonaCallback> getTrusonaCallback(Callback[] callbacks);

  String getCallbackValue(HiddenValueCallback callback);
}

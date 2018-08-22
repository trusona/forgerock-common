package com.trusona.forgerock.auth.authenticator;

import com.sun.identity.authentication.spi.AuthLoginException;
import com.trusona.forgerock.auth.callback.TrusonaCallback;
import com.trusona.sdk.resources.dto.TrusonaficationResult;

import java.util.UUID;

public interface Authenticator {
  UUID createTrusonafication(TrusonaCallback callback) throws AuthLoginException;

  TrusonaficationResult getTrusonaficationResult(UUID trusonaficationId) throws AuthLoginException;
}
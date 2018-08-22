package com.trusona.forgerock.auth;

import com.sun.identity.authentication.internal.AuthPrincipal;
import com.trusona.sdk.resources.TrusonaApi;
import com.trusona.sdk.resources.dto.Trusonafication;
import com.trusona.sdk.resources.dto.TrusonaficationResult;
import com.trusona.sdk.resources.dto.TrusonaficationStatus;
import com.trusona.sdk.resources.exception.TrusonaException;

import java.security.Principal;
import java.util.Optional;
import java.util.UUID;

public class TrucodeAuthenticator {
  private TrusonaApi trusona;

  public TrucodeAuthenticator(TrusonaApi trusona) {
    this.trusona = trusona;
  }

  public Optional<Principal> authenticate(UUID trucodeId, String action, String resource) throws TrusonaException {
    TrusonaDebug.getInstance().message("trucodeId = {}; action = {}; resource = {}", trucodeId, action, resource);
    Principal principal = null;

    TrusonaficationResult result = trusona.createTrusonafication(Trusonafication.essential()
      .truCode(trucodeId)
      .action(action)
      .resource(resource)
      .build());

    UUID trusonaficationId = result.getTrusonaficationId();

    if (TrusonaficationStatus.IN_PROGRESS.equals(result.getStatus())) {
      result = trusona.getTrusonaficationResult(trusonaficationId);
      TrusonaDebug.getInstance().message("TrusonaficationResult => {}", result);

      if (result.isSuccessful()) {
        TrusonaDebug.getInstance().message("result was successful");
        principal = new AuthPrincipal(result.getUserIdentifier());
      }
      else {
        TrusonaDebug.getInstance().warning("result was not successful");
      }
    }

    return Optional.ofNullable(principal);
  }
}
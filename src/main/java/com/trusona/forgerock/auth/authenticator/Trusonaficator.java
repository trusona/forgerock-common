package com.trusona.forgerock.auth.authenticator;

import static com.trusona.sdk.resources.dto.TrusonaficationStatus.IN_PROGRESS;

import com.sun.identity.authentication.spi.AuthLoginException;
import com.trusona.forgerock.auth.TrusonaDebug;
import com.trusona.forgerock.auth.callback.TrusonaCallback;
import com.trusona.sdk.resources.TrusonaApi;
import com.trusona.sdk.resources.dto.Trusonafication;
import com.trusona.sdk.resources.dto.Trusonafication.IdentifierStep;
import com.trusona.sdk.resources.dto.TrusonaficationResult;
import com.trusona.sdk.resources.exception.TrusonaException;
import java.util.UUID;

public final class Trusonaficator implements Authenticator {

  public enum AuthenticationLevel {
    ESSENTIAL,
    EXECUTIVE
  }

  private final TrusonaApi trusona;
  private final String action;
  private final String resource;
  private final AuthenticationLevel authenticationLevel;

  public Trusonaficator(TrusonaApi trusona, String action, String resource) {
    this(trusona, action, resource, AuthenticationLevel.ESSENTIAL);
  }

  public Trusonaficator(TrusonaApi trusona, String action, String resource, AuthenticationLevel authenticationLevel) {
    this.trusona = trusona;
    this.action = action;
    this.resource = resource;
    this.authenticationLevel = authenticationLevel;
  }

  @Override
  public UUID createTrusonafication(TrusonaCallback callback) throws AuthLoginException {
    Trusonafication trusonafication = callback.fillIdentifier(getBuilder())
      .action(action)
      .resource(resource)
      .build();

    try {
      TrusonaficationResult result = trusona.createTrusonafication(trusonafication);
      TrusonaDebug.getInstance().message("TrusonaficationResult = {}", result);

      if (IN_PROGRESS.equals(result.getStatus())) {
        return result.getTrusonaficationId();
      }

      throw new AuthLoginException(String.format("Trusonafication status was not expected, was %s", result.getStatus()));
    }
    catch (TrusonaException ex) {
      TrusonaDebug.getInstance().error("An error occurred while creating a Trusonafication", ex);
      throw new AuthLoginException("An error occurred while creating a Trusonafication", ex);
    }
  }

  @Override
  public TrusonaficationResult getTrusonaficationResult(UUID trusonaficationId) throws AuthLoginException {
    try {
      return trusona.getTrusonaficationResult(trusonaficationId);
    }
    catch (TrusonaException ex) {
      TrusonaDebug.getInstance().error("An error occurred while creating a Trusonafication", ex);
      throw new AuthLoginException("An error occurred while creating a Trusonafication", ex);
    }
  }

  private IdentifierStep getBuilder() {
    if (authenticationLevel == AuthenticationLevel.EXECUTIVE) {
      return Trusonafication.executive();
    }
    else {
      return Trusonafication.essential();
    }
  }
}
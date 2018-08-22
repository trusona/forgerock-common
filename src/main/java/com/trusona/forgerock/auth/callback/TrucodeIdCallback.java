package com.trusona.forgerock.auth.callback;

import com.trusona.sdk.resources.dto.Trusonafication;

import java.util.UUID;

public class TrucodeIdCallback implements TrusonaCallback {
  private UUID trucodeId;

  public TrucodeIdCallback(UUID trucodeId) {
    this.trucodeId = trucodeId;
  }

  @Override
  public Trusonafication.ActionStep fillIdentifier(Trusonafication.IdentifierStep trusonafication) {
    return trusonafication.truCode(trucodeId);
  }

  @Override
  public boolean isValid() {
    return trucodeId != null;
  }
}
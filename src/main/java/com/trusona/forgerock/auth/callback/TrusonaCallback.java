package com.trusona.forgerock.auth.callback;

import com.trusona.sdk.resources.dto.Trusonafication;

public interface TrusonaCallback {

  Trusonafication.ActionStep fillIdentifier(Trusonafication.IdentifierStep trusonafication);

  boolean isValid();

}
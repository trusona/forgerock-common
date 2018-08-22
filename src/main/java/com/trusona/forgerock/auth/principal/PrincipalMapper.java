package com.trusona.forgerock.auth.principal;

import com.trusona.sdk.resources.dto.TrusonaficationResult;

import java.security.Principal;
import java.util.Optional;

public interface PrincipalMapper {
  Optional<Principal> mapPrincipal(TrusonaficationResult result);
}
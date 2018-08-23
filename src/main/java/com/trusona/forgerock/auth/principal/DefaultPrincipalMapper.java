package com.trusona.forgerock.auth.principal;

import com.sun.identity.authentication.internal.AuthPrincipal;
import com.sun.identity.idm.AMIdentity;
import com.trusona.client.TrusonaClient;
import com.trusona.client.dto.response.UserResponse;
import com.trusona.forgerock.auth.TrusonaDebug;
import com.trusona.sdk.resources.dto.TrusonaficationResult;

import java.security.Principal;
import java.util.*;

public class DefaultPrincipalMapper implements PrincipalMapper {
  private static final String TRUSONA_APP_PREFIX = "trusonaId:";

  private final TrusonaClient trusonaClient;
  private final IdentityFinder identityFinder;

  public DefaultPrincipalMapper(TrusonaClient trusonaClient, IdentityFinder identityFinder) {
    this.trusonaClient = trusonaClient;
    this.identityFinder = identityFinder;
  }

  @Override
  public Optional<Principal> mapPrincipal(TrusonaficationResult result) {
    TrusonaDebug.getInstance().message("Mapping Result to Principal: {}", result);
    Date lastAllowedExpiration = new Date(System.currentTimeMillis() - 60 * 1000);

    return Optional.of(result)
      .filter(TrusonaficationResult::isSuccessful)
      .filter(trusonaficationResult -> trusonaficationResult.getExpiresAt().after(lastAllowedExpiration))
      .map(TrusonaficationResult::getUserIdentifier)
      .flatMap(this::mapPrincipal);
  }


  private Optional<Principal> mapPrincipal(String userIdentifier) {
    List<String> subjects = getSubjects(userIdentifier);
    AMIdentity identity = null;

    if (subjects.isEmpty()) {
      return Optional.empty();
    }

    for (String subject : subjects) {
      TrusonaDebug.getInstance().message("Looking within ForgeRock for user with subject '{}'", subject);
      identity = identityFinder.findForgeRockUser(subject);

      if (identity != null) {
        TrusonaDebug.getInstance().message("User found!");
        break;
      }
    }

    AuthPrincipal authPrincipal = new AuthPrincipal(identity != null ? identity.getName() : subjects.get(0));
    return Optional.of(authPrincipal);
  }

  private List<String> getSubjects(String userIdentifier) {
    if (userIdentifier.startsWith(TRUSONA_APP_PREFIX)) {
      String trusonaId = userIdentifier.replace(TRUSONA_APP_PREFIX, "");
      TrusonaDebug.getInstance().message("Looking up user by trusonaId {}", trusonaId);

      Optional<UserResponse> userResponse = trusonaClient.getUser(trusonaId);
      return userResponse.<List<String>>map(response -> new LinkedList<>(response.getEmails())).orElse(Collections.emptyList());
    }
    else {
      return Collections.singletonList(userIdentifier);
    }
  }
}
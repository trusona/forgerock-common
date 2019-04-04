package com.trusona.forgerock.auth.principal;

import com.sun.identity.authentication.internal.AuthPrincipal;
import com.sun.identity.idm.AMIdentity;
import com.trusona.client.TrusonaClient;
import com.trusona.client.dto.response.UserResponse;
import com.trusona.forgerock.auth.TrusonaDebug;
import com.trusona.sdk.resources.dto.TrusonaficationResult;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

public class DefaultPrincipalMapper implements PrincipalMapper {

  private static final String TRUSONA_APP_PREFIX = "trusonaId:";
  private static final String UID = "uid";
  private static final String ID = "id";

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

    AuthPrincipal authPrincipal;

    if (identity != null) {
      String name = identity.getName();

      Stream<Optional<String>> stream = Stream.<Optional<String>>builder()
        .add(getIdentityField(name, UID))
        .add(getIdentityField(name, ID))
        .build();

      String identityName = stream.filter(Optional::isPresent)
        .map(Optional::get)
        .findFirst()
        .orElse(name);

      authPrincipal = new AuthPrincipal(identityName);
    }
    else {
      authPrincipal = new AuthPrincipal(subjects.get(0));
    }

    return Optional.of(authPrincipal);
  }

  private Optional<String> getIdentityField(String identityName, String key) {
    String idField = key + "=";
    return Arrays.stream(identityName.split(","))
      .filter(identityNamePair -> identityNamePair.startsWith(idField))
      .map(uidPair -> uidPair.replace(idField, ""))
      .findFirst();
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
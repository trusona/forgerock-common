package com.trusona.forgerock.auth.principal;

import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdUtils;

import java.util.Collections;
import java.util.Set;

public class IdentityFinder {
  private final String organization;
  private final Set<String> userAliasSet;

  public IdentityFinder(Set<String> userAliasSet, String organization) {
    this.userAliasSet = Collections.unmodifiableSet(userAliasSet);
    this.organization = organization;
  }

  AMIdentity findForgeRockUser(String subject) {
    return IdUtils.getIdentity(subject, organization, userAliasSet);
  }
}
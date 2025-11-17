package org.bonitasoft.connectors.rest.model;

public enum AuthorizationType {
  NONE,
  BASIC,
  DIGEST,
  OAUTH2_CLIENT_CREDENTIALS("OAUTH2 (Client Credentials)"),
  OAUTH2_BEARER("OAUTH2 (Bearer)"),
  OAUTH2_AUTHORIZATION_CODE("OAUTH2 (Authorization Code)");

  private final String displayName;

  AuthorizationType() {
    this.displayName = name();
  }

  AuthorizationType(String displayName) {
    this.displayName = displayName;
  }

  public String getDisplayName() {
    return displayName;
  }

  public static AuthorizationType fromString(String value) {
    if (value == null) {
      return null;
    }
    for (AuthorizationType type : values()) {
      if (type.name().equals(value) || type.displayName.equals(value)) {
        return type;
      }
    }
    throw new IllegalArgumentException("Unknown AuthorizationType: " + value);
  }
}
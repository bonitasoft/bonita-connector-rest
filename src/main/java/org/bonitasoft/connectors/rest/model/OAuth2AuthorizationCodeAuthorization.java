/**
 * Copyright (C) 2025 BonitaSoft S.A. BonitaSoft, 32 rue Gustave Eiffel - 38000 Grenoble This
 * library is free software; you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation version 2.1 of the
 * License. This library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU Lesser General Public License for more details. You should have received a
 * copy of the GNU Lesser General Public License along with this program; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package org.bonitasoft.connectors.rest.model;

/**
 * This class represents OAuth2 Authorization Code with optional PKCE authorization information. The
 * authorization code and code_verifier must be provided by the user (obtained through the OAuth2
 * authorization flow externally).
 */
public class OAuth2AuthorizationCodeAuthorization extends OAuth2TokenRequestAuthorization {

  private String code;
  private String codeVerifier;
  private String redirectUri;

  public String getCode() {
    return code;
  }

  public void setCode(final String code) {
    this.code = code;
  }

  public String getCodeVerifier() {
    return codeVerifier;
  }

  public void setCodeVerifier(final String codeVerifier) {
    this.codeVerifier = codeVerifier;
  }

  public String getRedirectUri() {
    return redirectUri;
  }

  public void setRedirectUri(final String redirectUri) {
    this.redirectUri = redirectUri;
  }
}

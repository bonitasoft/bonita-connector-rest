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
 * Base class for OAuth2 authorization types that require token exchange at a token endpoint.
 * This includes Client Credentials and Authorization Code flows.
 */
public abstract class OAuth2TokenRequestAuthorization implements Authorization {

  private String tokenEndpoint;
  private String clientId;
  private String clientSecret;

  public String getTokenEndpoint() {
    return tokenEndpoint;
  }

  public void setTokenEndpoint(final String tokenEndpoint) {
    this.tokenEndpoint = tokenEndpoint;
  }

  public String getClientId() {
    return clientId;
  }

  public void setClientId(final String clientId) {
    this.clientId = clientId;
  }

  public String getClientSecret() {
    return clientSecret;
  }

  public void setClientSecret(final String clientSecret) {
    this.clientSecret = clientSecret;
  }
}

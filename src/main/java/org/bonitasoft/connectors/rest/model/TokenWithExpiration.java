/**
 * Copyright (C) 2014-2025 BonitaSoft S.A. BonitaSoft, 32 rue Gustave Eiffel - 38000 Grenoble This
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
 * Stores an OAuth2 access token along with its expiration timestamp.
 * This allows expiration checking without assuming the token is a JWT.
 */
public class TokenWithExpiration {

    private final String accessToken;
    private final long expirationTimeMillis;

    /**
     * Create a new token with expiration
     *
     * @param accessToken The OAuth2 access token
     * @param expirationTimeMillis The expiration time in milliseconds since epoch
     */
    public TokenWithExpiration(String accessToken, long expirationTimeMillis) {
        this.accessToken = accessToken;
        this.expirationTimeMillis = expirationTimeMillis;
    }

    /**
     * Get the access token
     *
     * @return The access token
     */
    public String getAccessToken() {
        return accessToken;
    }

    /**
     * Get the expiration time in milliseconds since epoch
     *
     * @return The expiration time
     */
    public long getExpirationTimeMillis() {
        return expirationTimeMillis;
    }

    /**
     * Check if this token is expired (with optional clock skew)
     *
     * @param clockSkewSeconds Number of seconds before actual expiration to treat as expired
     * @return true if expired, false otherwise
     */
    public boolean isExpired(long clockSkewSeconds) {
        long nowMillis = System.currentTimeMillis();
        long expirationWithSkew = expirationTimeMillis - (clockSkewSeconds * 1000);
        return expirationWithSkew <= nowMillis;
    }
}

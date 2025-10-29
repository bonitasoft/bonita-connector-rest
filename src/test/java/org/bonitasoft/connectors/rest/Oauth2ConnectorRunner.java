/**
 * Copyright (C) 2025 BonitaSoft S.A.
 * BonitaSoft, 32 rue Gustave Eiffel - 38000 Grenoble
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2.0 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package org.bonitasoft.connectors.rest;

import org.bonitasoft.connectors.rest.model.AuthorizationType;
import org.bonitasoft.engine.api.APIAccessor;
import org.bonitasoft.engine.connector.EngineExecutionContext;
import org.mockito.Mockito;

import java.util.HashMap;
import java.util.Map;

import static org.bonitasoft.connectors.rest.AbstractRESTConnectorImpl.*;

/**
 * Standalone runner for OAuth2 connector testing
 *
 * This class allows running the OAuth2 connector from command line with parameters.
 * It's designed to be called from the Python script for manual testing with real OAuth2 providers.
 *
 * Usage:
 *   ./mvnw exec:java -Dexec.mainClass="org.bonitasoft.connectors.rest.Oauth2ConnectorRunner" \
 *     -Dexec.classpathScope="test" \
 *     -Dexec.args="token_endpoint client_id client_secret auth_code [redirect_uri]"
 *
 * Example:
 *   ./mvnw exec:java -Dexec.mainClass="org.bonitasoft.connectors.rest.Oauth2ConnectorRunner" \
 *     -Dexec.classpathScope="test" \
 *     -Dexec.args="https://oauth2.googleapis.com/token my_client_id my_secret auth_code_123 http://localhost:8080"
 */
public class Oauth2ConnectorRunner {

    public static void main(String[] args) {
        try {
            if (args.length < 4) {
                System.err.println("Usage: Oauth2ConnectorRunner <token_endpoint> <client_id> <client_secret> <auth_code> [redirect_uri]");
                System.err.println("");
                System.err.println("Arguments:");
                System.err.println("  token_endpoint : OAuth2 token endpoint URL");
                System.err.println("  client_id      : OAuth2 client ID");
                System.err.println("  client_secret  : OAuth2 client secret");
                System.err.println("  auth_code      : Authorization code obtained from OAuth2 provider");
                System.err.println("  redirect_uri   : (Optional) Redirect URI used in authorization request");
                System.exit(1);
            }

            String tokenEndpoint = args[0];
            String clientId = args[1];
            String clientSecret = args[2];
            String authCode = args[3];
            String redirectUri = args.length > 4 ? args[4] : null;

            System.out.println("=== OAuth2 Connector Runner ===");
            System.out.println("Token Endpoint: " + tokenEndpoint);
            System.out.println("Client ID: " + maskSensitiveData(clientId));
            System.out.println("Auth Code: " + maskSensitiveData(authCode));
            System.out.println("Redirect URI: " + (redirectUri != null ? redirectUri : "not provided"));
            System.out.println("");

            // Build connector parameters
            Map<String, Object> parameters = new HashMap<>();
            parameters.put(AUTH_TYPE_PARAMETER, AuthorizationType.OAUTH2_AUTHORIZATION_CODE.name());
            parameters.put(OAUTH2_TOKEN_ENDPOINT_INPUT_PARAMETER, tokenEndpoint);
            parameters.put(OAUTH2_CLIENT_ID_INPUT_PARAMETER, clientId);
            parameters.put(OAUTH2_CLIENT_SECRET_INPUT_PARAMETER, clientSecret);
            parameters.put(OAUTH2_CODE_INPUT_PARAMETER, authCode);

            if (redirectUri != null && !redirectUri.isEmpty()) {
                parameters.put(OAUTH2_REDIRECT_URI_INPUT_PARAMETER, redirectUri);
            }

            // Create and execute connector
            System.out.println("Executing OAuth2 connector...");
            Oauth2ConnectorImpl connector = new Oauth2ConnectorImpl();

            // Create mock Bonita context (required by connector framework)
            EngineExecutionContext engineContext = Mockito.mock(EngineExecutionContext.class);
            APIAccessor apiAccessor = Mockito.mock(APIAccessor.class);

            connector.setExecutionContext(engineContext);
            connector.setAPIAccessor(apiAccessor);
            connector.setInputParameters(parameters);

            // Validate and execute
            connector.validateInputParameters();
            Map<String, Object> outputs = connector.execute();

            // Display results
            String accessToken = (String) outputs.get(Oauth2ConnectorImpl.OAUTH2_TOKEN_OUTPUT_PARAMETER);

            if (accessToken != null && !accessToken.isEmpty()) {
                System.out.println("");
                System.out.println("=== SUCCESS ===");
                System.out.println("Access token retrieved successfully!");
                System.out.println("");
                System.out.println("Token: " + accessToken);
                System.out.println("");
                System.out.println("Token length: " + accessToken.length() + " characters");

                // Check if it's a JWT
                if (accessToken.split("\\.").length == 3) {
                    System.out.println("Token format: JWT (3 parts)");
                } else {
                    System.out.println("Token format: Opaque token");
                }

                System.exit(0);
            } else {
                System.err.println("ERROR: No access token received");
                System.exit(1);
            }

        } catch (Exception e) {
            System.err.println("");
            System.err.println("=== ERROR ===");
            System.err.println("Failed to exchange authorization code for token");
            System.err.println("");
            System.err.println("Error type: " + e.getClass().getSimpleName());
            System.err.println("Error message: " + e.getMessage());

            if (e.getCause() != null) {
                System.err.println("Cause: " + e.getCause().getMessage());
            }

            System.err.println("");
            System.err.println("Common issues:");
            System.err.println("  - Authorization code already used (codes are single-use)");
            System.err.println("  - Authorization code expired (typically 10 minutes)");
            System.err.println("  - Invalid client credentials");
            System.err.println("  - Redirect URI mismatch");

            e.printStackTrace();
            System.exit(1);
        }
    }

    private static String maskSensitiveData(String data) {
        if (data == null || data.length() <= 14) {
            return "***";
        }
        return data.substring(0, 10) + "..." + data.substring(data.length() - 4);
    }
}

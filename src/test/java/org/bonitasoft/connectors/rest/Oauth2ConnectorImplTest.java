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

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.bonitasoft.connectors.rest.AbstractRESTConnectorImpl.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.util.HashMap;
import java.util.Map;

import org.bonitasoft.connectors.rest.model.AuthorizationType;
import org.bonitasoft.connectors.rest.model.HTTPMethod;
import org.bonitasoft.engine.connector.ConnectorException;
import org.bonitasoft.engine.connector.ConnectorValidationException;
import org.bonitasoft.engine.exception.BonitaException;
import org.junit.Test;

/**
 * Tests for the OAuth2 Connector (Oauth2ConnectorImpl)
 * Includes validation tests and execution tests with a mocked OAuth2 server (WireMock)
 */
public class Oauth2ConnectorImplTest extends AcceptanceTestBase {

    private static final String TEST_ACCESS_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjo5OTk5OTk5OTk5fQ.test_signature";
    private static final String OAUTH2_TOKEN_ENDPOINT_PATH = "/oauth/token";

    // ========== Validation Tests ==========

    @Test
    public void testGetMethod() throws Exception {
        Oauth2ConnectorImpl connector = new Oauth2ConnectorImpl();
        assertEquals(HTTPMethod.POST.name(), connector.getMethod());
    }

    @Test
    public void should_validate_with_valid_oauth2_client_credentials_parameters() throws Exception {
        Oauth2ConnectorImpl connector = new Oauth2ConnectorImpl();
        Map<String, Object> parameters = buildValidOAuth2Parameters();
        connector.setInputParameters(parameters);

        // Should not throw exception
        connector.validateInputParameters();
    }

    @Test
    public void should_fail_validation_when_token_endpoint_is_missing() throws Exception {
        Oauth2ConnectorImpl connector = new Oauth2ConnectorImpl();
        Map<String, Object> parameters = buildValidOAuth2Parameters();
        parameters.remove(OAUTH2_TOKEN_ENDPOINT_INPUT_PARAMETER);
        connector.setInputParameters(parameters);

        assertThrows(ConnectorValidationException.class, () -> connector.validateInputParameters());
    }

    @Test
    public void should_fail_validation_when_token_endpoint_is_empty() throws Exception {
        Oauth2ConnectorImpl connector = new Oauth2ConnectorImpl();
        Map<String, Object> parameters = buildValidOAuth2Parameters();
        parameters.put(OAUTH2_TOKEN_ENDPOINT_INPUT_PARAMETER, "");
        connector.setInputParameters(parameters);

        assertThrows(ConnectorValidationException.class, () -> connector.validateInputParameters());
    }

    @Test
    public void should_fail_validation_when_client_id_is_missing() throws Exception {
        Oauth2ConnectorImpl connector = new Oauth2ConnectorImpl();
        Map<String, Object> parameters = buildValidOAuth2Parameters();
        parameters.remove(OAUTH2_CLIENT_ID_INPUT_PARAMETER);
        connector.setInputParameters(parameters);

        assertThrows(ConnectorValidationException.class, () -> connector.validateInputParameters());
    }

    @Test
    public void should_fail_validation_when_client_id_is_empty() throws Exception {
        Oauth2ConnectorImpl connector = new Oauth2ConnectorImpl();
        Map<String, Object> parameters = buildValidOAuth2Parameters();
        parameters.put(OAUTH2_CLIENT_ID_INPUT_PARAMETER, "");
        connector.setInputParameters(parameters);

        assertThrows(ConnectorValidationException.class, () -> connector.validateInputParameters());
    }

    @Test
    public void should_fail_validation_when_client_secret_is_missing() throws Exception {
        Oauth2ConnectorImpl connector = new Oauth2ConnectorImpl();
        Map<String, Object> parameters = buildValidOAuth2Parameters();
        parameters.remove(OAUTH2_CLIENT_SECRET_INPUT_PARAMETER);
        connector.setInputParameters(parameters);

        assertThrows(ConnectorValidationException.class, () -> connector.validateInputParameters());
    }

    @Test
    public void should_fail_validation_when_client_secret_is_empty() throws Exception {
        Oauth2ConnectorImpl connector = new Oauth2ConnectorImpl();
        Map<String, Object> parameters = buildValidOAuth2Parameters();
        parameters.put(OAUTH2_CLIENT_SECRET_INPUT_PARAMETER, "");
        connector.setInputParameters(parameters);

        assertThrows(ConnectorValidationException.class, () -> connector.validateInputParameters());
    }

    @Test
    public void should_fail_validation_when_auth_type_is_not_oauth2_client_credentials() throws Exception {
        Oauth2ConnectorImpl connector = new Oauth2ConnectorImpl();
        Map<String, Object> parameters = buildValidOAuth2Parameters();
        parameters.put(AUTH_TYPE_PARAMETER, AuthorizationType.BASIC.name());
        connector.setInputParameters(parameters);

        ConnectorValidationException exception = assertThrows(
            ConnectorValidationException.class,
            () -> connector.validateInputParameters()
        );
        assertEquals("OAuth2 connector requires auth_type to be OAUTH2_CLIENT_CREDENTIALS", exception.getMessage());
    }

    @Test
    public void should_validate_with_oauth2_scope() throws Exception {
        Oauth2ConnectorImpl connector = new Oauth2ConnectorImpl();
        Map<String, Object> parameters = buildValidOAuth2Parameters();
        parameters.put(OAUTH2_SCOPE_INPUT_PARAMETER, "read write");
        connector.setInputParameters(parameters);

        // Should not throw exception
        connector.validateInputParameters();
    }

    @Test
    public void should_validate_timeout_parameters() throws Exception {
        Oauth2ConnectorImpl connector = new Oauth2ConnectorImpl();
        Map<String, Object> parameters = buildValidOAuth2Parameters();
        parameters.put(SOCKET_TIMEOUT_MS_PARAMETER, 30000);
        parameters.put(CONNECTION_TIMEOUT_MS_PARAMETER, 15000);
        connector.setInputParameters(parameters);

        // Should not throw exception
        connector.validateInputParameters();
    }

    // ========== Execution Tests with WireMock ==========

    @Test
    public void should_retrieve_access_token_successfully() throws BonitaException {
        // Given: Mock OAuth2 token endpoint
        stubFor(post(urlEqualTo(OAUTH2_TOKEN_ENDPOINT_PATH))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(String.format(
                                "{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":3600}",
                                TEST_ACCESS_TOKEN))));

        // When: Execute OAuth2 connector
        String tokenEndpoint = String.format("http://localhost:%d%s", wireMockServer.port(), OAUTH2_TOKEN_ENDPOINT_PATH);
        Map<String, Object> parameters = buildOAuth2ParametersWithEndpoint(tokenEndpoint);
        Map<String, Object> outputs = executeOAuth2Connector(parameters);

        // Then: Verify token was retrieved and set in output
        assertThat(outputs).containsKey(Oauth2ConnectorImpl.OAUTH2_TOKEN_OUTPUT_PARAMETER);
        String retrievedToken = (String) outputs.get(Oauth2ConnectorImpl.OAUTH2_TOKEN_OUTPUT_PARAMETER);
        assertThat(retrievedToken).isEqualTo(TEST_ACCESS_TOKEN);
    }

    @Test
    public void should_retrieve_token_with_scope() throws BonitaException {
        // Given: Mock OAuth2 token endpoint
        stubFor(post(urlEqualTo(OAUTH2_TOKEN_ENDPOINT_PATH))
                .withRequestBody(containing("scope=read+write"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(String.format(
                                "{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"read write\"}",
                                TEST_ACCESS_TOKEN))));

        // When: Execute OAuth2 connector with scope
        String tokenEndpoint = String.format("http://localhost:%d%s", wireMockServer.port(), OAUTH2_TOKEN_ENDPOINT_PATH);
        Map<String, Object> parameters = buildOAuth2ParametersWithEndpoint(tokenEndpoint);
        parameters.put(OAUTH2_SCOPE_INPUT_PARAMETER, "read write");
        Map<String, Object> outputs = executeOAuth2Connector(parameters);

        // Then: Verify token was retrieved
        assertThat(outputs).containsKey(Oauth2ConnectorImpl.OAUTH2_TOKEN_OUTPUT_PARAMETER);
        String retrievedToken = (String) outputs.get(Oauth2ConnectorImpl.OAUTH2_TOKEN_OUTPUT_PARAMETER);
        assertThat(retrievedToken).isEqualTo(TEST_ACCESS_TOKEN);

        // Verify scope was included in request
        verify(1, postRequestedFor(urlEqualTo(OAUTH2_TOKEN_ENDPOINT_PATH))
                .withRequestBody(containing("scope=read+write")));
    }

    @Test(expected = ConnectorException.class)
    public void should_fail_when_token_endpoint_is_unreachable() throws BonitaException {
        // Given: Invalid token endpoint
        Map<String, Object> parameters = buildOAuth2ParametersWithEndpoint("http://invalid-host-that-does-not-exist:9999/oauth/token");

        // When/Then: Should throw ConnectorException
        executeOAuth2Connector(parameters);
    }

    @Test
    public void should_handle_token_response_with_additional_fields() throws BonitaException {
        // Given: Mock OAuth2 token endpoint with additional fields
        stubFor(post(urlEqualTo(OAUTH2_TOKEN_ENDPOINT_PATH))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(String.format(
                                "{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"refresh_token\":\"refresh_abc123\",\"scope\":\"read write\"}",
                                TEST_ACCESS_TOKEN))));

        // When: Execute OAuth2 connector
        String tokenEndpoint = String.format("http://localhost:%d%s", wireMockServer.port(), OAUTH2_TOKEN_ENDPOINT_PATH);
        Map<String, Object> parameters = buildOAuth2ParametersWithEndpoint(tokenEndpoint);
        Map<String, Object> outputs = executeOAuth2Connector(parameters);

        // Then: Verify access token was extracted correctly
        assertThat(outputs).containsKey(Oauth2ConnectorImpl.OAUTH2_TOKEN_OUTPUT_PARAMETER);
        String retrievedToken = (String) outputs.get(Oauth2ConnectorImpl.OAUTH2_TOKEN_OUTPUT_PARAMETER);
        assertThat(retrievedToken).isEqualTo(TEST_ACCESS_TOKEN);
    }

    // ========== Helper Methods ==========

    /**
     * Execute the OAuth2 connector with given parameters
     *
     * @param parameters The connector input parameters
     * @return The connector outputs
     * @throws BonitaException If connector execution fails
     */
    private Map<String, Object> executeOAuth2Connector(final Map<String, Object> parameters)
            throws BonitaException {
        final Oauth2ConnectorImpl connector = new Oauth2ConnectorImpl();
        connector.setExecutionContext(getEngineExecutionContext());
        connector.setAPIAccessor(getApiAccessor());
        connector.setInputParameters(parameters);
        connector.validateInputParameters();
        return connector.execute();
    }

    /**
     * Builds a valid set of OAuth2 Client Credentials parameters for validation testing
     */
    private Map<String, Object> buildValidOAuth2Parameters() {
        Map<String, Object> parameters = new HashMap<>();
        parameters.put(AUTH_TYPE_PARAMETER,
                      AuthorizationType.OAUTH2_CLIENT_CREDENTIALS.name());
        parameters.put(OAUTH2_TOKEN_ENDPOINT_INPUT_PARAMETER,
                      "https://auth.example.com/oauth/token");
        parameters.put(OAUTH2_CLIENT_ID_INPUT_PARAMETER,
                      "test_client_id");
        parameters.put(OAUTH2_CLIENT_SECRET_INPUT_PARAMETER,
                      "test_client_secret");
        return parameters;
    }

    /**
     * Build a valid set of OAuth2 parameters for execution testing with custom endpoint
     *
     * @param tokenEndpoint The OAuth2 token endpoint URL
     * @return Map of connector input parameters
     */
    private Map<String, Object> buildOAuth2ParametersWithEndpoint(String tokenEndpoint) {
        Map<String, Object> parameters = new HashMap<>();
        parameters.put(AUTH_TYPE_PARAMETER, AuthorizationType.OAUTH2_CLIENT_CREDENTIALS.name());
        parameters.put(OAUTH2_TOKEN_ENDPOINT_INPUT_PARAMETER, tokenEndpoint);
        parameters.put(OAUTH2_CLIENT_ID_INPUT_PARAMETER, "test_client_id");
        parameters.put(OAUTH2_CLIENT_SECRET_INPUT_PARAMETER, "test_client_secret");
        return parameters;
    }
}

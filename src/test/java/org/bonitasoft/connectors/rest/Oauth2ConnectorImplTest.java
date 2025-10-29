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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.bonitasoft.connectors.rest.AbstractRESTConnectorImpl.*;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.bonitasoft.connectors.rest.model.AuthorizationType;
import org.bonitasoft.connectors.rest.model.HTTPMethod;
import org.bonitasoft.engine.connector.ConnectorException;
import org.bonitasoft.engine.connector.ConnectorValidationException;
import org.bonitasoft.engine.exception.BonitaException;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests for the OAuth2 Connector (Oauth2ConnectorImpl)
 * Includes validation tests and execution tests with a mocked OAuth2 server (WireMock)
 */
public class Oauth2ConnectorImplTest extends AcceptanceTestBase {

    // Test data constants
    private static final String TEST_ACCESS_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjo5OTk5OTk5OTk5fQ.test_signature";
    private static final String OAUTH2_TOKEN_ENDPOINT_PATH = "/oauth/token";
    private static final String TEST_CLIENT_ID = "test_client_id";
    private static final String TEST_CLIENT_SECRET = "test_client_secret";

    // Concurrency test constants
    private static final int CONCURRENT_THREAD_COUNT_SMALL = 5;
    private static final int CONCURRENT_THREAD_COUNT_MEDIUM = 10;
    private static final int CACHE_EVICTION_TEST_TOKEN_COUNT = 250;
    private static final int CONCURRENT_TEST_TIMEOUT_SECONDS = 10;

    /**
     * Clear the OAuth2 token cache and locks before each test to ensure clean state
     */
    @Before
    public void clearTokenCache() {
        RESTConnector.OAUTH2_ACCESS_TOKENS.clear();
        RESTConnector.OAUTH2_TOKEN_ACQUISITION_LOCKS.clear();
    }

    // ========== Validation Tests ==========

    @Test
    public void should_return_POST_method_for_oauth2_connector() {
        Oauth2ConnectorImpl connector = new Oauth2ConnectorImpl();
        assertThat(connector.getMethod()).isEqualTo(HTTPMethod.POST.name());
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
    public void should_fail_validation_when_token_endpoint_is_missing() {
        assertValidationFailsWhenParameterMissing(OAUTH2_TOKEN_ENDPOINT_INPUT_PARAMETER);
    }

    @Test
    public void should_fail_validation_when_token_endpoint_is_empty() {
        assertValidationFailsWhenParameterEmpty(OAUTH2_TOKEN_ENDPOINT_INPUT_PARAMETER);
    }

    @Test
    public void should_fail_validation_when_client_id_is_missing() {
        assertValidationFailsWhenParameterMissing(OAUTH2_CLIENT_ID_INPUT_PARAMETER);
    }

    @Test
    public void should_fail_validation_when_client_id_is_empty() {
        assertValidationFailsWhenParameterEmpty(OAUTH2_CLIENT_ID_INPUT_PARAMETER);
    }

    @Test
    public void should_fail_validation_when_client_secret_is_missing() {
        assertValidationFailsWhenParameterMissing(OAUTH2_CLIENT_SECRET_INPUT_PARAMETER);
    }

    @Test
    public void should_fail_validation_when_client_secret_is_empty() throws Exception {
        Oauth2ConnectorImpl connector = new Oauth2ConnectorImpl();
        Map<String, Object> parameters = buildValidOAuth2Parameters();
        parameters.put(OAUTH2_CLIENT_SECRET_INPUT_PARAMETER, "");
        connector.setInputParameters(parameters);

        assertThatThrownBy(() -> connector.validateInputParameters())
                .isInstanceOf(ConnectorValidationException.class);
    }

    @Test
    public void should_fail_validation_when_auth_type_is_not_oauth2_client_credentials() throws Exception {
        Oauth2ConnectorImpl connector = new Oauth2ConnectorImpl();
        Map<String, Object> parameters = buildValidOAuth2Parameters();
        parameters.put(AUTH_TYPE_PARAMETER, AuthorizationType.BASIC.name());
        connector.setInputParameters(parameters);

        assertThatThrownBy(() -> connector.validateInputParameters())
                .isInstanceOf(ConnectorValidationException.class)
                .hasMessage("OAuth2 connector requires auth_type to be OAUTH2_CLIENT_CREDENTIALS or OAUTH2_AUTHORIZATION_CODE");
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
        stubSuccessfulTokenResponse(TEST_ACCESS_TOKEN);

        // When: Execute OAuth2 connector
        Map<String, Object> parameters = buildOAuth2ParametersWithEndpoint(getTokenEndpointUrl());
        Map<String, Object> outputs = executeOAuth2Connector(parameters);

        // Then: Verify token was retrieved and set in output
        assertTokenRetrievedSuccessfully(outputs, TEST_ACCESS_TOKEN);
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

    // ========== OAuth2 Authorization Code Flow Tests ==========

    @Test
    public void should_validate_with_valid_oauth2_authorization_code_parameters() throws Exception {
        Oauth2ConnectorImpl connector = new Oauth2ConnectorImpl();
        Map<String, Object> parameters = buildValidAuthorizationCodeParameters();
        connector.setInputParameters(parameters);

        // Should not throw exception
        connector.validateInputParameters();
    }

    @Test
    public void should_fail_validation_when_authorization_code_is_missing() throws Exception {
        Oauth2ConnectorImpl connector = new Oauth2ConnectorImpl();
        Map<String, Object> parameters = buildValidAuthorizationCodeParameters();
        parameters.remove(OAUTH2_CODE_INPUT_PARAMETER);
        connector.setInputParameters(parameters);

        assertThatThrownBy(() -> connector.validateInputParameters())
                .isInstanceOf(ConnectorValidationException.class);
    }

    @Test
    public void should_fail_validation_when_authorization_code_is_empty() throws Exception {
        Oauth2ConnectorImpl connector = new Oauth2ConnectorImpl();
        Map<String, Object> parameters = buildValidAuthorizationCodeParameters();
        parameters.put(OAUTH2_CODE_INPUT_PARAMETER, "");
        connector.setInputParameters(parameters);

        assertThatThrownBy(() -> connector.validateInputParameters())
                .isInstanceOf(ConnectorValidationException.class);
    }

    @Test
    public void should_validate_authorization_code_without_code_verifier() throws Exception {
        Oauth2ConnectorImpl connector = new Oauth2ConnectorImpl();
        Map<String, Object> parameters = buildValidAuthorizationCodeParameters();
        parameters.remove(OAUTH2_CODE_VERIFIER_INPUT_PARAMETER);
        connector.setInputParameters(parameters);

        // Should not throw exception - code_verifier is optional
        connector.validateInputParameters();
    }

    @Test
    public void should_validate_authorization_code_without_redirect_uri() throws Exception {
        Oauth2ConnectorImpl connector = new Oauth2ConnectorImpl();
        Map<String, Object> parameters = buildValidAuthorizationCodeParameters();
        parameters.remove(OAUTH2_REDIRECT_URI_INPUT_PARAMETER);
        connector.setInputParameters(parameters);

        // Should not throw exception - redirect_uri is optional
        connector.validateInputParameters();
    }

    @Test
    public void should_retrieve_token_with_authorization_code_and_pkce() throws BonitaException {
        // Given: Mock OAuth2 token endpoint for authorization code exchange
        stubFor(post(urlEqualTo(OAUTH2_TOKEN_ENDPOINT_PATH))
                .withRequestBody(containing("grant_type=authorization_code"))
                .withRequestBody(containing("code=test_auth_code"))
                .withRequestBody(containing("code_verifier=test_code_verifier"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(String.format(
                                "{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":3600}",
                                TEST_ACCESS_TOKEN))));

        // When: Execute OAuth2 connector with Authorization Code
        String tokenEndpoint = String.format("http://localhost:%d%s", wireMockServer.port(), OAUTH2_TOKEN_ENDPOINT_PATH);
        Map<String, Object> parameters = buildAuthorizationCodeParametersWithEndpoint(tokenEndpoint);
        Map<String, Object> outputs = executeOAuth2Connector(parameters);

        // Then: Verify token was retrieved
        assertThat(outputs).containsKey(Oauth2ConnectorImpl.OAUTH2_TOKEN_OUTPUT_PARAMETER);
        String retrievedToken = (String) outputs.get(Oauth2ConnectorImpl.OAUTH2_TOKEN_OUTPUT_PARAMETER);
        assertThat(retrievedToken).isEqualTo(TEST_ACCESS_TOKEN);

        // Verify code_verifier was included in request
        verify(1, postRequestedFor(urlEqualTo(OAUTH2_TOKEN_ENDPOINT_PATH))
                .withRequestBody(containing("code_verifier=test_code_verifier")));
    }

    @Test
    public void should_retrieve_token_with_authorization_code_without_pkce() throws BonitaException {
        // Given: Mock OAuth2 token endpoint for authorization code exchange without PKCE
        stubFor(post(urlEqualTo(OAUTH2_TOKEN_ENDPOINT_PATH))
                .withRequestBody(containing("grant_type=authorization_code"))
                .withRequestBody(containing("code=test_auth_code"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(String.format(
                                "{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":3600}",
                                TEST_ACCESS_TOKEN))));

        // When: Execute OAuth2 connector without code_verifier
        String tokenEndpoint = String.format("http://localhost:%d%s", wireMockServer.port(), OAUTH2_TOKEN_ENDPOINT_PATH);
        Map<String, Object> parameters = buildAuthorizationCodeParametersWithEndpoint(tokenEndpoint);
        parameters.remove(OAUTH2_CODE_VERIFIER_INPUT_PARAMETER);
        Map<String, Object> outputs = executeOAuth2Connector(parameters);

        // Then: Verify token was retrieved
        assertThat(outputs).containsKey(Oauth2ConnectorImpl.OAUTH2_TOKEN_OUTPUT_PARAMETER);
        String retrievedToken = (String) outputs.get(Oauth2ConnectorImpl.OAUTH2_TOKEN_OUTPUT_PARAMETER);
        assertThat(retrievedToken).isEqualTo(TEST_ACCESS_TOKEN);

        // Verify code_verifier was NOT included in request
        verify(1, postRequestedFor(urlEqualTo(OAUTH2_TOKEN_ENDPOINT_PATH))
                .withRequestBody(notMatching(".*code_verifier.*")));
    }

    @Test
    public void should_retrieve_token_with_authorization_code_and_redirect_uri() throws BonitaException {
        // Given: Mock OAuth2 token endpoint requiring redirect_uri
        stubFor(post(urlEqualTo(OAUTH2_TOKEN_ENDPOINT_PATH))
                .withRequestBody(containing("grant_type=authorization_code"))
                .withRequestBody(containing("code=test_auth_code"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(String.format(
                                "{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":3600}",
                                TEST_ACCESS_TOKEN))));

        // When: Execute OAuth2 connector with redirect_uri
        String tokenEndpoint = String.format("http://localhost:%d%s", wireMockServer.port(), OAUTH2_TOKEN_ENDPOINT_PATH);
        Map<String, Object> parameters = buildAuthorizationCodeParametersWithEndpoint(tokenEndpoint);
        parameters.put(OAUTH2_REDIRECT_URI_INPUT_PARAMETER, "https://app.example.com/callback");
        Map<String, Object> outputs = executeOAuth2Connector(parameters);

        // Then: Verify token was retrieved
        assertThat(outputs).containsKey(Oauth2ConnectorImpl.OAUTH2_TOKEN_OUTPUT_PARAMETER);

        // Verify redirect_uri was included in request
        verify(1, postRequestedFor(urlEqualTo(OAUTH2_TOKEN_ENDPOINT_PATH))
                .withRequestBody(containing("redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback")));
    }

    // ========== Helper Methods - WireMock Stubs ==========

    /**
     * Stub a successful OAuth2 token response with custom token
     */
    private void stubSuccessfulTokenResponse(String accessToken) {
        stubFor(post(urlEqualTo(OAUTH2_TOKEN_ENDPOINT_PATH))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(buildTokenResponseJson(accessToken))));
    }

    /**
     * Build OAuth2 token response JSON
     */
    private String buildTokenResponseJson(String accessToken) {
        return String.format(
                "{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":3600}",
                accessToken);
    }

    /**
     * Get the full OAuth2 token endpoint URL for the WireMock server
     */
    private String getTokenEndpointUrl() {
        return String.format("http://localhost:%d%s", wireMockServer.port(), OAUTH2_TOKEN_ENDPOINT_PATH);
    }

    // ========== Helper Methods - Validation ==========

    /**
     * Assert that validation fails when a required parameter is missing
     */
    private void assertValidationFailsWhenParameterMissing(String parameterName) {
        Oauth2ConnectorImpl connector = new Oauth2ConnectorImpl();
        Map<String, Object> parameters = buildValidOAuth2Parameters();
        parameters.remove(parameterName);
        connector.setInputParameters(parameters);

        assertThatThrownBy(() -> connector.validateInputParameters())
                .isInstanceOf(ConnectorValidationException.class);
    }

    /**
     * Assert that validation fails when a required parameter is empty
     */
    private void assertValidationFailsWhenParameterEmpty(String parameterName) {
        Oauth2ConnectorImpl connector = new Oauth2ConnectorImpl();
        Map<String, Object> parameters = buildValidOAuth2Parameters();
        parameters.put(parameterName, "");
        connector.setInputParameters(parameters);

        assertThatThrownBy(() -> connector.validateInputParameters())
                .isInstanceOf(ConnectorValidationException.class);
    }

    // ========== Helper Methods - Assertions ==========

    /**
     * Assert that the token was retrieved successfully and matches expected value
     */
    private void assertTokenRetrievedSuccessfully(Map<String, Object> outputs, String expectedToken) {
        assertThat(outputs)
                .containsKey(Oauth2ConnectorImpl.OAUTH2_TOKEN_OUTPUT_PARAMETER);
        assertThat(outputs.get(Oauth2ConnectorImpl.OAUTH2_TOKEN_OUTPUT_PARAMETER))
                .isEqualTo(expectedToken);
    }

    // ========== Helper Methods - Concurrency Testing ==========

    /**
     * Functional interface for concurrent test actions
     */
    @FunctionalInterface
    private interface ConcurrentTestAction {
        Map<String, Object> execute(int threadId) throws Exception;
    }

    /**
     * Result holder for concurrent test execution
     */
    private static class ConcurrentTestResult {
        final Map<Integer, String> tokens;
        final Map<Integer, Exception> errors;
        final boolean completed;

        ConcurrentTestResult(Map<Integer, String> tokens,
                           Map<Integer, Exception> errors,
                           boolean completed) {
            this.tokens = tokens;
            this.errors = errors;
            this.completed = completed;
        }
    }

    /**
     * Execute a test action concurrently across multiple threads with proper coordination
     */
    private ConcurrentTestResult executeConcurrentTest(int threadCount, ConcurrentTestAction action)
            throws InterruptedException {

        final CountDownLatch startLatch = new CountDownLatch(1);
        final CountDownLatch doneLatch = new CountDownLatch(threadCount);
        final ConcurrentHashMap<Integer, String> tokens = new ConcurrentHashMap<>();
        final ConcurrentHashMap<Integer, Exception> errors = new ConcurrentHashMap<>();

        for (int i = 0; i < threadCount; i++) {
            final int threadId = i;
            Thread thread = new Thread(() -> {
                try {
                    startLatch.await();
                    Map<String, Object> outputs = action.execute(threadId);
                    String token = (String) outputs.get(Oauth2ConnectorImpl.OAUTH2_TOKEN_OUTPUT_PARAMETER);
                    tokens.put(threadId, token);
                } catch (Exception e) {
                    errors.put(threadId, e);
                } finally {
                    doneLatch.countDown();
                }
            });
            thread.setName("OAuth2-Test-Thread-" + threadId);
            thread.start();
        }

        startLatch.countDown();
        boolean completed = doneLatch.await(CONCURRENT_TEST_TIMEOUT_SECONDS, TimeUnit.SECONDS);

        return new ConcurrentTestResult(tokens, errors, completed);
    }

    /**
     * Assert that all tokens in the map are identical
     */
    private void assertAllTokensAreIdentical(Map<Integer, String> tokens) {
        assertThat(tokens).isNotEmpty();
        String firstToken = tokens.values().iterator().next();
        tokens.values().forEach(token -> assertThat(token).isEqualTo(firstToken));
    }

    // ========== Helper Methods - Parameter Builders ==========

    /**
     * Builds a valid set of OAuth2 Authorization Code parameters for validation testing
     */
    private Map<String, Object> buildValidAuthorizationCodeParameters() {
        Map<String, Object> parameters = new HashMap<>();
        parameters.put(AUTH_TYPE_PARAMETER, AuthorizationType.OAUTH2_AUTHORIZATION_CODE.name());
        parameters.put(OAUTH2_TOKEN_ENDPOINT_INPUT_PARAMETER, "https://auth.example.com/oauth/token");
        parameters.put(OAUTH2_CLIENT_ID_INPUT_PARAMETER, "test_client_id");
        parameters.put(OAUTH2_CLIENT_SECRET_INPUT_PARAMETER, "test_client_secret");
        parameters.put(OAUTH2_CODE_INPUT_PARAMETER, "test_auth_code");
        parameters.put(OAUTH2_CODE_VERIFIER_INPUT_PARAMETER, "test_code_verifier");
        return parameters;
    }

    /**
     * Build OAuth2 Authorization Code parameters for execution testing with custom endpoint
     *
     * @param tokenEndpoint The OAuth2 token endpoint URL
     * @return Map of connector input parameters
     */
    private Map<String, Object> buildAuthorizationCodeParametersWithEndpoint(String tokenEndpoint) {
        Map<String, Object> parameters = new HashMap<>();
        parameters.put(AUTH_TYPE_PARAMETER, AuthorizationType.OAUTH2_AUTHORIZATION_CODE.name());
        parameters.put(OAUTH2_TOKEN_ENDPOINT_INPUT_PARAMETER, tokenEndpoint);
        parameters.put(OAUTH2_CLIENT_ID_INPUT_PARAMETER, "test_client_id");
        parameters.put(OAUTH2_CLIENT_SECRET_INPUT_PARAMETER, "test_client_secret");
        parameters.put(OAUTH2_CODE_INPUT_PARAMETER, "test_auth_code");
        parameters.put(OAUTH2_CODE_VERIFIER_INPUT_PARAMETER, "test_code_verifier");
        return parameters;
    }

    // ========== Concurrency Tests ==========

    @Test
    public void should_handle_concurrent_token_acquisition_with_same_credentials() throws Exception {
        // Given: Mock OAuth2 token endpoint
        stubSuccessfulTokenResponse(TEST_ACCESS_TOKEN);
        String tokenEndpoint = getTokenEndpointUrl();

        // When: 10 threads simultaneously request token with same credentials
        ConcurrentTestResult result = executeConcurrentTest(CONCURRENT_THREAD_COUNT_MEDIUM, threadId -> {
            Map<String, Object> parameters = buildOAuth2ParametersWithEndpoint(tokenEndpoint);
            return executeOAuth2Connector(parameters);
        });

        // Then: All threads should succeed
        assertThat(result.completed)
                .withFailMessage("Concurrent test did not complete within timeout")
                .isTrue();
        assertThat(result.errors).isEmpty();
        assertThat(result.tokens).hasSize(CONCURRENT_THREAD_COUNT_MEDIUM);

        // All threads should get the same token (cached)
        assertAllTokensAreIdentical(result.tokens);

        // Verify token endpoint was called only once (cache worked)
        verify(1, postRequestedFor(urlEqualTo(OAUTH2_TOKEN_ENDPOINT_PATH)));
    }

    @Test
    public void should_handle_concurrent_token_acquisition_with_different_credentials() throws Exception {
        // Given: Mock OAuth2 token endpoint
        stubSuccessfulTokenResponse(TEST_ACCESS_TOKEN);
        String tokenEndpoint = getTokenEndpointUrl();

        // When: 5 threads request tokens with different client IDs
        ConcurrentTestResult result = executeConcurrentTest(CONCURRENT_THREAD_COUNT_SMALL, threadId -> {
            Map<String, Object> parameters = buildOAuth2ParametersWithEndpoint(tokenEndpoint);
            parameters.put(OAUTH2_CLIENT_ID_INPUT_PARAMETER, "client_" + threadId);
            return executeOAuth2Connector(parameters);
        });

        // Then: All threads should succeed
        assertThat(result.completed)
                .withFailMessage("Concurrent test did not complete within timeout")
                .isTrue();
        assertThat(result.errors).isEmpty();
        assertThat(result.tokens).hasSize(CONCURRENT_THREAD_COUNT_SMALL);

        // Verify token endpoint was called once per unique client
        verify(CONCURRENT_THREAD_COUNT_SMALL, postRequestedFor(urlEqualTo(OAUTH2_TOKEN_ENDPOINT_PATH)));
    }

    @Test
    public void should_verify_lru_cache_eviction_limit() throws Exception {
        // Given: Mock OAuth2 token endpoint
        stubSuccessfulTokenResponse(TEST_ACCESS_TOKEN);
        String tokenEndpoint = getTokenEndpointUrl();

        // When: Acquire 250 tokens with different credentials (exceeds cache limit of 100)
        for (int i = 0; i < CACHE_EVICTION_TEST_TOKEN_COUNT; i++) {
            Map<String, Object> parameters = buildOAuth2ParametersWithEndpoint(tokenEndpoint);
            parameters.put(OAUTH2_CLIENT_ID_INPUT_PARAMETER, "client_" + i);
            parameters.put(OAUTH2_CLIENT_SECRET_INPUT_PARAMETER, "secret_" + i);
            executeOAuth2Connector(parameters);
        }

        // Then: Cache should not exceed maximum size (LRU eviction works)
        int cacheSize = RESTConnector.OAUTH2_ACCESS_TOKENS.size();
        assertThat(cacheSize).isLessThanOrEqualTo(RESTConnector.MAX_CACHED_TOKENS);

        // Locks map uses bounded growth strategy with cleanup
        // When lock count exceeds MAX_CACHED_LOCKS (200), cleanup removes orphaned locks
        // Expected behavior: lock count stays reasonably bounded (approximately equal to cache size after cleanup)
        int locksSize = RESTConnector.OAUTH2_TOKEN_ACQUISITION_LOCKS.size();
        assertThat(locksSize)
                .withFailMessage("Lock map should be bounded by cleanup (expected ~100-200, got %d)", locksSize)
                .isLessThan(CACHE_EVICTION_TEST_TOKEN_COUNT) // Should be less than 250 (cleanup triggered)
                .isGreaterThanOrEqualTo(RESTConnector.MAX_CACHED_TOKENS); // Should be at least cache size

        // Verify all token acquisitions succeeded (250 requests)
        verify(CACHE_EVICTION_TEST_TOKEN_COUNT, postRequestedFor(urlEqualTo(OAUTH2_TOKEN_ENDPOINT_PATH)));
    }

    @Test
    public void should_handle_concurrent_authorization_code_exchanges() throws Exception {
        // Given
        stubSuccessfulTokenResponse(TEST_ACCESS_TOKEN);
        String tokenEndpoint = getTokenEndpointUrl();

        // When
        ConcurrentTestResult result = executeConcurrentTest(CONCURRENT_THREAD_COUNT_SMALL, threadId -> {
            Map<String, Object> parameters = buildAuthorizationCodeParametersWithEndpoint(tokenEndpoint);
            parameters.put(OAUTH2_CODE_INPUT_PARAMETER, "auth_code_" + threadId);
            return executeOAuth2Connector(parameters);
        });

        // Then
        assertThat(result.completed).withFailMessage("Concurrent test did not complete within timeout").isTrue();
        assertThat(result.errors).isEmpty();
        assertThat(result.tokens).hasSize(CONCURRENT_THREAD_COUNT_SMALL);

        // Authorization codes are never cached, so each should make a separate request
        verify(CONCURRENT_THREAD_COUNT_SMALL, postRequestedFor(urlEqualTo(OAUTH2_TOKEN_ENDPOINT_PATH)));
    }
}

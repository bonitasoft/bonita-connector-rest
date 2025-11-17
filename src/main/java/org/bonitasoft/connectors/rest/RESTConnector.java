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
package org.bonitasoft.connectors.rest;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.*;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.ChallengeState;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.AuthCache;
import org.apache.http.client.CookieStore;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.config.RequestConfig.Builder;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.auth.AuthSchemeBase;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.auth.DigestScheme;
import org.apache.http.impl.client.*;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.apache.http.protocol.HttpContext;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;
import org.bonitasoft.connectors.rest.model.*;
import org.bonitasoft.connectors.rest.utils.HttpStatusFailureException;
import org.bonitasoft.engine.api.ProcessAPI;
import org.bonitasoft.engine.bpm.document.Document;
import org.bonitasoft.engine.bpm.document.DocumentNotFoundException;
import org.bonitasoft.engine.commons.exceptions.SRetryableException;
import org.bonitasoft.engine.connector.ConnectorException;
import org.bonitasoft.engine.connector.ConnectorValidationException;

import javax.net.ssl.HostnameVerifier;
import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.io.UncheckedIOException;
import java.net.HttpCookie;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;

/** This main class of the REST Connector implementation */
public class RESTConnector extends AbstractRESTConnectorImpl {

    /** The HTTP request builder constants. */
    private static final String HTTP_PROTOCOL = "HTTP";

    private static final int HTTP_PROTOCOL_VERSION_MAJOR = 1;
    private static final int HTTP_PROTOCOL_VERSION_MINOR = 1;

    private static final List<String> SECRET_HEADER_NAMES = List.of("authorization", "token", "set-cookie");

    /** The class logger */
    private static final Logger LOGGER = Logger.getLogger(RESTConnector.class.getName());

    /**
     * Forces the character encoding of the HTTP response body to the default JVM Charset if no
     * Charset is defined in the response header. If this property is not set, the ISO-8859-1 Charset
     * is used as fallback, as specified in the specification.
     */
    static final String DEFAULT_JVM_CHARSET_FALLBACK_PROPERTY = "org.bonitasoft.connectors.rest.response.fallbackToJVMCharset";

    /**
     * Maximum number of cached OAuth2 tokens. When this limit is exceeded,
     * the least recently used (LRU) entries are automatically removed.
     */
    protected static final int MAX_CACHED_TOKENS = 100;

    /**
     * OAuth2 access token cache (key: tokenEndpoint#clientId#scope, value: TokenWithExpiration) for Client Credentials flow.
     * Uses synchronized LinkedHashMap with access-order LRU eviction to prevent unbounded growth.
     * The 'true' parameter enables access-order mode, making this an LRU cache.
     *
     * Note: When cache entries are evicted, we intentionally do NOT remove corresponding locks
     * from {@link #OAUTH2_TOKEN_ACQUISITION_LOCKS} to avoid race conditions. See that field's JavaDoc for details.
     *
     * Package-private for testing
     */
    static final Map<String, TokenWithExpiration> OAUTH2_ACCESS_TOKENS =
        Collections.synchronizedMap(new LinkedHashMap<String, TokenWithExpiration>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, TokenWithExpiration> eldest) {
                // Evict eldest entry when cache exceeds max size
                // Note: We intentionally do NOT remove locks here to avoid race conditions
                return size() > MAX_CACHED_TOKENS;
            }
        });

    /**
     * Maximum number of locks to keep in the lock map before triggering cleanup.
     *
     * When this limit is exceeded, we perform a cleanup that removes locks for
     * cache keys that no longer exist in the token cache. This prevents unbounded
     * growth while avoiding the race condition.
     */
    private static final int MAX_CACHED_LOCKS = MAX_CACHED_TOKENS * 2; // 200 locks

    /**
     * Per-cache-key locks to prevent concurrent token acquisitions for the same credentials.
     * This allows parallel acquisitions for different credentials while preventing race conditions.
     *
     * Bounded Growth Strategy:
     * - Locks are created on-demand via computeIfAbsent
     * - When map size exceeds {@link #MAX_CACHED_LOCKS}, cleanup is triggered
     * - Cleanup removes locks for keys NOT in the token cache (safe because no ongoing acquisition)
     * - This prevents unbounded growth while avoiding the race condition
     *
     * Why This Approach is Safe:
     *
     * - We only remove locks for keys that are NOT in the token cache
     * - If a key is not in cache, no thread should be waiting on its lock
     * - Worst case: Lock is removed between cache check and computeIfAbsent → new lock created
     * - This is harmless - just means we might create a new lock unnecessarily
     *
     * Memory Overhead: Bounded to ~200 locks = ~3-6 KB max
     */
    static final Map<String, Object> OAUTH2_TOKEN_ACQUISITION_LOCKS = new ConcurrentHashMap<>();

    /**
     * Clock skew for anticipating token expiration (60 seconds before actual expiration)
     */
    private static final long OAUTH2_TOKEN_EXPIRATION_CLOCK_SKEW_SECONDS = 60;

    /**
     * Default token expiration time in seconds if not provided by the OAuth2 provider
     */
    public static final int DEFAULT_TOKEN_EXPIRES_IN = 3600;

    /**
     * Shared ObjectMapper instance for JSON parsing (thread-safe).
     * Used for both OAuth2 token responses and REST API response parsing.
     */
    private static final ObjectMapper JSON_MAPPER = new ObjectMapper();

    /**
     * Used for saving OAuth2 access tokens obtained from Authorization Code flow
     * In case of retryable exception during connector execution, if token was already acquired it can be reused
     * This is especially useful since authorization codes are single-use only
     */
    private String userTokenSavedForRetry;

    /**
     * Whether a the given HTTP method has a body payload
     */
    private final boolean hasBody;

    protected RESTConnector(boolean hasBody) {
        this.hasBody = hasBody;
    }

    @Override
    public void validateInputParameters() throws ConnectorValidationException {
        super.validateInputParameters();

        LOGGER.fine("super validateInputParameters done.");

        final List<String> messages = new ArrayList<>(0);
        if (!isStringInputValid(getUrl())) {
            messages.add(URL_INPUT_PARAMETER);
        } else {
            try {
                new URL(getUrl());
            } catch (final MalformedURLException e) {
                messages.add(URL_INPUT_PARAMETER);
            }
        }

        if (!isStringInputValid(getMethod())) {
            messages.add(METHOD_INPUT_PARAMETER);
        }

        if (Objects.equals(getMethod(), HTTPMethod.POST.name())
                || Objects.equals(getMethod(), HTTPMethod.PUT.name())
                || Objects.equals(getMethod(), HTTPMethod.PATCH.name())) {
            if (!isStringInputValid(getContentType())) {
                messages.add(CONTENTTYPE_INPUT_PARAMETER);
            }
            if (!isStringInputValid(getCharset())) {
                messages.add(CHARSET_INPUT_PARAMETER);
            }
            String body = getBody();
            String documentBody = getDocumentBody();
            if (body != null && !body.trim().isEmpty() && documentBody != null && !documentBody.trim().isEmpty()) {
                messages.add("Either body input or documentBody input should be set. Found both.");
            }
        }

        final List<?> urlCookies = getUrlCookies();
        messages.addAll(manageKeyValueCouples(urlCookies, URLCOOKIES_INPUT_PARAMETER));

        final List<?> urlheaders = getUrlHeaders();
        messages.addAll(manageKeyValueCouples(urlheaders, URLHEADERS_INPUT_PARAMETER));

        if (!messages.isEmpty()) {
            LOGGER.fine(() -> String.format("validateInputParameters error: %s", messages.toString()));
            throw new ConnectorValidationException(this, messages);
        }
    }

    /**
     * Is the String input valid?
     *
     * @param value The value to be checked
     * @return If the String input is valid or not
     */
    private boolean isStringInputValid(final String value) {
        return value != null && !value.isEmpty();
    }

    /**
     * Validate the key value couples
     *
     * @param keyValueCouples The key value couples from the input
     * @param inputName The input name where the key value couples are from
     * @return The error messages if any or empty list otherwise
     */
    private List<String> manageKeyValueCouples(
            final List<?> keyValueCouples, final String inputName) {
        final List<String> messages = new ArrayList<>();
        if (keyValueCouples == null) {
            return messages;
        }
        for (final Object keyValueCouple : keyValueCouples) {
            if (keyValueCouple instanceof List) {
                final List<?> keyValueCoupleRow = (List<?>) keyValueCouple;
                if (!isItAKeyValueCouple(keyValueCoupleRow)) {
                    messages.add(inputName + " - columns - " + keyValueCoupleRow.size());
                } else if (!isKeyValueCoupleValid(keyValueCoupleRow)) {
                    messages.add(inputName + " - value");
                }
            } else {
                messages.add(inputName + " - type");
            }
        }
        return messages;
    }

    /**
     * Is the key and the value valid?
     *
     * @param keyValueCoupleRow The key value couple row
     * @return If the key and the value is valid or not
     */
    private boolean isKeyValueCoupleValid(final List<?> keyValueCoupleRow) {
        return keyValueCoupleRow.get(0) != null
                && !keyValueCoupleRow.get(0).toString().isEmpty()
                && keyValueCoupleRow.get(1) != null;
    }

    /**
     * Is the row a key value couple?
     *
     * @param keyValueCoupleRow the list of elements stating the row
     * @return If the row is a key value couple or not
     */
    private boolean isItAKeyValueCouple(final List<?> keyValueCoupleRow) {
        return keyValueCoupleRow.size() == 2;
    }

    @Override
    protected void executeBusinessLogic() throws ConnectorException {
        try {
            final Request request = buildRequest();
            execute(request);
        } catch (final SRetryableException e) {
            throw e;
        } catch (final Exception e) {
            logException(e);
            throw new ConnectorException(e);
        }
    }

    /**
     * Build the request bean from all the inputs
     *
     * @return The request bean
     * @throws MalformedURLException
     */
    protected Request buildRequest() throws MalformedURLException, ConnectorException {
        final Request request = new Request();
        request.setUrl(new URL(getUrl()));
        LOGGER.fine(() -> "URL set to: " + request.getUrl().toString());
        request.setRestMethod(HTTPMethod.getRESTHTTPMethodFromValue(getMethod()));
        LOGGER.fine(() -> "Method set to: " + request.getRestMethod().toString());
        if (request.getRestMethod() == HTTPMethod.POST || request.getRestMethod() == HTTPMethod.PUT || request.getRestMethod() == HTTPMethod.PATCH) {
            ContentType contentType = ContentType.create(getContentType(), Charset.forName(getCharset()));
            request.setContentType(contentType);
            LOGGER.fine(() -> "Content-Type set to: " + contentType.toString());
        }

        setBody(request);

        request.setRedirect(!getDoNotFollowRedirect());
        LOGGER.fine(() -> "Follow redirect set to: " + request.isRedirect());
        request.setIgnore(getIgnoreBody());
        LOGGER.fine(() -> "Ignore body set to: " + request.isIgnore());
        for (final List<?> urlheaderRow : getUrlHeaders()) {
            String name = urlheaderRow.get(0).toString();
            String value = urlheaderRow.get(1).toString();
            request.addHeader(name, value);
            LOGGER.fine(() -> "Add header: "
                    + urlheaderRow.get(0).toString()
                    + " set as "
                    + urlheaderRow.get(1).toString());
        }
        if (getAddBonitaContextHeaders()) {
            LOGGER.fine("Adding Bonita context headers.");
            addBonitaContextHeader(request, getBonitaActivityInstanceIdHeader(), Long.toString(getExecutionContext().getActivityInstanceId()));
            addBonitaContextHeader(request, getBonitaProcessInstanceIdHeader(), Long.toString(getExecutionContext().getProcessInstanceId()));
            addBonitaContextHeader(request, getBonitaRootProcessInstanceIdHeader(), Long.toString(getExecutionContext().getRootProcessInstanceId()));
            addBonitaContextHeader(request, getBonitaProcessDefinitionIdHeader(), Long.toString(getExecutionContext().getProcessDefinitionId()));
            addBonitaContextHeader(request, getBonitaTaskAssigneeIdHeader(), Long.toString(getExecutionContext().getTaskAssigneeId()));
            LOGGER.fine("Context headers added.");
        }
        for (final List<?> urlCookieRow : getUrlCookies()) {
            request.addCookie(urlCookieRow.get(0).toString(), urlCookieRow.get(1).toString());
            LOGGER.fine(() -> "Add cookie: "
                    + urlCookieRow.get(0).toString()
                    + " with content "
                    + urlCookieRow.get(1).toString());
        }

        request.setSsl(buildSSL());
        LOGGER.fine("Add the SSL options");

        if (isProxySet()) {
            request.setProxy(buildProxy());
            LOGGER.fine("Add the Proxy options");
        }

        if (getAuthType() == AuthorizationType.BASIC) {
            LOGGER.fine("Add basic auth");
            request.setAuthorization(buildBasicAuthorization());
        } else if (getAuthType() == AuthorizationType.DIGEST) {
            LOGGER.fine("Add digest auth");
            request.setAuthorization(buildDigestAuthorization());
        } else if (getAuthType() == AuthorizationType.OAUTH2_CLIENT_CREDENTIALS) {
            LOGGER.fine("Add OAuth2 Client Credentials auth");
            request.setAuthorization(buildOAuth2ClientCredentialsAuthorization());
        } else if (getAuthType() == AuthorizationType.OAUTH2_BEARER) {
            LOGGER.fine("Add OAuth2 Bearer auth");
            request.setAuthorization(buildOAuth2BearerAuthorization());
        } else if (getAuthType() == AuthorizationType.OAUTH2_AUTHORIZATION_CODE) {
            LOGGER.fine("Add OAuth2 Authorization Code auth");
            request.setAuthorization(buildOAuth2AuthorizationCodeAuthorization());
        }
        return request;
    }

    private void addBonitaContextHeader(Request request, String headerName, String headerValue) {
        if (StringUtils.isNotBlank(headerName) && StringUtils.isNotBlank(headerValue)) {
            LOGGER.fine(() -> "Adding header: " + headerName + " with value " + headerValue);
            request.setHeader(headerName, headerValue);
        }
    }

    private void setBody(Request request) throws ConnectorException {
        String body = getBody();
        String documentBody = getDocumentBody();
        request.setHasBody(hasBody());
        if (StringUtils.isNotBlank(body)) {
            request.setBody(body);
            LOGGER.fine(() -> "Body set to: " + abbreviateBody(request.getBody().toString()));
        } else if (documentBody != null && !documentBody.trim().isEmpty()) {
            try {
                ProcessAPI processAPI = getAPIAccessor().getProcessAPI();
                Document doc = processAPI
                        .getLastDocument(getExecutionContext().getProcessInstanceId(), documentBody);
                request.setBody(processAPI.getDocumentContent(doc.getContentStorageId()));
                LOGGER.fine(() -> String.format("Body set with %s document content", documentBody));
            } catch (DocumentNotFoundException e) {
                throw new ConnectorException(String.format("Document '%s' not found", documentBody), e);
            }
        } else {
            request.setBody("");
        }
    }

    /**
     * Is a Proxy used?
     *
     * @return If a Proxy is used or not
     */
    protected boolean isProxySet() {
        return isStringInputValid(getProxyHost()) && isStringInputValid(getProxyProtocol());
    }

    /**
     * Build the Digest Auth bean for the request builder
     *
     * @return The Digest Auth according to the input values
     */
    BasicDigestAuthorization buildDigestAuthorization() {
        final BasicDigestAuthorization authorization = new BasicDigestAuthorization(false);
        authorization.setUsername(getAuthUsername());
        authorization.setPassword(getAuthPassword());

        if (isStringInputValid(getAuthHost())) {
            authorization.setHost(getAuthHost());
        }
        authorization.setPort(getAuthPort());
        if (isStringInputValid(getAuthRealm())) {
            authorization.setRealm(getAuthRealm());
        }
        authorization.setPreemptive(getAuthPreemptive());
        return authorization;
    }

    /**
     * Build the Basic Auth bean for the request builder
     *
     * @return The Basic Auth according to the input values
     */
    BasicDigestAuthorization buildBasicAuthorization() {
        final BasicDigestAuthorization authorization = new BasicDigestAuthorization(true);
        authorization.setUsername(getAuthUsername());
        authorization.setPassword(getAuthPassword());

        if (isStringInputValid(getAuthHost())) {
            authorization.setHost(getAuthHost());
        }
        authorization.setPort(getAuthPort());
        if (isStringInputValid(getAuthRealm())) {
            authorization.setRealm(getAuthRealm());
        }
        authorization.setPreemptive(getAuthPreemptive());

        return authorization;
    }

    /**
     * Build the OAuth2 Client Credentials Auth bean for the request builder
     *
     * @return The OAuth2 Client Credentials Auth according to the input values
     */
    OAuth2ClientCredentialsAuthorization buildOAuth2ClientCredentialsAuthorization() {
        final OAuth2ClientCredentialsAuthorization authorization = new OAuth2ClientCredentialsAuthorization();
        authorization.setTokenEndpoint(getOAuth2TokenEndpoint());
        authorization.setClientId(getOAuth2ClientId());
        authorization.setClientSecret(getOAuth2ClientSecret());
        authorization.setScope(getOAuth2Scope());
        return authorization;
    }

    OAuth2BearerAuthorization buildOAuth2BearerAuthorization() {
        final OAuth2BearerAuthorization authorization = new OAuth2BearerAuthorization();
        authorization.setToken(getOAuth2Token());
        return authorization;
    }

    /**
     * Build the OAuth2 Authorization Code Auth bean for the request builder
     *
     * @return The OAuth2 Authorization Code Auth according to the input values
     */
    OAuth2AuthorizationCodeAuthorization buildOAuth2AuthorizationCodeAuthorization() {
        final OAuth2AuthorizationCodeAuthorization authorization = new OAuth2AuthorizationCodeAuthorization();
        authorization.setTokenEndpoint(getOAuth2TokenEndpoint());
        authorization.setClientId(getOAuth2ClientId());
        authorization.setClientSecret(getOAuth2ClientSecret());
        authorization.setCode(getOAuth2Code());
        authorization.setCodeVerifier(getOAuth2CodeVerifier());
        authorization.setRedirectUri(getOAuth2RedirectUri());
        return authorization;
    }

    /**
     * Build the SSL Req bean for the request builder
     *
     * @return The SSL Req according to the input values
     */
    SSL buildSSL() {
        final SSL ssl = new SSL();
        ssl.setSslVerifier(getHostnameVerifier());
        ssl.setTrustCertificateStrategy(getTrustCertificateStrategy());
        ssl.setUseTLS(getTLS());

        if (isStringInputValid(getTrustStoreFile()) && isStringInputValid(getTrustStorePassword())) {
            final Store trustStore = new Store();
            trustStore.setFile(new File(getTrustStoreFile()));
            trustStore.setPassword(getTrustStorePassword());
            ssl.setTrustStore(trustStore);
        }

        if (isStringInputValid(getKeyStoreFile()) && isStringInputValid(getKeyStorePassword())) {
            final Store keyStore = new Store();
            keyStore.setFile(new File(getKeyStoreFile()));
            keyStore.setPassword(getKeyStorePassword());
            ssl.setKeyStore(keyStore);
        }

        return ssl;
    }

    /**
     * Build the Proxy Req bean for the request builder
     *
     * @return The Proxy Req according to the input values
     */
    Proxy buildProxy() {
        final Proxy proxy = new Proxy();
        proxy.setProtocol(ProxyProtocol.valueOf(getProxyProtocol().toUpperCase()));
        proxy.setHost(getProxyHost());
        proxy.setPort(getProxyPort());
        if (isStringInputValid(getProxyUsername())) {
            proxy.setUsername(getProxyUsername());
        }
        if (isStringInputValid(getProxyPassword())) {
            proxy.setPassword(getProxyPassword());
        }

        return proxy;
    }

    /**
     * Get or acquire an OAuth2 access token for the given authorization
     *
     * @param authorization The OAuth2 Token Request authorization (Client Credentials or Authorization Code)
     * @param proxy The proxy configuration (may be null)
     * @param ssl The SSL configuration (may be null)
     * @return The access token
     * @throws Exception if token acquisition fails
     */
    protected String getOAuth2AccessToken(final OAuth2TokenRequestAuthorization authorization, final Proxy proxy, final SSL ssl) throws Exception {
        // Authorization codes are single-use - they cannot be used in a cache key but save the token in the connector instance for retries
        if (authorization instanceof OAuth2AuthorizationCodeAuthorization) {
            if (userTokenSavedForRetry != null) {
                LOGGER.fine("Reusing previously acquired OAuth2 access token from retry cache");
            } else {
                LOGGER.fine("OAuth2 Authorization Code flow detected - acquiring fresh token (no caching for single-use codes)");
                userTokenSavedForRetry = acquireOAuth2Token(authorization, proxy, ssl).getAccessToken();
            }
            return userTokenSavedForRetry;
        }

        // For Client Credentials flow, use cached tokens
        if (authorization instanceof OAuth2ClientCredentialsAuthorization) {
            LOGGER.fine("OAuth2 Client Credentials authorization detected");
            final OAuth2ClientCredentialsAuthorization clientCreds = (OAuth2ClientCredentialsAuthorization) authorization;

            // Build cache key
            String cacheKey = authorization.getTokenEndpoint() + "#" + authorization.getClientId();
            cacheKey += (clientCreds.getScope() == null ? "" : "#" + clientCreds.getScope());

            // Check cache without lock (fast path)
            TokenWithExpiration cachedToken = OAUTH2_ACCESS_TOKENS.get(cacheKey);
            if (cachedToken != null && !cachedToken.isExpired(OAUTH2_TOKEN_EXPIRATION_CLOCK_SKEW_SECONDS)) {
                return cachedToken.getAccessToken();
            }

            // Get or create a per-key lock to prevent concurrent acquisitions for the same credentials
            final Object lock = OAUTH2_TOKEN_ACQUISITION_LOCKS.computeIfAbsent(cacheKey, k -> new Object());

            // Trigger cleanup if lock map is getting too large
            if (OAUTH2_TOKEN_ACQUISITION_LOCKS.size() > MAX_CACHED_LOCKS) {
                cleanupOrphanedLocks();
            }

            // Synchronize on per-key lock to prevent parallel acquisitions with same credentials
            synchronized (lock) {
                // Double-check: another thread might have acquired token while we were waiting for the lock
                cachedToken = OAUTH2_ACCESS_TOKENS.get(cacheKey);
                if (cachedToken != null && !cachedToken.isExpired(OAUTH2_TOKEN_EXPIRATION_CLOCK_SKEW_SECONDS)) {
                    return cachedToken.getAccessToken();
                }

                // Acquire token (only one thread per cache key will reach here)
                TokenWithExpiration newToken = acquireOAuth2Token(authorization, proxy, ssl);
                OAUTH2_ACCESS_TOKENS.put(cacheKey, newToken);
                return newToken.getAccessToken();
            }
        }

        // Fallback for unknown authorization types
        throw new ConnectorException("Unsupported OAuth2 authorization type: " + authorization.getClass().getName());
    }

    /**
     * Clean up orphaned locks for cache keys that no longer exist in the token cache.
     * This is safe because if a key is not in the cache, no thread should be waiting on its lock.
     * Called when lock map size exceeds MAX_CACHED_LOCKS.
     *
     * Thread-safety: Synchronizes on OAUTH2_ACCESS_TOKENS to ensure the snapshot of cache keys
     * is consistent and atomic with respect to cache modifications.
     */
    private void cleanupOrphanedLocks() {
        // Take a consistent snapshot of cache keys while synchronized to prevent race conditions
        // where a lock could be removed while another thread is about to use it
        synchronized (OAUTH2_ACCESS_TOKENS) {
            Set<String> cacheKeys = new HashSet<>(OAUTH2_ACCESS_TOKENS.keySet());
            OAUTH2_TOKEN_ACQUISITION_LOCKS.keySet().removeIf(key -> !cacheKeys.contains(key));
        }
    }

    /**
     * Acquire a new OAuth2 access token from the token endpoint
     *
     * @param authorization The OAuth2 Token Request authorization (Client Credentials or Authorization Code)
     * @param proxy The proxy configuration (may be null)
     * @param ssl The SSL configuration (may be null)
     * @return The access token with expiration information
     * @throws Exception if token acquisition fails
     */
    private TokenWithExpiration acquireOAuth2Token(final OAuth2TokenRequestAuthorization authorization, final Proxy proxy, final SSL ssl) throws Exception {
        final HttpPost tokenRequest = new HttpPost(authorization.getTokenEndpoint());

        // Build form-urlencoded body based on grant type
        final List<NameValuePair> params = new ArrayList<>();

        if (authorization instanceof OAuth2ClientCredentialsAuthorization) {
            // Client Credentials flow
            final OAuth2ClientCredentialsAuthorization clientCreds = (OAuth2ClientCredentialsAuthorization) authorization;
            params.add(new BasicNameValuePair("grant_type", "client_credentials"));
            params.add(new BasicNameValuePair("client_id", clientCreds.getClientId()));
            params.add(new BasicNameValuePair("client_secret", clientCreds.getClientSecret()));
            if (isStringInputValid(clientCreds.getScope())) {
                params.add(new BasicNameValuePair("scope", clientCreds.getScope()));
            }
        } else if (authorization instanceof OAuth2AuthorizationCodeAuthorization) {
            // Authorization Code flow with optional PKCE
            final OAuth2AuthorizationCodeAuthorization authCode = (OAuth2AuthorizationCodeAuthorization) authorization;
            params.add(new BasicNameValuePair("grant_type", "authorization_code"));
            params.add(new BasicNameValuePair("client_id", authCode.getClientId()));

            // Client secret is optional for public clients in PKCE flow
            if (isStringInputValid(authCode.getClientSecret())) {
                params.add(new BasicNameValuePair("client_secret", authCode.getClientSecret()));
            }

            params.add(new BasicNameValuePair("code", authCode.getCode()));

            // Code verifier is optional (PKCE is not mandatory)
            if (isStringInputValid(authCode.getCodeVerifier())) {
                params.add(new BasicNameValuePair("code_verifier", authCode.getCodeVerifier()));
            }

            // Redirect URI may be required by some OAuth2 providers
            if (isStringInputValid(authCode.getRedirectUri())) {
                params.add(new BasicNameValuePair("redirect_uri", authCode.getRedirectUri()));
            }
        }

        tokenRequest.setEntity(new UrlEncodedFormEntity(params, Charset.forName("UTF-8")));
        tokenRequest.setHeader("Content-Type", "application/x-www-form-urlencoded");

        // Configure request timeouts
        final RequestConfig requestConfig = RequestConfig.custom()
                .setConnectionRequestTimeout(getConnectionTimeoutMs())
                .setConnectTimeout(getConnectionTimeoutMs())
                .setSocketTimeout(getSocketTimeoutMs())
                .build();
        tokenRequest.setConfig(requestConfig);
        LOGGER.fine(() -> "OAuth2 token request configured with timeouts: connect=" + getConnectionTimeoutMs() + "ms, socket=" + getSocketTimeoutMs() + "ms");

        // Build HTTP client with SSL and proxy support
        final HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();

        // Apply SSL configuration
        setSSL(ssl, httpClientBuilder);

        if (proxy != null) {
            final HttpHost proxyHost = new HttpHost(proxy.getHost(), proxy.getPort());
            httpClientBuilder.setProxy(proxyHost);

            // Add proxy credentials if provided
            if (proxy.hasCredentials()) {
                final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
                credentialsProvider.setCredentials(
                        new AuthScope(proxy.getHost(), proxy.getPort()),
                        new UsernamePasswordCredentials(
                                proxy.getUsername(), proxy.getPassword() == null ? "" : proxy.getPassword()));
                httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);
                LOGGER.fine("OAuth2 token request configured with proxy authentication");
            }
            LOGGER.fine(() -> "OAuth2 token request configured to use proxy: " + proxy.getHost() + ":" + proxy.getPort());
        }

        // Execute the token request
        try (final CloseableHttpClient httpClient = httpClientBuilder.build()) {
            try (final CloseableHttpResponse response = httpClient.execute(tokenRequest)) {
                return handleTokenResponse(response);
            }
        }
    }

    private TokenWithExpiration handleTokenResponse(CloseableHttpResponse response) throws IOException, ConnectorException {
        final int statusCode = response.getStatusLine().getStatusCode();

        // Parse the JSON response
        final String responseBody = EntityUtils.toString(response.getEntity());
        final ContentType responseContentType = ContentType.get(response.getEntity());

        // Check if response is JSON before attempting to parse error details
        boolean isJsonResponse = responseContentType != null
            && ContentType.APPLICATION_JSON.getMimeType().equals(responseContentType.getMimeType());

        if (statusCode != 200) {
            // If response is JSON, try to parse OAuth2 error details
            if (isJsonResponse) {
                try {
                    final Map<String, Object> errorResponse = JSON_MAPPER.readValue(responseBody, HashMap.class);

                    // Check and handle OAuth2 error responses (RFC 6749 Section 5.2)
                    checkForErrorResponse(errorResponse);
                } catch (JsonParseException | JsonMappingException e) {
                    // Fall through to generic error message if JSON parsing fails
                    LOGGER.fine(() -> "Could not parse JSON error in token response. Response: " + abbreviateBody(responseBody) + ", Error: " + e.getMessage());
                }
            }
            // Generic error message if response is not JSON or parsing failed
            throw new ConnectorException("Failed to acquire OAuth2 token. Status: " + statusCode + ", Response: " + abbreviateBody(responseBody));
        }

        // Status code is 200 - parse successful token response
        try {
            final Map<String, Object> tokenResponse = JSON_MAPPER.readValue(responseBody, HashMap.class);

            // Check and handle OAuth2 error responses (RFC 6749 Section 5.2)
            // Some providers return 200 status with error field like {"error": "invalid_grant"}
            checkForErrorResponse(tokenResponse);

            final String accessToken = (String) tokenResponse.get("access_token");
            if (accessToken == null || accessToken.isEmpty()) {
                throw new ConnectorException("Neither access_token nor error in OAuth2 token response. Response: " + abbreviateBody(responseBody));
            }

            // Extract expires_in (in seconds) from the response
            // Default to DEFAULT_TOKEN_EXPIRES_IN if not provided
            // Handle both Number and String types (some OAuth2 providers return strings)
            Integer expiresInSeconds = null;
            if (tokenResponse.get("expires_in") != null) {
                Object expiresInValue = tokenResponse.get("expires_in");
                if (expiresInValue instanceof Number) {
                    expiresInSeconds = ((Number) expiresInValue).intValue();
                } else if (expiresInValue instanceof String) {
                    try {
                        expiresInSeconds = Integer.parseInt((String) expiresInValue);
                    } catch (NumberFormatException e) {
                        if (LOGGER.isLoggable(Level.WARNING)) {
                            LOGGER.warning("Invalid expires_in value: " + expiresInValue + ". Defaulting to " + DEFAULT_TOKEN_EXPIRES_IN + " seconds.");
                        }
                    }
                } else {
                    if (LOGGER.isLoggable(Level.WARNING)) {
                        LOGGER.warning("Unexpected expires_in type: " + expiresInValue.getClass().getName() + ". Defaulting to " + DEFAULT_TOKEN_EXPIRES_IN + " seconds.");
                    }
                }
            }
            if (expiresInSeconds == null) {
                if (LOGGER.isLoggable(Level.WARNING)) {
                    LOGGER.warning("OAuth2 provider did not return expires_in. Defaulting to " + DEFAULT_TOKEN_EXPIRES_IN + " seconds.");
                }
                expiresInSeconds = DEFAULT_TOKEN_EXPIRES_IN;
            }

            // Calculate expiration time in milliseconds
            final long expirationTimeMillis = System.currentTimeMillis() + (expiresInSeconds * 1000L);

            if (LOGGER.isLoggable(Level.FINE)) {
                LOGGER.fine("OAuth2 token acquired successfully. Expires in " + expiresInSeconds + " seconds");
            }

            return new TokenWithExpiration(accessToken, expirationTimeMillis);
        } catch (JsonParseException | JsonMappingException e) {
            LOGGER.severe(() -> "Could not parse token response: " + e.getMessage());
            // Generic error message if response is not JSON or parsing failed
            throw new ConnectorException("Failed to acquire OAuth2 token. Status: " + statusCode + ", Response: " + abbreviateBody(responseBody));
        }
    }

    private void checkForErrorResponse(Map<String, Object> tokenResponse) throws ConnectorException {
        if (tokenResponse.containsKey("error")) {
            final String error = (String) tokenResponse.get("error");
            final String errorDescription = (String) tokenResponse.get("error_description");
            final String errorUri = (String) tokenResponse.get("error_uri");

            StringBuilder errorMessage = new StringBuilder("OAuth2 token request failed. Error: " + error);
            if (errorDescription != null && !errorDescription.isEmpty()) {
                errorMessage.append(", Description: ").append(errorDescription);
            }
            if (errorUri != null && !errorUri.isEmpty()) {
                errorMessage.append(", URI: ").append(errorUri);
            }
            throw new ConnectorException(errorMessage.toString());
        }
    }

    /**
     * Extracts the response of the HTTP transaction
     *
     * @param response The response of the sent request
     * @param request
     * @throws IOException if an I/O error occurs
     */
    protected void setOutputs(final HttpResponse response, Request request) throws IOException {
        if (response != null) {
            final HttpEntity entity = response.getEntity();
            if (entity != null) {
                if (request.isIgnore()) {
                    EntityUtils.consumeQuietly(entity);
                } else {
                    parseResponse(entity);
                }
            } else {
                setBody("");
                setBody(Collections.<String, Object> emptyMap());
            }
            setHeaders(asMap(response.getAllHeaders()));
            setStatusCode(response.getStatusLine().getStatusCode());
            setStatusMessage(response.getStatusLine().getReasonPhrase());
            LOGGER.fine("All outputs have been set.");
        } else {
            LOGGER.fine("Response is null.");
        }
    }

    private String abbreviateBody(String body) {
        Integer maximumBodyContentPrintedLogs = getMaximumBodyContentPrintedLogs();
        if (maximumBodyContentPrintedLogs == 0) {
            return "Hidden body content";
        }
        final String abbrevMarker = "...";
        return StringUtils.abbreviate(body, abbrevMarker, getMaximumBodyContentPrintedLogs() + abbrevMarker.length());
    }

    private void parseResponse(final HttpEntity entity) throws IOException {
        boolean fallbackToDefaultCharset = Boolean
                .parseBoolean(System.getProperty(DEFAULT_JVM_CHARSET_FALLBACK_PROPERTY));
        String stringContent = EntityUtils.toString(entity, fallbackToDefaultCharset ? Charset.defaultCharset() : null);
        final String bodyResponse = stringContent != null ? stringContent.trim() : "";
            LOGGER.fine(() -> "Response body: " + abbreviateBody(bodyResponse));
        setBody(bodyResponse);
        setBody(Collections.<String, Object> emptyMap());
        ContentType contentType = ContentType.get(entity);
        if (contentType != null
                && ContentType.APPLICATION_JSON.getMimeType().equals(contentType.getMimeType())) {
            try {
                if (bodyResponse.startsWith("[")) {
                    setBody(JSON_MAPPER.readValue(bodyResponse, List.class));
                } else if (bodyResponse.startsWith("{")) {
                    setBody(JSON_MAPPER.readValue(bodyResponse, HashMap.class));
                } else {
                    setBody(JSON_MAPPER.readValue(bodyResponse, Object.class));
                }
            } catch (JsonParseException | JsonMappingException e) {
                LOGGER.warning(
                        String.format(
                                "BodyAsObject output cannot be set. Response content is not valid json(%s).",
                                bodyResponse));
            }
        } else {
            LOGGER.warning(
                    () -> String.format(
                            "Body as map output cannot be set. Response content type is not json compliant(%s).",
                            contentType != null ? contentType : "no Content-Type in response header"));
        }
    }

    private Map<String, String> asMap(Header[] headers) {
        final Map<String, String> result = new HashMap<>();
        if (headers != null) {
            for (final Header header : headers) {
                String name = header.getName();
                if (!StringUtils.isEmpty(header.getValue())) {
                    if (!result.containsKey(name)) {
                        result.put(name, header.getValue());
                    } else {
                        String currentValue = result.get(name);
                        result.put(name, currentValue + "," + header.getValue());
                    }
                }
            }
        }
        return result;
    }

    HttpClientBuilder newHttpClientBuilder() {
        return HttpClientBuilder.create();
    }

    /**
     * Execute a given request
     *
     * @param request The request to execute
     * @throws Exception any exception that might occur
     */
    public void execute(final Request request, Consumer<HttpResponse> consumer, Consumer<HttpResponse> retryConsumer, Consumer<HttpResponse> failureConsumer) throws Exception {
        CloseableHttpClient httpClient = null;

        try {
            final URL url = request.getUrl();
            final String urlHost = url.getHost();

            final Builder requestConfigurationBuilder = RequestConfig.custom();
            requestConfigurationBuilder.setConnectionRequestTimeout(getConnectionTimeoutMs());
            requestConfigurationBuilder.setRedirectsEnabled(request.isRedirect());
            requestConfigurationBuilder.setConnectTimeout(getConnectionTimeoutMs());
            requestConfigurationBuilder.setSocketTimeout(getSocketTimeoutMs());

            final HttpClientBuilder httpClientBuilder = newHttpClientBuilder();
            httpClientBuilder.setRetryHandler(new DefaultHttpRequestRetryHandler(0, false));
            setSSL(request.getSsl(), httpClientBuilder);
            setProxy(request.getProxy(), httpClientBuilder, requestConfigurationBuilder);
            setCookies(requestConfigurationBuilder, httpClientBuilder, request.getCookies(), urlHost);

            final RequestBuilder requestBuilder = getRequestBuilderFromMethod(request.getRestMethod());
            requestBuilder.setVersion(
                    new ProtocolVersion(
                            HTTP_PROTOCOL, HTTP_PROTOCOL_VERSION_MAJOR, HTTP_PROTOCOL_VERSION_MINOR));
            int urlPort = url.getPort();
            if (url.getPort() == -1) {
                urlPort = url.getDefaultPort();
            }
            final String urlProtocol = url.getProtocol();
            final String urlStr = url.toString();
            requestBuilder.setUri(urlStr);
            setHeaders(requestBuilder, request.getHeaders());
            if (request.hasBody()) {
                final Serializable body = request.getBody();
                if (body != null) {
                    requestBuilder.setEntity(
                            new ByteArrayEntity(toByteArray(body, request.getContentType().getCharset()), request.getContentType()));
                }
            }

            final HttpContext httpContext = setAuthorizations(
                    requestConfigurationBuilder,
                    requestBuilder,
                    request.getAuthorization(),
                    request.getProxy(),
                    request.getSsl(),
                    urlHost,
                    urlPort,
                    urlProtocol,
                    httpClientBuilder);

            LOGGER.info(() -> request.getRestMethod() + " " + url);

            requestBuilder.setConfig(requestConfigurationBuilder.build());
            httpClientBuilder.setDefaultRequestConfig(requestConfigurationBuilder.build());

            final HttpUriRequest httpRequest = requestBuilder.build();
            logHeaders(httpRequest);
            httpClient = httpClientBuilder.build();
            LOGGER.fine("Request sent.");
            final CloseableHttpResponse httpResponse = httpClient.execute(httpRequest, httpContext);
            LOGGER.fine("Response received.");
            final int statusCode = httpResponse.getStatusLine().getStatusCode();
            LOGGER.fine(
                    () -> String.format(
                            "%s response status is: %s - %s",
                            request, statusCode, httpResponse.getStatusLine().getReasonPhrase()));
            logHeaders(httpResponse);
            if (retryConsumer != null && retryRequested(httpResponse)) {
                LOGGER.fine("Retry requested.");
                retryConsumer.accept(httpResponse);
            } else if (failureConsumer != null && failureRequested(httpResponse)) {
                LOGGER.fine("Failure requested.");
                failureConsumer.accept(httpResponse);
            } else {
                consumer.accept(httpResponse);
            }
        } finally {
            try {
                if (httpClient != null) {
                    httpClient.close();
                }
            } catch (final IOException ex) {
                logException(ex);
            }
        }
    }

    private void logHeaders(HttpUriRequest httpRequest) {
        if (!LOGGER.isLoggable(Level.FINE)) {
            return;
        }
        LOGGER.fine("Request headers:");
        for (Header header : httpRequest.getAllHeaders()) {
            logHeader(header);
        }
    }

    private void logHeaders(CloseableHttpResponse httpResponse) {
        if (!LOGGER.isLoggable(Level.FINE)) {
            return;
        }
        LOGGER.fine("Response headers:");
        for (Header header : httpResponse.getAllHeaders()) {
            logHeader(header);
        }
    }

    private void logHeader(Header header) {
        if (!LOGGER.isLoggable(Level.FINE)) {
            return;
        }
        var lowerCaseName = header.getName().toLowerCase();
        var value = (SECRET_HEADER_NAMES.stream().anyMatch(lowerCaseName::contains) && !getShowSensitiveHeadersInLogs()) ?
                "Hidden header value" :
                header.getValue();
        LOGGER.fine(header.getName() + ": " + value);
    }

    private boolean failureRequested(HttpResponse response) {
        int statusCode = response.getStatusLine().getStatusCode();
        if (getFailExceptionHttpCodes().contains(Integer.toString(statusCode))) {
            return false;
        }
        if (getFailOnHttp5xx() && statusCode >= 500 && statusCode <= 599) {
            return true;
        }
        if (getFailOnHttp4xx() && statusCode >= 400 && statusCode <= 499) {
            return true;
        }
        return false;
    }

    private boolean retryRequested(HttpResponse response) {
        int statusCode = response.getStatusLine().getStatusCode();
        if (getRetryAdditionalHttpCodes().contains(Integer.toString(statusCode))) {
            return true;
        }
        if (getRetryOnHttp5xx() && statusCode >= 500 && statusCode <= 599) {
            return true;
        }
        return false;
    }

    protected void execute(final Request request) throws Exception {
        execute(request,
                response -> {
                    try {
                        setOutputs(response, request);
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }
                },
                response -> {
                    throw new SRetryableException(new HttpStatusFailureException(response.getStatusLine().getStatusCode()));
                },
                response -> {
                    throw new HttpStatusFailureException(response.getStatusLine().getStatusCode());
                }
        );
    }

    private byte[] toByteArray(Serializable body, Charset charset) {
        if (body instanceof String) {
            return ((String) body).getBytes(charset);
        }
        if (body instanceof byte[]) {
            return (byte[]) body;
        }
        throw new IllegalArgumentException(
                "Body content type not supported. Expected String or byte[]");
    }

    /**
     * Set the request builder based on the request
     *
     * @param ssl The request SSL options
     * @param httpClientBuilder The request builder
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws CertificateException
     * @throws UnrecoverableKeyException
     * @throws KeyManagementException
     */
    private void setSSL(final SSL ssl, final HttpClientBuilder httpClientBuilder) throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException, UnrecoverableKeyException, KeyManagementException {
        if (ssl != null) {
            final SSLContextBuilder sslContextBuilder = new SSLContextBuilder();
            TrustCertificateStrategy trustCertificateStrategy = ssl.getTrustCertificateStrategy();
            if (trustCertificateStrategy == TrustCertificateStrategy.TRUST_SELF_SIGNED) {
                sslContextBuilder.loadTrustMaterial(null, TrustSelfSignedStrategy.INSTANCE);
            } else if (trustCertificateStrategy == TrustCertificateStrategy.TRUST_ALL) {
                sslContextBuilder.loadTrustMaterial(
                        null,
                        (chain, authType) -> Boolean.TRUE);
            }
            if (ssl.getTrustStore() != null) {
                final KeyStore keyStore = ssl.getTrustStore().generateKeyStore();
                if (trustCertificateStrategy == TrustCertificateStrategy.DEFAULT) {
                    sslContextBuilder.loadTrustMaterial(keyStore, null);
                }
            }

            if (ssl.getKeyStore() != null) {
                final KeyStore keyStore = ssl.getKeyStore().generateKeyStore();
                final String keyStorePassword = ssl.getKeyStore().getPassword();
                sslContextBuilder.loadKeyMaterial(keyStore, keyStorePassword.toCharArray());
            }

            sslContextBuilder.setSecureRandom(null);
            sslContextBuilder.setProtocol(ssl.isUseTLS() ? "TLS" : "SSL");

            final SSLVerifier verifier = ssl.getSslVerifier();
            HostnameVerifier hostnameVerifier = SSLConnectionSocketFactory.getDefaultHostnameVerifier();
            switch (verifier) {
                case ALLOW:
                    hostnameVerifier = NoopHostnameVerifier.INSTANCE;
                    break;
                case BROWSER:
                case STRICT:
                default:
                    break;
            }

            final SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(sslContextBuilder.build(),
                    hostnameVerifier);
            httpClientBuilder.setSSLSocketFactory(socketFactory);
        }
    }

    /**
     * Set the request builder based on the request
     *
     * @param proxy The request Proxy options
     * @param httpClientBuilder The request builder
     */
    private void setProxy(
            final Proxy proxy,
            final HttpClientBuilder httpClientBuilder,
            final Builder requestConfigurationBuilder) {
        if (proxy != null) {
            final HttpHost httpHost = new HttpHost(proxy.getHost(), proxy.getPort());

            httpClientBuilder.setProxy(httpHost);
            httpClientBuilder.setProxyAuthenticationStrategy(new ProxyAuthenticationStrategy());

            requestConfigurationBuilder.setProxy(httpHost);
            final ArrayList<String> authPrefs = new ArrayList<>();
            authPrefs.add(AuthSchemes.BASIC);
            requestConfigurationBuilder.setProxyPreferredAuthSchemes(authPrefs);
        }
    }

    /**
     * Set the request builder credentials provider based on the request
     *
     * @param proxy The request Proxy options
     * @param credentialsProvider The request builder credentials provider
     */
    private void setProxyCredentials(
            final Proxy proxy, final CredentialsProvider credentialsProvider) {
        if (proxy != null && proxy.hasCredentials()) {
            credentialsProvider.setCredentials(
                    new AuthScope(proxy.getHost(), proxy.getPort()),
                    new UsernamePasswordCredentials(
                            proxy.getUsername(), proxy.getPassword() == null ? "" : proxy.getPassword()));
        }
    }

    /**
     * Set proxy credentials with preemptive authentication and return HttpContext
     *
     * @param proxy The request Proxy options
     * @param httpClientBuilder The HTTP client builder to configure
     * @return HttpContext with preemptive proxy authentication if proxy has credentials, or default context otherwise
     */
    private HttpContext setProxyCredentialsWithContext(
            final Proxy proxy, final HttpClientBuilder httpClientBuilder) {
        if (proxy != null && proxy.hasCredentials()) {
            final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
            setProxyCredentials(proxy, credentialsProvider);
            httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);

            // Make proxy authentication preemptive
            HttpContext httpContext = createProxyAuthContext(proxy);
            LOGGER.fine("Proxy credentials configured with preemptive authentication");
            return httpContext;
        }
        return HttpClientContext.create();
    }

    /**
     * Create an HttpContext with preemptive proxy authentication
     *
     * @param proxy The proxy configuration
     * @return HttpContext with preemptive proxy authentication configured
     */
    private HttpContext createProxyAuthContext(final Proxy proxy) {
        final AuthCache authenticationCache = new BasicAuthCache();
        final BasicScheme basicScheme = new BasicScheme(ChallengeState.PROXY);
        authenticationCache.put(new HttpHost(proxy.getHost(), proxy.getPort()), basicScheme);
        final HttpClientContext localContext = HttpClientContext.create();
        localContext.setAuthCache(authenticationCache);
        return localContext;
    }

    /**
     * Set the cookies to the builder based on the request cookies
     *
     * @param requestConfigurationBuilder The request builder
     * @param httpClientBuilder The request builder
     * @param cookies The cookies
     * @param urlHost The URL host
     */
    private void setCookies(
            final Builder requestConfigurationBuilder,
            final HttpClientBuilder httpClientBuilder,
            final List<HttpCookie> cookies,
            final String urlHost) {
        final CookieStore cookieStore = new BasicCookieStore();
        for (final HttpCookie cookie : cookies) {
            final BasicClientCookie c = new BasicClientCookie(cookie.getName(), cookie.getValue());
            c.setPath("/");
            c.setVersion(0);
            c.setDomain(urlHost);
            cookieStore.addCookie(c);
        }
        httpClientBuilder.setDefaultCookieStore(cookieStore);
        requestConfigurationBuilder.setCookieSpec(CookieSpecs.DEFAULT);
    }

    /**
     * Set the headers to the builder based on the request headers
     *
     * @param requestBuilder The request builder
     * @param headerData The request headers
     */
    private void setHeaders(final RequestBuilder requestBuilder, final List<Header> headerData) {
        for (final Header aHeaderData : headerData) {
            requestBuilder.addHeader(aHeaderData);
        }
    }

    /**
     * Set the builder based on the request elements
     *
     * @param requestConfigurationBuilder The builder to be set
     * @param authorization The authentication element of the request
     * @param proxy The proxy element of the request
     * @param ssl The SSL configuration for the request
     * @param urlHost The URL host of the request
     * @param urlPort The URL post of the request
     * @param urlProtocol The URL protocol of the request
     * @param httpClientBuilder The builder to be set
     * @return HTTPContext The HTTP context to be set
     */
    private HttpContext setAuthorizations(
            final Builder requestConfigurationBuilder,
            final RequestBuilder requestBuilder,
            final Authorization authorization,
            final Proxy proxy,
            final SSL ssl,
            final String urlHost,
            final int urlPort,
            final String urlProtocol,
            final HttpClientBuilder httpClientBuilder) throws Exception {
        HttpContext httpContext = HttpClientContext.create();
        if (authorization != null) {
            if (authorization instanceof OAuth2TokenRequestAuthorization) {
                final OAuth2TokenRequestAuthorization castAuthorization = (OAuth2TokenRequestAuthorization) authorization;
                // Get or acquire access token (proxy and SSL are passed for token endpoint access)
                String oauth2Token = getOAuth2AccessToken(castAuthorization, proxy, ssl);
                // Add Bearer token to request header
                setBearerAuthenticationHeader(requestBuilder, oauth2Token);
                // Handle proxy credentials for the actual API request (if proxy is configured)
                httpContext = setProxyCredentialsWithContext(proxy, httpClientBuilder);
            } else if (authorization instanceof OAuth2BearerAuthorization) {
                final OAuth2BearerAuthorization castAuthorization = (OAuth2BearerAuthorization) authorization;
                LOGGER.fine("OAuth2 Bearer authorization detected");
                String oauth2Token = castAuthorization.getToken();
                // Add Bearer token to request header
                setBearerAuthenticationHeader(requestBuilder, oauth2Token);
                // Handle proxy credentials for the actual API request (if proxy is configured)
                httpContext = setProxyCredentialsWithContext(proxy, httpClientBuilder);
            } else if (authorization instanceof BasicDigestAuthorization) {
                final BasicDigestAuthorization castAuthorization = (BasicDigestAuthorization) authorization;
                final List<String> authPrefs = new ArrayList<>();
                authPrefs.add(castAuthorization.isBasic() ? AuthSchemes.BASIC : AuthSchemes.DIGEST);
                requestConfigurationBuilder.setTargetPreferredAuthSchemes(authPrefs);
                final String username = castAuthorization.getUsername();
                final String password = castAuthorization.getPassword();
                String host = urlHost;
                if (isStringInputValid(castAuthorization.getHost())) {
                    host = castAuthorization.getHost();
                }

                int port = urlPort;
                if (castAuthorization.getPort() != null) {
                    port = castAuthorization.getPort();
                }

                String realm = AuthScope.ANY_REALM;
                if (isStringInputValid(castAuthorization.getRealm())) {
                    realm = castAuthorization.getRealm();
                }

                final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
                credentialsProvider.setCredentials(
                        new AuthScope(host, port, realm), new UsernamePasswordCredentials(username, password));
                setProxyCredentials(proxy, credentialsProvider);
                httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);

                if (castAuthorization.isPreemptive() || proxy != null) {
                    final AuthCache authenticationCache = new BasicAuthCache();
                    if (castAuthorization.isPreemptive()) {
                        final AuthSchemeBase authorizationScheme = castAuthorization.isBasic() ? new BasicScheme()
                                : new DigestScheme();
                        authenticationCache.put(new HttpHost(host, port, urlProtocol), authorizationScheme);
                    }
                    if (proxy != null) {
                        httpContext = createProxyAuthContext(proxy);
                    } else {
                        final HttpClientContext localContext = HttpClientContext.create();
                        localContext.setAuthCache(authenticationCache);
                        httpContext = localContext;
                    }
                }
            }
        } else if (proxy != null) {
            final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
            setProxyCredentials(proxy, credentialsProvider);
            httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);

            // Make it preemptive
            if (proxy.hasCredentials()) {
                httpContext = createProxyAuthContext(proxy);
            }
        }

        return httpContext;
    }

    protected void setBearerAuthenticationHeader(RequestBuilder requestBuilder, String oauth2Token) {
        requestBuilder.addHeader("Authorization", "Bearer " + oauth2Token);
        LOGGER.fine("OAuth2 Bearer token added to Authorization header");
    }

    /**
     * Generate a request builder based on the given method
     *
     * @param method The method
     * @return The request builder
     */
    private RequestBuilder getRequestBuilderFromMethod(final HTTPMethod method) {
        switch (method) {
            case GET:
                return RequestBuilder.get();
            case POST:
                return RequestBuilder.post();
            case PUT:
                return RequestBuilder.put();
            case DELETE:
                return RequestBuilder.delete();
            case HEAD:
                return RequestBuilder.head();
            case PATCH:
                return RequestBuilder.patch();
            default:
                throw new IllegalStateException(
                        "Impossible to get the RequestBuilder from the \"" + method.name() + "\" name.");
        }
    }

    /**
     * Log an exception in generic way
     *
     * @param e The exception raised
     */
    protected void logException(final Exception e) {
        final StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(e.toString());
        for (final StackTraceElement stackTraceElement : e.getStackTrace()) {
            stringBuilder.append("\n").append(stackTraceElement);
        }
        LOGGER.fine(() -> "executeBusinessLogic error: " + stringBuilder.toString());
    }

    @Override
    public boolean hasBody() {
        return hasBody;
    }
}

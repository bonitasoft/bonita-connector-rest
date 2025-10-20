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
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
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
     * OAuth2 access token cache (key: tokenEndpoint#clientId, value: access token JWT)
     * Package-private for testing
     */
    static final Map<String, String> OAUTH2_ACCESS_TOKENS = Collections.synchronizedMap(new HashMap<>());

    /**
     * Clock skew for anticipating token expiration (60 seconds before actual expiration)
     */
    private static final long OAUTH2_TOKEN_EXPIRATION_CLOCK_SKEW_SECONDS = 60;

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
    private Request buildRequest() throws MalformedURLException, ConnectorException {
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
    private boolean isProxySet() {
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
     * @param authorization The OAuth2 Client Credentials authorization
     * @param proxy The proxy configuration (may be null)
     * @return The access token
     * @throws Exception if token acquisition fails
     */
    private String getOAuth2AccessToken(final OAuth2ClientCredentialsAuthorization authorization, final Proxy proxy) throws Exception {
        final String cacheKey = authorization.getTokenEndpoint() + "#" + authorization.getClientId();

        // Check if we have a cached token that's still valid
        String cachedToken = OAUTH2_ACCESS_TOKENS.get(cacheKey);
        if (cachedToken != null && !isOAuth2TokenExpired(cachedToken)) {
            LOGGER.fine("Using cached OAuth2 access token");
            return cachedToken;
        }

        // Acquire a new token
        LOGGER.fine("Acquiring new OAuth2 access token from " + authorization.getTokenEndpoint());
        final String accessToken = acquireOAuth2Token(authorization, proxy);

        // Cache the token
        OAUTH2_ACCESS_TOKENS.put(cacheKey, accessToken);
        LOGGER.fine("OAuth2 access token acquired and cached");

        return accessToken;
    }

    /**
     * Acquire a new OAuth2 access token from the token endpoint
     *
     * @param authorization The OAuth2 Client Credentials authorization
     * @param proxy The proxy configuration (may be null)
     * @return The access token
     * @throws Exception if token acquisition fails
     */
    private String acquireOAuth2Token(final OAuth2ClientCredentialsAuthorization authorization, final Proxy proxy) throws Exception {
        final HttpPost tokenRequest = new HttpPost(authorization.getTokenEndpoint());

        // Build form-urlencoded body
        final List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("grant_type", "client_credentials"));
        params.add(new BasicNameValuePair("client_id", authorization.getClientId()));
        params.add(new BasicNameValuePair("client_secret", authorization.getClientSecret()));
        if (isStringInputValid(authorization.getScope())) {
            params.add(new BasicNameValuePair("scope", authorization.getScope()));
        }

        tokenRequest.setEntity(new UrlEncodedFormEntity(params, Charset.forName("UTF-8")));
        tokenRequest.setHeader("Content-Type", "application/x-www-form-urlencoded");

        // Build HTTP client with proxy support
        final HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
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
                final int statusCode = response.getStatusLine().getStatusCode();
                if (statusCode != 200) {
                    final String responseBody = EntityUtils.toString(response.getEntity());
                    throw new ConnectorException("Failed to acquire OAuth2 token. Status: " + statusCode + ", Response: " + responseBody);
                }

                // Parse the JSON response
                final String responseBody = EntityUtils.toString(response.getEntity());
                final ObjectMapper objectMapper = new ObjectMapper();
                final Map<String, Object> tokenResponse = objectMapper.readValue(responseBody, HashMap.class);

                final String accessToken = (String) tokenResponse.get("access_token");
                if (accessToken == null || accessToken.isEmpty()) {
                    throw new ConnectorException("No access_token in OAuth2 token response");
                }

                LOGGER.fine("OAuth2 token acquired successfully");
                return accessToken;
            }
        }
    }

    /**
     * Check if an OAuth2 access token (JWT) is expired using Nimbus JOSE JWT library
     *
     * @param accessToken The JWT access token
     * @return true if the token is expired (or will expire within clock skew), false otherwise
     */
    private boolean isOAuth2TokenExpired(final String accessToken) {
        try {
            // Parse the JWT
            final JWT jwt = JWTParser.parse(accessToken);
            final Date expirationTime = jwt.getJWTClaimsSet().getExpirationTime();

            if (expirationTime == null) {
                LOGGER.fine("No expiration time in JWT, treating as expired");
                return true;
            }

            // Check if token is expired (with clock skew)
            final long nowMillis = System.currentTimeMillis();
            final long expirationMillis = expirationTime.getTime() - (OAUTH2_TOKEN_EXPIRATION_CLOCK_SKEW_SECONDS * 1000);
            final boolean isExpired = expirationMillis <= nowMillis;

            if (isExpired) {
                LOGGER.fine(() -> "OAuth2 token is expired or will expire soon. exp=" + expirationTime + ", now=" + new Date(nowMillis));
            }

            return isExpired;
        } catch (Exception e) {
            LOGGER.warning("Failed to parse OAuth2 token expiration, treating as expired: " + e.getMessage());
            return true;
        }
    }

    /**
     * Extracts the response of the HTTP transaction
     *
     * @param response The response of the sent request
     * @param request
     * @throws
     * @throws IOException
     */
    private void setOutputs(final HttpResponse response, Request request) throws IOException {
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
                    setBody(new ObjectMapper().readValue(bodyResponse, List.class));
                } else if (bodyResponse.startsWith("{")) {
                    setBody(new ObjectMapper().readValue(bodyResponse, HashMap.class));
                } else {
                    setBody(new ObjectMapper().readValue(bodyResponse, Object.class));
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
    private void setProxyCrendentials(
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
            setProxyCrendentials(proxy, credentialsProvider);
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
            final String urlHost,
            final int urlPort,
            final String urlProtocol,
            final HttpClientBuilder httpClientBuilder) throws Exception {
        HttpContext httpContext = HttpClientContext.create();
        if (authorization != null) {
            if (authorization instanceof OAuth2ClientCredentialsAuthorization) {
                final OAuth2ClientCredentialsAuthorization castAuthorization = (OAuth2ClientCredentialsAuthorization) authorization;
                LOGGER.fine("OAuth2 Client Credentials authorization detected");

                // Get or acquire access token (proxy is passed for token endpoint access)
                final String accessToken = getOAuth2AccessToken(castAuthorization, proxy);

                // Add Bearer token to request header
                requestBuilder.addHeader("Authorization", "Bearer " + accessToken);
                LOGGER.fine("OAuth2 Bearer token added to Authorization header");

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
                setProxyCrendentials(proxy, credentialsProvider);
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
            setProxyCrendentials(proxy, credentialsProvider);
            httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);

            // Make it preemptive
            if (proxy.hasCredentials()) {
                httpContext = createProxyAuthContext(proxy);
            }
        }

        return httpContext;
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
    private void logException(final Exception e) {
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

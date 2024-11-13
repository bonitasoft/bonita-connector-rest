/**
 * Copyright (C) 2014 BonitaSoft S.A. BonitaSoft, 32 rue Gustave Eiffel - 38000 Grenoble This
 * library is free software; you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation version 2.1 of the
 * License. This library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU Lesser General Public License for more details. You should have received a
 * copy of the GNU Lesser General Public License along with this program; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package org.bonitasoft.connectors.rest;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.net.HttpCookie;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Logger;

import javax.net.ssl.HostnameVerifier;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.ProtocolVersion;
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
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.auth.AuthSchemeBase;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.auth.DigestScheme;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.ProxyAuthenticationStrategy;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.apache.http.protocol.HttpContext;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.TrustStrategy;
import org.apache.http.util.EntityUtils;
import org.bonitasoft.connectors.rest.model.Authorization;
import org.bonitasoft.connectors.rest.model.AuthorizationType;
import org.bonitasoft.connectors.rest.model.BasicDigestAuthorization;
import org.bonitasoft.connectors.rest.model.HTTPMethod;
import org.bonitasoft.connectors.rest.model.Proxy;
import org.bonitasoft.connectors.rest.model.ProxyProtocol;
import org.bonitasoft.connectors.rest.model.Request;
import org.bonitasoft.connectors.rest.model.SSL;
import org.bonitasoft.connectors.rest.model.SSLVerifier;
import org.bonitasoft.connectors.rest.model.Store;
import org.bonitasoft.connectors.rest.model.TrustCertificateStrategy;
import org.bonitasoft.engine.api.ProcessAPI;
import org.bonitasoft.engine.bpm.document.Document;
import org.bonitasoft.engine.bpm.document.DocumentNotFoundException;
import org.bonitasoft.engine.connector.ConnectorException;
import org.bonitasoft.engine.connector.ConnectorValidationException;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/** This main class of the REST Connector implementation */
public class RESTConnector extends AbstractRESTConnectorImpl {

    /** The HTTP request builder constants. */
    private static final String HTTP_PROTOCOL = "HTTP";

    private static final int HTTP_PROTOCOL_VERSION_MAJOR = 1;
    private static final int HTTP_PROTOCOL_VERSION_MINOR = 1;

    /** The class logger */
    private static final Logger LOGGER = Logger.getLogger(RESTConnector.class.getName());
    /**
     * Forces the character encoding of the HTTP response body to the default JVM Charset if no
     * Charset is defined in the response header. If this property is not set, the ISO-8859-1 Charset
     * is used as fallback, as specified in the specification.
     */
    static final String DEFAULT_JVM_CHARSET_FALLBACK_PROPERTY = "org.bonitasoft.connectors.rest.response.fallbackToJVMCharset";

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
                || Objects.equals(getMethod(), HTTPMethod.PUT.name())) {
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
        LOGGER.fine("Follow redirect set to: " + request.isRedirect());
        request.setIgnore(getIgnoreBody());
        LOGGER.fine("Ignore body set to: " + request.isIgnore());
        for (final Object urlheader : getUrlHeaders()) {
            final List<?> urlheaderRow = (List<?>) urlheader;
            String name = urlheaderRow.get(0).toString();
            String value = urlheaderRow.get(1).toString();
            request.addHeader(name, value);
            LOGGER.fine(() -> "Add header: "
                    + urlheaderRow.get(0).toString()
                    + " set as "
                    + urlheaderRow.get(1).toString());
        }
        for (final Object urlCookie : getUrlCookies()) {
            final List<?> urlCookieRow = (List<?>) urlCookie;
            request.addCookie(urlCookieRow.get(0).toString(), urlCookieRow.get(1).toString());
            LOGGER.fine(() -> "Add cookie: "
                    + urlCookieRow.get(0).toString()
                    + " set as "
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
        }
        return request;
    }

    private void setBody(Request request) throws ConnectorException {
        String body = getBody();
        String documentBody = getDocumentBody();
        if (body != null && !body.trim().isEmpty()) {
            request.setBody(body);
            LOGGER.fine(() -> "Body set to: " + request.getBody().toString());
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

    private void parseResponse(final HttpEntity entity) throws IOException {
        boolean fallbackToDefaultCharset = Boolean
                .parseBoolean(System.getProperty(DEFAULT_JVM_CHARSET_FALLBACK_PROPERTY));
        String stringContent = EntityUtils.toString(entity, fallbackToDefaultCharset ? Charset.defaultCharset() : null);
        final String bodyResponse = stringContent != null ? stringContent.trim() : "";
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
                if (!result.containsKey(name)) {
                    result.put(name, header.getValue());
                } else {
                    String currentValue = result.get(name);
                    if (header.getValue() != null && !header.getValue().isEmpty())
                        result.put(name, currentValue + ";" + header.getValue());
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
    public void execute(final Request request) throws Exception {
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
            if (hasBody()) {
                final Serializable body = request.getBody();
                if (body != null) {
                    ContentType contentType = ContentType.create(getContentType(), Charset.forName(getCharset()));
                    requestBuilder.setEntity(
                            new ByteArrayEntity(toByteArray(body, contentType.getCharset()), contentType));
                }
            }

            final HttpContext httpContext = setAuthorizations(
                    requestConfigurationBuilder,
                    request.getAuthorization(),
                    request.getProxy(),
                    urlHost,
                    urlPort,
                    urlProtocol,
                    httpClientBuilder);

            requestBuilder.setConfig(requestConfigurationBuilder.build());
            httpClientBuilder.setDefaultRequestConfig(requestConfigurationBuilder.build());

            final HttpUriRequest httpRequest = requestBuilder.build();
            httpClient = httpClientBuilder.build();
            LOGGER.fine("Request sent.");
            final CloseableHttpResponse httpResponse = httpClient.execute(httpRequest, httpContext);
            LOGGER.fine("Response recieved.");
            final int statusCode = httpResponse.getStatusLine().getStatusCode();
            if (!statusSuccessful(statusCode)) {
                LOGGER.warning(
                        () -> String.format(
                                "%s response status is not successful: %s - %s",
                                request, statusCode, httpResponse.getStatusLine().getReasonPhrase()));
            }
            setOutputs(httpResponse, request);
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

    private boolean statusSuccessful(int statusCode) {
        return statusCode >= 200 && statusCode < 400;
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
                        new TrustStrategy() {

                            @Override
                            public boolean isTrusted(X509Certificate[] chain, String authType)
                                    throws CertificateException {
                                return Boolean.TRUE;
                            }
                        });
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
     * @throws Exception
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
     * Set the cookies to the builder based on the request cookies
     *
     * @param requestConfigurationBuilder The request builder
     * @param httpClientBuilder The request builder
     * @param list The cookies
     * @param urlHost The URL host
     */
    private void setCookies(
            final Builder requestConfigurationBuilder,
            final HttpClientBuilder httpClientBuilder,
            final List<HttpCookie> list,
            final String urlHost) {
        final CookieStore cookieStore = new BasicCookieStore();
        final List<HttpCookie> cookies = list;
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
            final Authorization authorization,
            final Proxy proxy,
            final String urlHost,
            final int urlPort,
            final String urlProtocol,
            final HttpClientBuilder httpClientBuilder) {
        HttpContext httpContext = HttpClientContext.create();
        if (authorization != null) {
            if (authorization instanceof BasicDigestAuthorization) {
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
                        final BasicScheme basicScheme = new BasicScheme(ChallengeState.PROXY);
                        authenticationCache.put(new HttpHost(proxy.getHost(), proxy.getPort()), basicScheme);
                    }
                    final HttpClientContext localContext = HttpClientContext.create();
                    localContext.setAuthCache(authenticationCache);
                    httpContext = localContext;
                }
            }
        } else if (proxy != null) {
            final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
            setProxyCrendentials(proxy, credentialsProvider);
            httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);

            // Make it preemptive
            if (proxy.hasCredentials()) {
                final AuthCache authoriationCache = new BasicAuthCache();
                final BasicScheme basicScheme = new BasicScheme(ChallengeState.PROXY);
                authoriationCache.put(new HttpHost(proxy.getHost(), proxy.getPort()), basicScheme);
                final HttpClientContext localContext = HttpClientContext.create();
                localContext.setAuthCache(authoriationCache);
                httpContext = localContext;
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
     * @throws ConnectorException The connector exception for the BonitaSoft system to act from it
     */
    private void logException(final Exception e) {
        final StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(e.toString());
        for (final StackTraceElement stackTraceElement : e.getStackTrace()) {
            stringBuilder.append("\n" + stackTraceElement);
        }
        LOGGER.fine(() -> "executeBusinessLogic error: " + stringBuilder.toString());
    }
    
    @Override
    public boolean hasBody() {
        return hasBody;
    }
}

/**
 * Copyright (C) 2014 BonitaSoft S.A.
 * BonitaSoft, 32 rue Gustave Eiffel - 38000 Grenoble
 * This library is free software; you can redistribute it and/or modify it under the terms
 * of the GNU Lesser General Public License as published by the Free Software Foundation
 * version 2.1 of the License.
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 * You should have received a copy of the GNU Lesser General Public License along with this
 * program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA.
 **/

package org.bonitasoft.connectors.rest;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.HttpCookie;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import javax.net.ssl.SSLContext;

import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.ProtocolVersion;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.NTCredentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.AuthCache;
import org.apache.http.client.CookieStore;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.config.RequestConfig.Builder;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.auth.AuthSchemeBase;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.auth.DigestScheme;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.apache.http.message.BasicHeader;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;
import org.bonitasoft.connectors.rest.model.Authorization;
import org.bonitasoft.connectors.rest.model.BasicDigestAuthorization;
import org.bonitasoft.connectors.rest.model.Content;
import org.bonitasoft.connectors.rest.model.HeaderAuthorization;
import org.bonitasoft.connectors.rest.model.NtlmAuthorization;
import org.bonitasoft.connectors.rest.model.RESTCharsets;
import org.bonitasoft.connectors.rest.model.RESTCookieStore;
import org.bonitasoft.connectors.rest.model.RESTHTTPMethod;
import org.bonitasoft.connectors.rest.model.RESTKeyStore;
import org.bonitasoft.connectors.rest.model.RESTRequest;
import org.bonitasoft.connectors.rest.model.RESTResponse;
import org.bonitasoft.connectors.rest.model.SSL;
import org.bonitasoft.connectors.rest.model.SSLVerifier;
import org.bonitasoft.engine.connector.ConnectorException;
import org.bonitasoft.engine.connector.ConnectorValidationException;

/**
 * This main class of the REST Connector implementation
 */
public class RESTConnector extends AbstractRESTConnectorImpl {

    /**
     * The HTTP request builder constants.
     */
    private static final String HTTP_PROTOCOL = "HTTP";
    private static final int HTTP_PROTOCOL_VERSION_MAJOR = 1;
    private static final int HTTP_PROTOCOL_VERSION_MINOR = 1;
    private static final int CONNECTION_TIMEOUT = 60000;
    private static final String AUTHORIZATION_HEADER = "Authorization";
    
    /**
     * The class logger
     */
    private static final Logger LOGGER = Logger.getLogger(RESTConnector.class.getName());

    @Override
    public void validateInputParameters() throws ConnectorValidationException {
        super.validateInputParameters();

        LOGGER.fine("super validateInputParameters done.");

        final List<String> messages = new ArrayList<String>(0);
        if (!isStringInputValid(getUrl())) {
            messages.add(URL_INPUT_PARAMETER);
        } else {
            try {
                new URL(getUrl());
            } catch (MalformedURLException e) {
                messages.add(URL_INPUT_PARAMETER);
            }
        }

        if (!isStringInputValid(getMethod())) {
            messages.add(METHOD_INPUT_PARAMETER);
        }

        if (!isStringInputValid(getContentType())) {
            messages.add(CONTENTTYPE_INPUT_PARAMETER);
        }
        if (!isStringInputValid(getCharset())) {
            messages.add(CHARSET_INPUT_PARAMETER);
        }

        List<?> urlCookies = getUrlCookies();
        messages.addAll(manageKeyValueCouples(urlCookies, URLCOOKIES_INPUT_PARAMETER));

        List<?> urlheaders = getUrlHeaders();
        messages.addAll(manageKeyValueCouples(urlheaders, URLHEADERS_INPUT_PARAMETER));

        if (!messages.isEmpty()) {
            LOGGER.fine("validateInputParameters error: " + messages.toString());
            throw new ConnectorValidationException(this, messages);
        }
    }

    /**
     * Is the String input valid?
     * @param value The value to be checked
     * @return If the String input is valid or not
     */
    private boolean isStringInputValid(final String value) {
        return value != null && !value.isEmpty();
    }

    /**
     * Validate the key value couples
     * @param keyValueCouples The key value couples from the input
     * @param inputName The input name where the key value couples are from
     * @return The error messages if any or empty list otherwise
     */
    private static List<String> manageKeyValueCouples(final List<?> keyValueCouples, final String inputName) {
        List<String> messages = new ArrayList<String>();
        if (keyValueCouples == null) {
            return messages;
        }
        for (Object keyValueCouple : keyValueCouples) {
            if (keyValueCouple instanceof List) {
                List<?> keyValueCoupleRow = (List<?>) keyValueCouple;
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
     * @param keyValueCoupleRow The key value couple row
     * @return If the key and the value is valid or not
     */
    private static boolean isKeyValueCoupleValid(final List<?> keyValueCoupleRow) {
        return keyValueCoupleRow.get(0) != null && !keyValueCoupleRow.get(0).toString().isEmpty() && keyValueCoupleRow.get(1) != null;
    }

    /**
     * Is the row a key value couple?
     * @param keyValueCoupleRow the list of elements stating the row
     * @return If the row is a key value couple or not
     */
    private static boolean isItAKeyValueCouple(final List<?> keyValueCoupleRow) {
        return keyValueCoupleRow.size() == 2;
    }

    @Override
    protected void executeBusinessLogic() throws ConnectorException {
        RESTRequest request = buildRequest();
        RESTResponse response = execute(request);
        LOGGER.fine("Request sent.");
        extractResponse(response);
    }

    /**
     * Build the request bean from all the inputs
     * @return The request bean
     * @throws ConnectorException exception
     */
    private RESTRequest buildRequest() throws ConnectorException {
        RESTRequest request = null;
        try {
            request = new RESTRequest();
            request.setUrl(new URL(getUrl()));
            LOGGER.fine("URL set to: " + request.getUrl().toString());
            String bodyStr = "";
            if (getBody() != null) {
                bodyStr = getBody();
            }
            Content content = new Content();
            content.setContentType(getContentType());
            content.setCharset(RESTCharsets.getRESTCharsetsFromValue(getCharset()));
            request.setContent(content);
            request.setBody(bodyStr);
            LOGGER.fine("Body set to: " + request.getBody().toString());
            request.setRestMethod(RESTHTTPMethod.getRESTHTTPMethodFromValue(getMethod()));
            LOGGER.fine("Method set to: " + request.getRestMethod().toString());
            request.setRedirect(!getDoNotFollowRedirect());
            LOGGER.fine("Follow redirect set to: " + request.isRedirect());
            request.setIgnore(getIgnoreBody());
            LOGGER.fine("Ignore body set to: " + request.isIgnore());
            for (Object urlheader : getUrlHeaders()) {
                List<?> urlheaderRow = (List<?>) urlheader;
                request.addHeader(urlheaderRow.get(0).toString(), urlheaderRow.get(1).toString());
                LOGGER.fine("Add header: " + urlheaderRow.get(0).toString() + " set as " + urlheaderRow.get(1).toString());
            }
            for (Object urlCookie : getUrlCookies()) {
                List<?> urlCookieRow = (List<?>) urlCookie;
                request.addCookie(urlCookieRow.get(0).toString(), urlCookieRow.get(1).toString());
                LOGGER.fine("Add cookie: " + urlCookieRow.get(0).toString() + " set as " + urlCookieRow.get(1).toString());
            }

            if (isSSLSet()) {
                request.setSsl(buildSSL());
                LOGGER.fine("Add the SSL options");
            }

            if (isBasicAuthSet()) {
                LOGGER.fine("Add basic auth");
                request.setAuthorization(buildBasicAuthorization());
            } else if (isDigestAuthSet()) {
                LOGGER.fine("Add digest auth");
                request.setAuthorization(buildDigestAuthorization());
            } else if (isNTLMAuthSet()) {
                LOGGER.fine("Add NTLM auth");
                request.setAuthorization(buildNtlmAuthorization());
            } else if (isOAuth2AuthSet()) {
                LOGGER.fine("Add Token auth");
                request.setAuthorization(buildHeaderAuthorization());
            }
        } catch (Exception e) {
            logException(e);
        }
        return request;
    }

    /**
     * Is the OAuth2 Auth used?
     * @return If the OAuth2 Auth is used or not
     */
    private boolean isOAuth2AuthSet() {
        return getAuth_OAuth2_bearer_token() != null && !getAuth_OAuth2_bearer_token().isEmpty();
    }

    /**
     * Is the NTLM Auth used?
     * @return If the NTLM Auth is used or not
     */
    private boolean isNTLMAuthSet() {
        return getAuth_NTLM_username() != null && !getAuth_NTLM_username().isEmpty() 
                && getAuth_NTLM_password() != null && !getAuth_NTLM_password().isEmpty() 
                && getAuth_NTLM_workstation() != null && !getAuth_NTLM_workstation().isEmpty() 
                && getAuth_NTLM_domain() != null && !getAuth_NTLM_domain().isEmpty();
    }

    /**
     * Is the Digest Auth used?
     * @return If the Digest Auth is used or not
     */
    private boolean isDigestAuthSet() {
        return getAuth_digest_username() != null && !getAuth_digest_username().isEmpty() 
                && getAuth_digest_password() != null && !getAuth_digest_password().isEmpty() 
                && getAuth_digest_preemptive() != null;
    }

    /**
     * Is the Basic Auth used?
     * @return If the Basic Auth is used or not
     */
    private boolean isBasicAuthSet() {
        return getAuth_basic_username() != null && !getAuth_basic_username().isEmpty() 
                && getAuth_basic_password() != null && !getAuth_basic_password().isEmpty() 
                && getAuth_basic_preemptive() != null;
    }

    /**
     * Is the SSL used?
     * @return If the SSL is used or not
     */
    private boolean isSSLSet() {
        return (getTrust_store_file() != null && !getTrust_store_file().isEmpty()) 
                && (getKey_store_file() != null && !getKey_store_file().isEmpty())
                || getTrust_self_signed_certificate();
    }
    
    /**
     * Build the Token Auth bean for the request builder
     * @return The Token Auth according to the input values
     */
    private HeaderAuthorization buildHeaderAuthorization() {
        HeaderAuthorization authorization = new HeaderAuthorization();
        authorization.setValue(getAuth_OAuth2_bearer_token());
        
        return authorization;
    }
    
    /**
     * Build the NTLM Auth bean for the request builder
     * @return The NTLM Auth according to the input values
     */
    private NtlmAuthorization buildNtlmAuthorization() {
        NtlmAuthorization authorization = new NtlmAuthorization();
        authorization.setUsername(getAuth_NTLM_username());
        authorization.setPassword(getAuth_NTLM_password());
        authorization.setWorkstation(getAuth_NTLM_workstation());
        authorization.setDomain(getAuth_NTLM_domain());
        
        return authorization;
    }
    
    
    /**
     * Build the Digest Auth bean for the request builder
     * @return The Digest Auth according to the input values
     */
    private BasicDigestAuthorization buildDigestAuthorization() {
        BasicDigestAuthorization authorization = new BasicDigestAuthorization(false);
        authorization.setUsername(getAuth_digest_username());
        authorization.setPassword(getAuth_digest_password());
    
        if (getAuth_digest_host() != null && !getAuth_digest_host().isEmpty()) {
            authorization.setHost(getAuth_digest_host());
        }
        if (getAuth_digest_realm() != null && !getAuth_digest_realm().isEmpty()) {
            authorization.setRealm(getAuth_digest_realm());
        }
        authorization.setPreemptive(getAuth_digest_preemptive());
        
        return authorization;
    }
    
    /**
     * Build the Basic Auth bean for the request builder
     * @return The Basic Auth according to the input values
     */
    private BasicDigestAuthorization buildBasicAuthorization() {
        BasicDigestAuthorization authorization = new BasicDigestAuthorization(true);
        authorization.setUsername(getAuth_basic_username());
        authorization.setPassword(getAuth_basic_password());
    
        if (getAuth_basic_host() != null && !getAuth_basic_host().isEmpty()) {
            authorization.setHost(getAuth_basic_host());
        }
        if (getAuth_basic_realm() != null && !getAuth_basic_realm().isEmpty()) {
            authorization.setRealm(getAuth_basic_realm());
        }
        authorization.setPreemptive(getAuth_basic_preemptive());
        
        return authorization;
    }
    
    /**
     * Build the SSL Req bean for the request builder
     * @return The SSL Req according to the input values
     */
    private SSL buildSSL() {
        SSL ssl = new SSL();
        ssl.setSslVerifier(SSLVerifier.valueOf(getHostname_verifier()));
        ssl.setUseSelfSignedCertificate(getTrust_self_signed_certificate());
    
        RESTKeyStore trustStore = new RESTKeyStore();
        trustStore.setFile(new File(getTrust_store_file()));
        trustStore.setPassword(getTrust_store_password());
        ssl.setTrustStore(trustStore);
    
        RESTKeyStore keyStore = new RESTKeyStore();
        keyStore.setFile(new File(getKey_store_file()));
        keyStore.setPassword(getKey_store_password());
        ssl.setKeyStore(keyStore);
        
        return ssl;
    }

    /**
     * Extracts the response of the HTTP transaction
     * @param response The response of the sent request
     */
    private void extractResponse(final RESTResponse response) {
        RESTResult result = new RESTResult();
        if (response != null) {
            String entity = "empty";
            if (response.getBody() != null && response.getBody().length() > 0) {
                entity = response.getBody().trim();
                LOGGER.fine("Response entity extracted and not empty.");
            }
            result.setEntity(entity);
            List<RESTResultKeyValueMap> headers = new ArrayList<RESTResultKeyValueMap>();
            List<RESTResultKeyValueMap> returnedHeaders = response.getHeaders();
            for (int i = 0; i < returnedHeaders.size(); i++) {
                List<String> returnedValues = returnedHeaders.get(i).getValue();
                RESTResultKeyValueMap mapping = new RESTResultKeyValueMap();
                List<String> mappingValues = new ArrayList<String>();
                mappingValues.addAll(returnedValues);
                mapping.setKey(returnedHeaders.get(i).getKey());
                mapping.setValue(mappingValues);
                headers.add(mapping);
                LOGGER.fine("Header value extracted.");
            }
            result.setHeader(headers);
            result.setTime(response.getExecutionTime());
            LOGGER.fine("Time extracted.");
            result.setStatusCode(response.getStatusCode());
            LOGGER.fine("Status code extracted.");
            result.setStatusLine(response.getMessage());
            LOGGER.fine("Status line extracted.");
        } else {
            LOGGER.fine("Response is null.");
        }
        setResult(result);
        LOGGER.fine("Result set.");
    }

    /**
     * Execute a given request
     * @param request The request to execute
     * @return The response of the executed request
     * @throws ConnectorException The connector exception for the BonitaSoft system to act from it
     */
    public static RESTResponse execute(final RESTRequest request) throws ConnectorException {
        CloseableHttpClient httpClient = null;

        try {
            final URL url = request.getUrl();
            final String urlHost = url.getHost();
            
            final Builder requestConfigurationBuilder = RequestConfig.custom();
            requestConfigurationBuilder.setConnectionRequestTimeout(CONNECTION_TIMEOUT);
            requestConfigurationBuilder.setRedirectsEnabled(request.isRedirect());
            RequestConfig requestConfig = requestConfigurationBuilder.build();
            
            final HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
            httpClientBuilder.setRetryHandler(new DefaultHttpRequestRetryHandler(0, false));
            setSSL(request.getSsl(), httpClientBuilder);
            setCookies(requestConfigurationBuilder, httpClientBuilder, request.getCookies(), urlHost);

            final RequestBuilder requestBuilder = getRequestBuilderFromMethod(request.getRestMethod());
            requestBuilder.setVersion(new ProtocolVersion(HTTP_PROTOCOL, HTTP_PROTOCOL_VERSION_MAJOR, HTTP_PROTOCOL_VERSION_MINOR));
            int urlPort = url.getPort();
            if (url.getPort() == -1) {
                urlPort = url.getDefaultPort();
            }
            final String urlProtocol = url.getProtocol();
            final String urlStr = url.toString();
            requestBuilder.setUri(urlStr);
            setHeaders(requestBuilder, request.getHeaders());
            if (!RESTHTTPMethod.GET.equals(RESTHTTPMethod.valueOf(requestBuilder.getMethod()))) {
                String body = request.getBody();
                if (body != null) {
                    requestBuilder.setEntity(
                            new StringEntity(request.getBody(), 
                            ContentType.create(request.getContent().getContentType(), 
                            request.getContent().getCharset().getValue())));
                }
            }

            requestBuilder.setConfig(requestConfig);

            HttpContext httpContext = setAuthorization(
                    requestConfigurationBuilder, 
                    request.getAuthorization(), 
                    urlHost, 
                    urlPort, 
                    urlProtocol, 
                    httpClientBuilder, 
                    requestBuilder);

            HttpUriRequest httpRequest = requestBuilder.build();

            httpClient = httpClientBuilder.build();

            long startTime = System.currentTimeMillis();
            HttpResponse httpResponse = httpClient.execute(httpRequest, httpContext);
            long endTime = System.currentTimeMillis();

            RESTResponse response = new RESTResponse();
            response.setExecutionTime(endTime - startTime);
            response.setStatusCode(httpResponse.getStatusLine().getStatusCode());
            response.setMessage(httpResponse.getStatusLine().toString());

            final Header[] responseHeaders = httpResponse.getAllHeaders();
            for (Header header : responseHeaders) {
                response.addHeader(header.getName(), header.getValue());
            }

            final HttpEntity entity = httpResponse.getEntity();
            if (entity != null) {
                if (request.isIgnore()) {
                    EntityUtils.consumeQuietly(entity);
                } else {
                    InputStream inputStream = entity.getContent();
                    try {
                        StringWriter stringWriter = new StringWriter();
                        IOUtils.copy(inputStream, stringWriter);
                        if (stringWriter.toString() != null) {
                            response.setBody(stringWriter.toString());
                        }
                    } catch (IOException ex) {
                        logException(ex);
                    }
                }
            }
            
            return response;
        } catch (Exception ex) {
            logException(ex);
        } finally {
            try {
                if (httpClient != null) {
                    httpClient.close();
                }
            } catch (IOException ex) {
                logException(ex);
            }
        }

        return null;
    }

    /**
     * Set the request builder based on the request
     * @param ssl The request SSL options
     * @param httpClientBuilder The request builder
     * @throws Exception 
     */
    private static void setSSL(final SSL ssl, final HttpClientBuilder httpClientBuilder) 
            throws Exception {
        if (ssl != null) {
            KeyStore trustStore = null;
            if (ssl.getTrustStore() != null) {
                trustStore = ssl.getTrustStore().generateKeyStore();
            }
            KeyStore keyStore = null;
            if (ssl.getKeyStore() != null) {
                keyStore = ssl.getKeyStore().generateKeyStore();
            }
            String keyStorePassword = null;
            if (ssl.getKeyStore() != null) {
                keyStorePassword = ssl.getKeyStore().getPassword();
            }

            TrustStrategy trustStrategy = null;
            if (ssl.isUseSelfSignedCertificate()) {
                trustStrategy = new TrustSelfSignedStrategy();
            }

            SSLContext sslContext = new SSLContextBuilder()
            .loadKeyMaterial(keyStore, keyStorePassword.toCharArray())
            .loadTrustMaterial(trustStore, trustStrategy)
            .setSecureRandom(null)
            .useTLS()
            .build();
            
            SSLVerifier verifier = ssl.getSslVerifier();
            final X509HostnameVerifier hostnameVerifier;
            switch (verifier) {
                case BROWSER:
                    hostnameVerifier = SSLConnectionSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER;
                    break;
                case ALLOW:
                    hostnameVerifier = SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
                    break;
                case STRICT:
                    hostnameVerifier = SSLConnectionSocketFactory.STRICT_HOSTNAME_VERIFIER;
                    break;
                default:
                    hostnameVerifier = SSLConnectionSocketFactory.STRICT_HOSTNAME_VERIFIER;
                    break;
            }
            
            SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(sslContext, hostnameVerifier);
            httpClientBuilder.setSSLSocketFactory(socketFactory);
        }
    }

    /**
     * Set the cookies to the builder based on the request cookies
     * @param requestConfigurationBuilder The request builder
     * @param httpClientBuilder The request builder
     * @param list The cookies
     * @param urlHost The URL host
     */
    private static void setCookies(
            final Builder requestConfigurationBuilder, 
            final HttpClientBuilder httpClientBuilder, 
            final List<HttpCookie> list, 
            final String urlHost) {
        CookieStore cookieStore = new RESTCookieStore();
        List<HttpCookie> cookies = list;
        for (HttpCookie cookie : cookies) {
            BasicClientCookie c = new BasicClientCookie(cookie.getName(), cookie.getValue());
            c.setPath("/");
            c.setVersion(0);
            c.setDomain(urlHost);
            cookieStore.addCookie(c);
        }
        httpClientBuilder.setDefaultCookieStore(cookieStore);
        requestConfigurationBuilder.setCookieSpec(CookieSpecs.BEST_MATCH);
    }

    /**
     * Set the headers to the builder based on the request headers
     * @param requestBuilder The request builder
     * @param headerData The request headers
     */
    private static void setHeaders(final RequestBuilder requestBuilder, final List<RESTResultKeyValueMap> headerData) {
        for (RESTResultKeyValueMap aHeaderData : headerData) {
            String key = aHeaderData.getKey();
            for (String value : aHeaderData.getValue()) {
                Header header = new BasicHeader(key, value);
                requestBuilder.addHeader(header);
            }
        }
    }

    /**
     * Set the builder based on the request elements
     * @param requestConfigurationBuilder The builder to be set
     * @param authorization The authentication element of the request
     * @param urlHost The URL host of the request
     * @param urlPort The URL post of the request
     * @param urlProtocol The URL protocol of the request
     * @param httpClientBuilder The builder to be set
     * @param requestBuilder 
     * @return HTTPContext The HTTP context to be set
     */
    private static HttpContext setAuthorization(
            final Builder requestConfigurationBuilder, 
            final Authorization authorization, 
            final String urlHost, 
            final int urlPort, 
            final String urlProtocol, 
            final HttpClientBuilder httpClientBuilder, 
            final RequestBuilder requestBuilder) {
        HttpContext httpContext = null;
        if (authorization != null) {
            if (authorization instanceof BasicDigestAuthorization) {
                List<String> authPrefs = new ArrayList<>();
                if (((BasicDigestAuthorization) authorization).isBasic()) {
                    authPrefs.add(AuthSchemes.BASIC);
                } else {
                    authPrefs.add(AuthSchemes.DIGEST);
                }
                requestConfigurationBuilder.setTargetPreferredAuthSchemes(authPrefs);
                BasicDigestAuthorization castAuthorization = (BasicDigestAuthorization) authorization;
                
                String username = castAuthorization.getUsername();
                String password = new String(castAuthorization.getPassword());
                String host = castAuthorization.getHost();
                if (castAuthorization.getHost() != null && castAuthorization.getHost().isEmpty()) {
                    host = urlHost;
                }
                String realm = castAuthorization.getRealm();
                if (castAuthorization.getRealm() != null && castAuthorization.getRealm().isEmpty()) {
                    realm = AuthScope.ANY_REALM;
                }

                CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
                credentialsProvider.setCredentials(
                        new AuthScope(host, urlPort, realm),
                        new UsernamePasswordCredentials(username, password));
                httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);

                if (castAuthorization.isPreemptive()) {
                    AuthCache authoriationCache = new BasicAuthCache();
                    AuthSchemeBase authorizationScheme = new DigestScheme();
                    if (castAuthorization instanceof BasicDigestAuthorization) {
                        authorizationScheme = new BasicScheme();
                    }
                    authoriationCache.put(new HttpHost(urlHost, urlPort, urlProtocol), authorizationScheme);
                    HttpClientContext localContext = HttpClientContext.create();
                    localContext.setAuthCache(authoriationCache);
                    httpContext = localContext;
                }
            } else if (authorization instanceof NtlmAuthorization) {
                List<String> authPrefs = new ArrayList<>();
                authPrefs.add(AuthSchemes.NTLM);
                requestConfigurationBuilder.setTargetPreferredAuthSchemes(authPrefs);

                NtlmAuthorization castAuthorization = (NtlmAuthorization) authorization;
                String username = castAuthorization.getUsername();
                String password = new String(castAuthorization.getPassword());

                CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
                credentialsProvider.setCredentials(
                        AuthScope.ANY,
                        new NTCredentials(username, password, castAuthorization.getWorkstation(), castAuthorization.getDomain()));
                httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);
            } else if (authorization instanceof HeaderAuthorization) {
                HeaderAuthorization castAuthorization = (HeaderAuthorization) authorization;
                final String authorizationHeader = castAuthorization.getValue();
                if (authorizationHeader != null && !authorizationHeader.isEmpty()) {
                    Header header = new BasicHeader(AUTHORIZATION_HEADER, authorizationHeader);
                    requestBuilder.addHeader(header);
                }
            }
        }
        
        return httpContext;
    }

    /**
     * Generate a request builder based on the given method
     * @param method The method
     * @return The request builder
     */
    private static RequestBuilder getRequestBuilderFromMethod(final RESTHTTPMethod method) {
        switch (method) {
            case GET:
                return RequestBuilder.get();
            case POST:
                return RequestBuilder.post();
            case PUT:
                return RequestBuilder.put();
            case DELETE:
                return RequestBuilder.delete();
            default:
                throw new IllegalStateException("Impossible to get the RequestBuilder from the \"" + method.name() + "\" name.");
        }
    }

    /**
     * Log an exception in generic way
     * @param e The exception raised
     * @throws ConnectorException The connector exception for the BonitaSoft system to act from it
     */
    private static void logException(final Exception e) throws ConnectorException {
        StringBuffer stringBuffer = new StringBuffer();
        stringBuffer.append(e.toString());
        for (StackTraceElement stackTraceElement : e.getStackTrace()) {
            stringBuffer.append("\n" + stackTraceElement);
        }
        LOGGER.fine("executeBusinessLogic error: " + stringBuffer.toString());
        throw new ConnectorException(e);
    }
}

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
import java.io.UnsupportedEncodingException;
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
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Logger;

import javax.net.ssl.SSLContext;

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
import org.apache.http.entity.AbstractHttpEntity;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.entity.mime.content.StringBody;
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
import org.bonitasoft.engine.connector.ConnectorException;
import org.bonitasoft.engine.connector.ConnectorValidationException;
import org.wiztools.commons.Charsets;
import org.wiztools.commons.MultiValueMap;
import org.wiztools.commons.StreamUtil;
import org.wiztools.commons.StringUtil;
import org.wiztools.restclient.HTTPClientUtil;
import org.wiztools.restclient.IGlobalOptions;
import org.wiztools.restclient.ServiceLocator;
import org.wiztools.restclient.bean.Auth;
import org.wiztools.restclient.bean.AuthorizationHeaderAuth;
import org.wiztools.restclient.bean.AuthorizationHeaderAuthBean;
import org.wiztools.restclient.bean.BasicAuth;
import org.wiztools.restclient.bean.BasicAuthBean;
import org.wiztools.restclient.bean.BasicDigestAuth;
import org.wiztools.restclient.bean.ContentType;
import org.wiztools.restclient.bean.ContentTypeBean;
import org.wiztools.restclient.bean.DigestAuth;
import org.wiztools.restclient.bean.DigestAuthBean;
import org.wiztools.restclient.bean.HTTPMethod;
import org.wiztools.restclient.bean.HTTPVersion;
import org.wiztools.restclient.bean.MultipartMode;
import org.wiztools.restclient.bean.NtlmAuth;
import org.wiztools.restclient.bean.NtlmAuthBean;
import org.wiztools.restclient.bean.ReqEntity;
import org.wiztools.restclient.bean.ReqEntityFilePart;
import org.wiztools.restclient.bean.ReqEntityMultipart;
import org.wiztools.restclient.bean.ReqEntityPart;
import org.wiztools.restclient.bean.ReqEntitySimple;
import org.wiztools.restclient.bean.ReqEntityStringBean;
import org.wiztools.restclient.bean.ReqEntityStringPart;
import org.wiztools.restclient.bean.Request;
import org.wiztools.restclient.bean.RequestBean;
import org.wiztools.restclient.bean.ResponseBean;
import org.wiztools.restclient.bean.SSLHostnameVerifier;
import org.wiztools.restclient.bean.SSLKeyStoreBean;
import org.wiztools.restclient.bean.SSLReq;
import org.wiztools.restclient.bean.SSLReqBean;
import org.wiztools.restclient.http.RESTClientCookieStore;
import org.wiztools.restclient.util.HttpUtil;
import org.wiztools.restclient.util.IDNUtil;

/**
 * This main class of the REST Connector implementation
 */
public class RESTConnector extends AbstractRESTConnectorImpl {

    /**
     * The Charset constants
     */
    private static final String UTF_8_STR = "UTF-8";
    private static final String UTF_16_STR = "UTF-16";
    private static final String UTF_16BE_STR = "UTF-16BE";
    private static final String UTF_16LE_STR = "UTF-16LE";
    private static final String ISO_8859_1_STR = "ISO-8859-1";
    private static final String US_ASCII_STR = "US-ASCII";

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
        RequestBean request = buildRequest();
        ResponseBean response = execute(request);
        LOGGER.fine("Request sent.");
        extractResponse(response);
    }

    /**
     * Build the request bean from all the inputs
     * @return The request bean
     * @throws ConnectorException exception
     */
    private RequestBean buildRequest() throws ConnectorException {
        RequestBean request = null;
        try {
            request = new RequestBean();
            request.setUrl(new URL(getUrl()));
            LOGGER.fine("URL set to: " + request.getUrl().toString());
            String bodyStr = "";
            if (getBody() != null) {
                bodyStr = getBody();
            }
            request.setBody(new ReqEntityStringBean(bodyStr, new ContentTypeBean(getContentType(), getCharset(getCharset()))));
            LOGGER.fine("Body set to: " + request.getBody().toString());
            request.setMethod(getHTTPMethod(getMethod()));
            LOGGER.fine("Method set to: " + request.getMethod().toString());
            request.setFollowRedirect(!getDoNotFollowRedirect());
            LOGGER.fine("Follow redirect set to: " + request.isFollowRedirect());
            request.setIgnoreResponseBody(getIgnoreBody());
            LOGGER.fine("Ignore body set to: " + request.isIgnoreResponseBody());
            for (Object urlheader : getUrlHeaders()) {
                List<?> urlheaderRow = (List<?>) urlheader;
                request.addHeader(urlheaderRow.get(0).toString(), urlheaderRow.get(1).toString());
                LOGGER.fine("Add header: " + urlheaderRow.get(0).toString() + " set as " + urlheaderRow.get(1).toString());
            }
            for (Object urlCookie : getUrlCookies()) {
                List<?> urlCookieRow = (List<?>) urlCookie;
                request.addCookie(new HttpCookie(urlCookieRow.get(0).toString(), urlCookieRow.get(1).toString()));
                LOGGER.fine("Add cookie: " + urlCookieRow.get(0).toString() + " set as " + urlCookieRow.get(1).toString());
            }

            if (isSSLSet()) {
                request.setSslReq(buildSSLReq());
                LOGGER.fine("Add the SSL options");
            }

            if (isBasicAuthSet()) {
                LOGGER.fine("Add basic auth");
                request.setAuth(buildBasicAuth());
            } else if (isDigestAuthSet()) {
                LOGGER.fine("Add digest auth");
                request.setAuth(buildDigestAuth());
            } else if (isNTLMAuthSet()) {
                LOGGER.fine("Add NTLM auth");
                request.setAuth(buildNTLMAuth());
            } else if (isOAuth2AuthSet()) {
                LOGGER.fine("Add Token auth");
                request.setAuth(buildTokenAuth());
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
    private AuthorizationHeaderAuthBean buildTokenAuth() {
        AuthorizationHeaderAuthBean auth = new AuthorizationHeaderAuthBean();
        auth.setAuthorizationHeaderValue(getAuth_OAuth2_bearer_token());
        
        return auth;
    }
    
    /**
     * Build the NTLM Auth bean for the request builder
     * @return The NTLM Auth according to the input values
     */
    private NtlmAuthBean buildNTLMAuth() {
        NtlmAuthBean auth = new NtlmAuthBean();
        auth.setUsername(getAuth_NTLM_username());
        auth.setPassword(getAuth_NTLM_password().toCharArray());
        auth.setWorkstation(getAuth_NTLM_workstation());
        auth.setDomain(getAuth_NTLM_domain());
        
        return auth;
    }
    
    
    /**
     * Build the Digest Auth bean for the request builder
     * @return The Digest Auth according to the input values
     */
    private DigestAuthBean buildDigestAuth() {
        DigestAuthBean auth = new DigestAuthBean();
        auth.setUsername(getAuth_digest_username());
        auth.setPassword(getAuth_digest_password().toCharArray());
    
        if (getAuth_digest_host() != null && !getAuth_digest_host().isEmpty()) {
            auth.setHost(getAuth_digest_host());
        }
        if (getAuth_digest_realm() != null && !getAuth_digest_realm().isEmpty()) {
            auth.setRealm(getAuth_digest_realm());
        }
        auth.setPreemptive(getAuth_digest_preemptive());
        
        return auth;
    }
    
    /**
     * Build the Basic Auth bean for the request builder
     * @return The Basic Auth according to the input values
     */
    private BasicAuthBean buildBasicAuth() {
        BasicAuthBean auth = new BasicAuthBean();
        auth.setUsername(getAuth_basic_username());
        auth.setPassword(getAuth_basic_password().toCharArray());
    
        if (getAuth_basic_host() != null && !getAuth_basic_host().isEmpty()) {
            auth.setHost(getAuth_basic_host());
        }
        if (getAuth_basic_realm() != null && !getAuth_basic_realm().isEmpty()) {
            auth.setRealm(getAuth_basic_realm());
        }
        auth.setPreemptive(getAuth_basic_preemptive());
        
        return auth;
    }
    
    /**
     * Build the SSL Req bean for the request builder
     * @return The SSL Req according to the input values
     */
    private SSLReqBean buildSSLReq() {
        SSLReqBean sslReq = new SSLReqBean();
        sslReq.setHostNameVerifier(SSLHostnameVerifier.valueOf(getHostname_verifier()));
        sslReq.setTrustSelfSignedCert(getTrust_self_signed_certificate());
    
        SSLKeyStoreBean sslTrustStore = new SSLKeyStoreBean();
        sslTrustStore.setFile(new File(getTrust_store_file()));
        sslTrustStore.setPassword(getTrust_store_password().toCharArray());
        sslReq.setTrustStore(sslTrustStore);
    
        SSLKeyStoreBean sslKeyStore = new SSLKeyStoreBean();
        sslKeyStore.setFile(new File(getKey_store_file()));
        sslKeyStore.setPassword(getKey_store_password().toCharArray());
        sslReq.setKeyStore(sslKeyStore);
        
        return sslReq;
    }

    /**
     * Extracts the response of the HTTP transaction
     * @param response The response of the sent request
     */
    private void extractResponse(final ResponseBean response) {
        RESTResult result = new RESTResult();
        if (response != null) {
            String entity = "empty";
            if (isReponseHasToBeExtracted(response)) {
                entity = new String(response.getResponseBody()).trim();
                LOGGER.fine("Response entity extracted and not empty.");
            }
            result.setEntity(entity);
            List<RESTResultKeyValueMap> header = new ArrayList<RESTResultKeyValueMap>();
            MultiValueMap<String, String> returnedHeader = response.getHeaders();
            for (String key : returnedHeader.keySet()) {
                RESTResultKeyValueMap mapping = new RESTResultKeyValueMap();
                List<String> values = new ArrayList<String>();
                Collection<String> returnedValues = returnedHeader.get(key);
                values.addAll(returnedValues);
                mapping.setKey(key);
                mapping.setValue(values);
                header.add(mapping);
                LOGGER.fine("Header value extracted.");
            }
            result.setHeader(header);
            result.setTime(response.getExecutionTime());
            LOGGER.fine("Time extracted.");
            result.setStatusCode(response.getStatusCode());
            LOGGER.fine("Status code extracted.");
            result.setStatusLine(response.getStatusLine());
            LOGGER.fine("Status line extracted.");
        } else {
            LOGGER.fine("Response is null.");
        }
        setResult(result);
        LOGGER.fine("Result set.");
    }

    /**
     * Is the response body to be extracted?
     * @param response The reponse to be checked
     * @return If the response body has to be extracted or not
     */
    private boolean isReponseHasToBeExtracted(final ResponseBean response) {
        return response.getResponseBody() != null && response.getResponseBody().length > 0;
    }

    /**
     * Get the HTTPMethod value based on a String value
     * @param input The String value
     * @return The associated HTTPMethod value
     */
    public static HTTPMethod getHTTPMethod(final String input) {
        if (input != null) {
            return HTTPMethod.valueOf(input);
        }
        return HTTPMethod.GET;
    }

    /**
     * Get the Charset value based on a String value
     * @param input The String value
     * @return The associated Charset value
     */
    public static Charset getCharset(final String input) {
        if (input != null) {
            if (UTF_8_STR.equals(input)) {
                return Charsets.UTF_8;
            }
            if (UTF_16_STR.equals(input)) {
                return Charsets.UTF_16;
            }
            if (UTF_16BE_STR.equals(input)) {
                return Charsets.UTF_16BE;
            }
            if (UTF_16LE_STR.equals(input)) {
                return Charsets.UTF_16LE;
            }
            if (ISO_8859_1_STR.equals(input)) {
                return Charsets.ISO_8859_1;
            }
            if (US_ASCII_STR.equals(input)) {
                return Charsets.US_ASCII;
            }
        }
        return Charsets.UTF_8;
    }

    /**
     * Execute a given request
     * @param request The request to execute
     * @return The response of the executed request
     * @throws ConnectorException The connector exception for the BonitaSoft system to act from it
     */
    public static ResponseBean execute(final Request request) throws ConnectorException {
        CloseableHttpClient httpClient = null;

        try {
            // Needed for specifying HTTP pre-emptive authentication:
            HttpContext httpContext = null;

            // Create all the builder objects:
            final HttpClientBuilder hcBuilder = HttpClientBuilder.create();
            final RequestConfig.Builder rcBuilder = RequestConfig.custom();
            final RequestBuilder reqBuilder = getRequestBuilderFromMethod(request.getMethod());

            // Retry handler (no-retries):
            hcBuilder.setRetryHandler(new DefaultHttpRequestRetryHandler(0, false));

            // Url:
            final URL url = IDNUtil.getIDNizedURL(request.getUrl());
            final String urlHost = url.getHost();
            int urlPort = url.getPort();
            if (url.getPort() == -1) {
                urlPort = url.getDefaultPort();
            }
            final String urlProtocol = url.getProtocol();
            final String urlStr = url.toString();
            reqBuilder.setUri(urlStr);

            // Set HTTP version:
            HTTPVersion httpVersion = request.getHttpVersion();
            ProtocolVersion protocolVersion = new ProtocolVersion("HTTP", 1, 0);
            if (httpVersion == HTTPVersion.HTTP_1_1) {
                protocolVersion = new ProtocolVersion("HTTP", 1, 1);
            }
            reqBuilder.setVersion(protocolVersion);

            // Set request timeout (default 1 minute--60000 milliseconds)
            IGlobalOptions options = ServiceLocator.getInstance(IGlobalOptions.class);
            rcBuilder.setConnectionRequestTimeout(
                    Integer.parseInt(options.getProperty("request-timeout-in-millis")));

            // HTTP Authentication
            httpContext = setAuthentication(rcBuilder, request.getAuth(), urlHost, urlPort, urlProtocol, hcBuilder, reqBuilder);

            setHeaders(reqBuilder, request.getHeaders());

            setCookies(rcBuilder, hcBuilder, request.getCookies(), urlHost);

            if (!setMethodSpecificLogic(reqBuilder, request)) {
                return null;
            }

            // SSL
            setSSL(request.getSslReq(), hcBuilder);

            // How to handle redirects:
            rcBuilder.setRedirectsEnabled(request.isFollowRedirect());

            // Now Execute:
            long startTime = System.currentTimeMillis();

            RequestConfig rc = rcBuilder.build();
            reqBuilder.setConfig(rc);
            HttpUriRequest req = reqBuilder.build();
            httpClient = hcBuilder.build();

            HttpResponse httpRes = httpClient.execute(req, httpContext);

            long endTime = System.currentTimeMillis();

            // Create response:
            ResponseBean response = new ResponseBean();

            setResponse(httpRes, response, request.isIgnoreResponseBody(), endTime - startTime);
            
            return response;
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException | KeyManagementException
                | IllegalStateException ex) {
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
     * Set the response from the request result
     * @param httpRes The response of the request
     * @param response The final result to be set
     * @param ignoreResponseBody Is the body ignored or not
     * @param executionTime Execution time of the request
     * @throws IOException exception
     * @throws ConnectorException The connector exception for the BonitaSoft system to act from it
     */
    private static void setResponse(final HttpResponse httpRes, final ResponseBean response, final boolean ignoreResponseBody, final long executionTime) 
            throws IOException, ConnectorException {
        response.setExecutionTime(executionTime);

        response.setStatusCode(httpRes.getStatusLine().getStatusCode());
        response.setStatusLine(httpRes.getStatusLine().toString());

        final Header[] responseHeaders = httpRes.getAllHeaders();
        for (Header header : responseHeaders) {
            response.addHeader(header.getName(), header.getValue());
        }

        // Response body:
        final HttpEntity entity = httpRes.getEntity();
        if (entity != null) {
            if (ignoreResponseBody) {
                EntityUtils.consumeQuietly(entity);
            } else {
                InputStream is = entity.getContent();
                try {
                    byte[] responseBody = StreamUtil.inputStream2Bytes(is);
                    if (responseBody != null) {
                        response.setResponseBody(responseBody);
                    }
                } catch (IOException ex) {
                    logException(ex);
                }
            }
        }
    }

    /**
     * Set the request builder based on the request
     * @param sslReq The request SSL options
     * @param hcBuilder The request builder
     * @throws IOException exception
     * @throws CertificateException exception
     * @throws NoSuchAlgorithmException exception
     * @throws KeyStoreException exception
     * @throws UnrecoverableKeyException exception
     * @throws KeyManagementException exception
     */
    private static void setSSL(final SSLReq sslReq, final HttpClientBuilder hcBuilder) 
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, KeyManagementException, UnrecoverableKeyException {
        // Set the hostname verifier:
        if (sslReq != null) {
            SSLHostnameVerifier verifier = sslReq.getHostNameVerifier();
            final X509HostnameVerifier hcVerifier;
            switch (verifier) {
                case STRICT:
                    hcVerifier = SSLConnectionSocketFactory.STRICT_HOSTNAME_VERIFIER;
                    break;
                case BROWSER_COMPATIBLE:
                    hcVerifier = SSLConnectionSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER;
                    break;
                case ALLOW_ALL:
                    hcVerifier = SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
                    break;
                default:
                    hcVerifier = SSLConnectionSocketFactory.STRICT_HOSTNAME_VERIFIER;
                    break;
            }

            // Register the SSL Scheme:
            KeyStore trustStore = null;
            if (sslReq.getTrustStore() != null) {
                trustStore = sslReq.getTrustStore().getKeyStore();
            }
            KeyStore keyStore = null;
            if (sslReq.getKeyStore() != null) {
                keyStore = sslReq.getKeyStore().getKeyStore();
            }
            char[] keyStorePassword = null;
            if (sslReq.getKeyStore() != null) {
                keyStorePassword = sslReq.getKeyStore().getPassword();
            }

            TrustStrategy trustStrategy = null;
            if (sslReq.isTrustSelfSignedCert()) {
                trustStrategy = new TrustSelfSignedStrategy();
            }

            SSLContext ctx = new SSLContextBuilder()
            .loadKeyMaterial(keyStore, keyStorePassword)
            .loadTrustMaterial(trustStore, trustStrategy)
            .setSecureRandom(null)
            .useTLS()
            .build();
            SSLConnectionSocketFactory sf = new SSLConnectionSocketFactory(ctx, hcVerifier);
            hcBuilder.setSSLSocketFactory(sf);
        }
    }

    /**
     * Set the request builder based on the specificities of the method of the request
     * @param reqBuilder The request builder
     * @param request The request
     * @return If everything went smoothly or not
     * @throws IOException exception
     */
    private static boolean setMethodSpecificLogic(final RequestBuilder reqBuilder, final Request request) throws IOException {
        // POST/PUT/PATCH/DELETE method specific logic
        if (HttpUtil.isEntityEnclosingMethod(reqBuilder.getMethod())) {

            // Create and set RequestEntity
            ReqEntity bean = request.getBody();
            if (bean != null) {
                try {
                    if (bean instanceof ReqEntitySimple) {
                        AbstractHttpEntity e = HTTPClientUtil.getEntity((ReqEntitySimple) bean);

                        reqBuilder.setEntity(e);
                    } else if (bean instanceof ReqEntityMultipart) {
                        ReqEntityMultipart multipart = (ReqEntityMultipart) bean;

                        MultipartEntityBuilder meb = MultipartEntityBuilder.create();

                        // Format:
                        MultipartMode mpMode = multipart.getMode();
                        switch (mpMode) {
                            case BROWSER_COMPATIBLE:
                                meb.setMode(HttpMultipartMode.BROWSER_COMPATIBLE);
                                break;
                            case RFC_6532:
                                meb.setMode(HttpMultipartMode.RFC6532);
                                break;
                            case STRICT:
                                meb.setMode(HttpMultipartMode.STRICT);
                                break;
                            default:
                                break;
                        }

                        // Parts:
                        for (ReqEntityPart part : multipart.getBody()) {
                            if (part instanceof ReqEntityStringPart) {
                                ReqEntityStringPart p = (ReqEntityStringPart) part;
                                String body = p.getPart();
                                ContentType ct = p.getContentType();
                                final StringBody sb;
                                if (ct != null) {
                                    sb = new StringBody(body, HTTPClientUtil.getContentType(ct));
                                } else {
                                    sb = new StringBody(body, org.apache.http.entity.ContentType.DEFAULT_TEXT);
                                }
                                meb.addPart(part.getName(), sb);
                            } else if (part instanceof ReqEntityFilePart) {
                                ReqEntityFilePart p = (ReqEntityFilePart) part;
                                File body = p.getPart();
                                ContentType ct = p.getContentType();
                                final FileBody fb;
                                if (ct != null) {
                                    fb = new FileBody(body, HTTPClientUtil.getContentType(ct), p.getFilename());
                                } else {
                                    fb = new FileBody(body, org.apache.http.entity.ContentType.DEFAULT_BINARY, p.getFilename());
                                }
                                meb.addPart(p.getName(), fb);
                            }
                        }

                        reqBuilder.setEntity(meb.build());
                    }

                } catch (UnsupportedEncodingException ex) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Set the cookies to the builder based on the request cookies
     * @param rcBuilder The request builder
     * @param hcBuilder The request builder
     * @param list The cookies
     * @param urlHost The URL host
     */
    private static void setCookies(final Builder rcBuilder, final HttpClientBuilder hcBuilder, final List<HttpCookie> list, final String urlHost) {
        // Set cookie policy:
        rcBuilder.setCookieSpec(CookieSpecs.BEST_MATCH);
        // Add to CookieStore:
        CookieStore store = new RESTClientCookieStore();
        List<HttpCookie> cookies = list;
        for (HttpCookie cookie : cookies) {
            BasicClientCookie c = new BasicClientCookie(
                    cookie.getName(), cookie.getValue());
            c.setVersion(0);
            c.setDomain(urlHost);
            c.setPath("/");

            store.addCookie(c);
        }
        // Attach store to client:
        hcBuilder.setDefaultCookieStore(store);
    }

    /**
     * Set the headers to the builder based on the request headers
     * @param reqBuilder The request builder
     * @param headerData The request headers
     */
    private static void setHeaders(final RequestBuilder reqBuilder, final MultiValueMap<String, String> headerData) {
        // Get request headers
        for (String key : headerData.keySet()) {
            for (String value : headerData.get(key)) {
                Header header = new BasicHeader(key, value);

                reqBuilder.addHeader(header);
            }
        }
    }

    /**
     * Set the builder based on the request elements
     * @param rcBuilder The builder to be set
     * @param auth The authentication element of the request
     * @param urlHost The URL host of the request
     * @param urlPort The URL post of the request
     * @param urlProtocol The URL protocol of the request
     * @param hcBuilder The builder to be set
     * @param reqBuilder 
     * @return HTTPContext The HTTP context to be set
     */
    private static HttpContext setAuthentication(final Builder rcBuilder, final Auth auth, final String urlHost, final int urlPort, 
            final String urlProtocol, final HttpClientBuilder hcBuilder, final RequestBuilder reqBuilder) {
        HttpContext httpContext = null;
        if (auth != null) {
            // Add auth preference:
            List<String> authPrefs = new ArrayList<>();
            if (auth instanceof BasicAuth) {
                authPrefs.add(AuthSchemes.BASIC);
            } else if (auth instanceof DigestAuth) {
                authPrefs.add(AuthSchemes.DIGEST);
            } else if (auth instanceof NtlmAuth) {
                authPrefs.add(AuthSchemes.NTLM);
            }
            rcBuilder.setTargetPreferredAuthSchemes(authPrefs);

            // BASIC & DIGEST:
            if (auth instanceof BasicAuth || auth instanceof DigestAuth) {
                BasicDigestAuth a = (BasicDigestAuth) auth;
                String uid = a.getUsername();
                String pwd = new String(a.getPassword());
                String host = a.getHost();
                if (StringUtil.isEmpty(a.getHost())) {
                    host = urlHost;
                }
                String realm = a.getRealm();
                if (StringUtil.isEmpty(a.getRealm())) {
                    realm = AuthScope.ANY_REALM;
                }

                CredentialsProvider credsProvider = new BasicCredentialsProvider();
                credsProvider.setCredentials(
                        new AuthScope(host, urlPort, realm),
                        new UsernamePasswordCredentials(uid, pwd));
                hcBuilder.setDefaultCredentialsProvider(credsProvider);

                // preemptive mode:
                if (a.isPreemptive()) {
                    AuthCache authCache = new BasicAuthCache();
                    AuthSchemeBase authScheme = new DigestScheme();
                    if (a instanceof BasicAuth) {
                        authScheme = new BasicScheme();
                    }
                    authCache.put(new HttpHost(urlHost, urlPort, urlProtocol), authScheme);
                    HttpClientContext localContext = HttpClientContext.create();
                    localContext.setAuthCache(authCache);
                    httpContext = localContext;
                }
            }

            // NTLM:
            if (auth instanceof NtlmAuth) {
                NtlmAuth a = (NtlmAuth) auth;
                String uid = a.getUsername();
                String pwd = new String(a.getPassword());

                CredentialsProvider credsProvider = new BasicCredentialsProvider();
                credsProvider.setCredentials(
                        AuthScope.ANY,
                        new NTCredentials(
                                uid, pwd, a.getWorkstation(), a.getDomain()));
                hcBuilder.setDefaultCredentialsProvider(credsProvider);
            }

            // Authorization header
            // Logic written in same place where Header is processed--a little down!
        }

        if (auth != null && auth instanceof AuthorizationHeaderAuth) {
            AuthorizationHeaderAuth a = (AuthorizationHeaderAuth) auth;
            final String authHeader = a.getAuthorizationHeaderValue();
            if (StringUtil.isNotEmpty(authHeader)) {
                Header header = new BasicHeader("Authorization", authHeader);
                reqBuilder.addHeader(header);
            }
        }
        
        return httpContext;
    }

    /**
     * Generate a request builder based on the given method
     * @param method The method
     * @return The request builder
     */
    private static RequestBuilder getRequestBuilderFromMethod(final HTTPMethod method) {
        switch (method) {
            case GET:
                return RequestBuilder.get();
            case POST:
                return RequestBuilder.post();
            case PUT:
                return RequestBuilder.put();
            case PATCH:
                return RequestBuilder.create("PATCH");
            case DELETE:
                return RequestBuilder.delete();
            case HEAD:
                return RequestBuilder.head();
            case OPTIONS:
                return RequestBuilder.options();
            case TRACE:
                return RequestBuilder.trace();
            default:
                throw new IllegalStateException("Method not defined!");
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

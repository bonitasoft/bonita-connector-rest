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

import com.github.tomakehurst.wiremock.client.MappingBuilder;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.stubbing.StubMapping;
import com.google.common.collect.Maps;
import org.apache.http.HttpStatus;
import org.apache.http.auth.AUTH;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.entity.ContentType;
import org.bonitasoft.connectors.rest.model.AuthorizationType;
import org.bonitasoft.connectors.rest.model.ProxyProtocol;
import org.bonitasoft.connectors.rest.model.SSLVerifier;
import org.bonitasoft.connectors.rest.model.TrustCertificateStrategy;
import org.bonitasoft.connectors.rest.utils.ProxyUtils;
import org.bonitasoft.engine.bpm.document.Document;
import org.bonitasoft.engine.commons.exceptions.SRetryableException;
import org.bonitasoft.engine.connector.ConnectorException;
import org.bonitasoft.engine.connector.ConnectorValidationException;
import org.bonitasoft.engine.exception.BonitaException;
import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;
import org.slf4j.bridge.SLF4JBridgeHandler;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.*;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.google.common.collect.Lists.newArrayList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.bonitasoft.connectors.rest.AbstractRESTConnectorImpl.*;
import static org.hamcrest.core.Is.isA;
import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** The class for the UTs of the REST Connector */
public class RESTConnectorTest extends AcceptanceTestBase {

    static {
        SLF4JBridgeHandler.install();
    }
    
    private static final int NB_OUTPUTS = 5;

    // WireMock
    /** All HTTP static strings used by WireMock to do tests */
    private static final String WM_CONTENT_TYPE = "Content-Type";

    private static final String WM_CHARSET = "charset";
    private static final String WM_COOKIES = "Cookie";

    // METHODS
    /** All the tested method values */
    private static final String GET = "GET";

    private static final String POST = "POST";
    private static final String PUT = "PUT";
    private static final String DELETE = "DELETE";
    private static final String HEAD = "HEAD";
    private static final String PATCH = "PATCH";
    private static final String METHOD_ERROR = "FAKE_METHOD";

    // CONTENT_TYPES
    /** All the tested content type values */
    private static final String PLAIN_TEXT = "text/plain";

    private static final String JSON = "application/json";
    private static final String CONTENT_TYPE_ERROR = "fakecontenttype";

    // CHARSETS
    /** All the tested charset values */
    private static final String UTF8 = "UTF-8";

    private static final String ISO_8859_1 = "ISO-8859-1";
    private static final String US_ASCII = "US-ASCII";
    private static final String CHARSET_ERROR = "FAKE-CHARSET";

    // COOKIES
    /** All the tested cookies values */
    private static final List<List<String>> ONE_COOKIES = new ArrayList<>();

    private static final List<List<String>> TWO_COOKIES = new ArrayList<>();
    private static final List<List<String>> COOKIES_ERROR = new ArrayList<>();

    // HEADERS
    /** All the tested headers values */
    private static final List<List<String>> ONE_HEADERS = new ArrayList<>();

    private static final List<List<String>> TWO_HEADERS = new ArrayList<>();
    private static final List<List<String>> HEADERS_ERROR = new ArrayList<>();

    // BODYS
    /** All the tested bodies values */
    private static final String EMPTY = "";

    private static final String FULL = "there is something inside";

    // SSL VERIFIERS
    /** All the tested SSL verifier values */
    private static final String STRICT = "Strict";


    private static final String USERNAME = "username";
    private static final String PASSWORD = "password";
    private static final String REALM = "realm";
    private static final String HOST = "localhost";
    // private static final String TOKEN = "token";

    // OTHER ERRORS
    /** All the tested errors */
    private static final String FAKE_URL = "fakeURL";

    /** Used to assert Exceptions */
    @Rule
    public ExpectedException thrown = ExpectedException.none();

    /** Initialize the tested values */
    @BeforeClass
    public static final void initValues() {
        final List<String> cookie1 = new ArrayList<>();
        cookie1.add("cookie1name");
        cookie1.add("cookie1value");
        ONE_COOKIES.add(cookie1);

        final List<String> cookie2 = new ArrayList<>();
        cookie2.add("cookie2name");
        cookie2.add("cookie2value");
        TWO_COOKIES.add(cookie1);
        TWO_COOKIES.add(cookie2);

        final List<String> cookie3 = new ArrayList<>();
        cookie3.add("cookie3name");
        cookie3.add("cookie3value");
        cookie3.add("cookie3extrat");
        final List<String> cookie4 = new ArrayList<>();
        cookie4.add("cookie4nameonly");
        COOKIES_ERROR.add(cookie1);
        COOKIES_ERROR.add(cookie2);
        COOKIES_ERROR.add(cookie3);
        COOKIES_ERROR.add(cookie4);

        final List<String> header1 = new ArrayList<>();
        header1.add("header1name");
        header1.add("header1value");
        ONE_HEADERS.add(header1);

        final List<String> header2 = new ArrayList<>();
        header2.add("header2name");
        header2.add("header2value");
        TWO_HEADERS.add(header1);
        TWO_HEADERS.add(header2);

        final List<String> header3 = new ArrayList<>();
        header3.add("header3name");
        header3.add("header3value");
        header3.add("header3extrat");
        final List<String> header4 = new ArrayList<>();
        header4.add("header4nameonly");
        HEADERS_ERROR.add(header1);
        HEADERS_ERROR.add(header2);
        HEADERS_ERROR.add(header3);
        HEADERS_ERROR.add(header4);
    }

    @After
    public void resetSystemProperies() throws Exception {
        System.setProperty(RESTConnector.DEFAULT_JVM_CHARSET_FALLBACK_PROPERTY, "");
    }
    
    @Test
    public void testUrlParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.URL_INPUT_PARAMETER, 1);
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateUrl());
    }
    
    @Test
    public void testMethodParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.METHOD_INPUT_PARAMETER, 1);
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateMethod());
    }
    
    @Test
    public void testContentTypeParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.CONTENTTYPE_INPUT_PARAMETER, 1);
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateContentType());
    }
    
    @Test
    public void testUrlCookiesParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.URLCOOKIES_INPUT_PARAMETER, 1);
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateUrlCookies());
    }
    
    @Test
    public void testUrlHeadersParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.URLHEADERS_INPUT_PARAMETER, 1);
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateUrlHeaders());
    }

    @Test
    public void testAddBonitaContextHeaders() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.ADD_BONITA_CONTEXT_HEADERS_INPUT_PARAMETER, 1);
       connector.setInputParameters(input);

       assertThrows(ConnectorValidationException.class , () -> connector.validateAddBonitaContextHeaders());
    }

    @Test
    public void testBonitaContextHeaders() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.BONITA_ACTIVITY_INSTANCE_ID_HEADER_INPUT_PARAMETER, null);
       input.put(RESTConnector.BONITA_PROCESS_DEFINITION_ID_HEADER_INPUT_PARAMETER, null);
       input.put(RESTConnector.BONITA_PROCESS_INSTANCE_ID_HEADER_INPUT_PARAMETER, null);
       input.put(RESTConnector.BONITA_ROOT_PROCESS_INSTANCE_ID_HEADER_INPUT_PARAMETER, null);
       input.put(RESTConnector.BONITA_TASK_ASSIGNEE_ID_HEADER_INPUT_PARAMETER, 1);
       connector.setInputParameters(input);

       assertThrows(ConnectorValidationException.class , () -> connector.validateBonitaContextHeaders());
    }

    @Test
    public void testFailOnHttp5xxParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.FAIL_ON_HTTP_5XX_INPUT_PARAMETER, 1);
       connector.setInputParameters(input);

       assertThrows(ConnectorValidationException.class , () -> connector.validateFailOnHttp5xx());
    }

    @Test
    public void testFailOnHttp4xxParameter() throws Exception {
         var connector =  new RESTConnector(false);
         Map<String, Object> input = new HashMap<>();
         input.put(RESTConnector.FAIL_ON_HTTP_4XX_INPUT_PARAMETER, 1);
         connector.setInputParameters(input);

         assertThrows(ConnectorValidationException.class , () -> connector.validateFailOnHttp4xx());
    }

    @Test
    public void testFailExceptionOnHttpErrorParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.FAILURE_EXCEPTIONS_HTTP_CODES_INPUT_PARAMETER, List.of(1));
       connector.setInputParameters(input);

       assertThrows(ConnectorValidationException.class , () -> connector.validateFailExceptionHttpCodes());
    }

    @Test
    public void testRetryOnHttp5xxParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.RETRY_ON_HTTP_5XX_INPUT_PARAMETER, 1);
       connector.setInputParameters(input);

       assertThrows(ConnectorValidationException.class , () -> connector.validateRetryOnHttp5xx());
    }

    @Test
    public void testRetryAdditionalHttpCodesParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.RETRY_ADDITIONAL_HTTP_CODES_INPUT_PARAMETER, List.of(1));
       connector.setInputParameters(input);

       assertThrows(ConnectorValidationException.class , () -> connector.validateRetryAdditionalHttpCodes());
    }

    @Test
    public void testMaximumBodyContentPrintedLogsParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.MAXIMUM_BODY_CONTENT_PRINTED_LOGS_PARAMETER, true);
       connector.setInputParameters(input);

       assertThrows(ConnectorValidationException.class , () -> connector.validateMaximumBodyContentPrintedLogs());
    }

    @Test
    public void testShowSensitiveHeaderValuesParameter() throws Exception {
        var connector =  new RESTConnector(false);
        Map<String, Object> input = new HashMap<>();
        input.put(RESTConnector.SENSITIVE_HEADERS_PRINTED_LOGS_PARAMETER, 1);
        connector.setInputParameters(input);

        assertThrows(ConnectorValidationException.class , () -> connector.validateShowSensitiveHeadersInLogs());
    }

    @Test
    public void testAutomaticProxyResolutionParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.AUTOMATIC_PROXY_RESOLUTION_PARAMETER, 1);
       connector.setInputParameters(input);

       assertThrows(ConnectorValidationException.class , () -> connector.validateAutomaticProxyResolution());
    }

    @Test
    public void testBodyParameter() throws Exception {
       var connector =  new RESTConnector(true);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.BODY_INPUT_PARAMETER, 1);
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateBody());
    }
    
    @Test
    public void testIgnoreBodyParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.IGNORE_BODY_INPUT_PARAMETER, "true");
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateIgnoreBody());
    }
    
    @Test
    public void testTLSParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.TLS_INPUT_PARAMETER, "true");
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateTLS());
    }
    
    @Test
    public void testTrustCertificateStrategyParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.TRUST_CERTIFICATE_STRATEGY_INPUT_PARAMETER, 1);
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateTrustCertificateStrategyInput());
    }
    
    @Test
    public void testTrustStoreFileParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.TRUST_STORE_FILE_INPUT_PARAMETER, 1);
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateTrustStoreFile());
    }
    
    @Test
    public void testTrustStorePasswordParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.TRUST_STORE_PASSWORD_INPUT_PARAMETER, 1);
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateTrustStorePassword());
    }
    
    @Test
    public void testKeyStoreFileParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.KEY_STORE_FILE_INPUT_PARAMETER, 1);
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateKeyStoreFile());
    }
    
    @Test
    public void testKeyStorePasswordParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.KEY_STORE_PASSWORD_INPUT_PARAMETER, 1);
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateKeyStorePassword());
    }
    
    @Test
    public void testFollowRedirectParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER, "true");
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateDoNotFollowRedirect());
    }

    @Test
    public void testHostNameVerfierParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.HOSTNAME_VERIFIER_INPUT_PARAMETER, 1);
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateHostnameVerifierInput());
    }
    
    @Test
    public void testAuthHostParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.AUTH_HOST_INPUT_PARAMETER, 1);
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateAuthHost());
    }
    
    @Test
    public void testAuthUsernameParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.AUTH_USERNAME_INPUT_PARAMETER, 1);
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateAuthUsername());
    }
    
    @Test
    public void testAuthPasswordParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.AUTH_PASSWORD_INPUT_PARAMETER, 1);
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateAuthPassword());
    }
    
    @Test
    public void testAuthPortParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.AUTH_PORT_INPUT_PARAMETER, "1");
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateAuthPort());
    }
    
    @Test
    public void testAuthPreemptiveParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.AUTH_PREEMPTIVE_INPUT_PARAMETER, "1");
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateAuthPreemptive());
    }
    
    @Test
    public void testAuthRealmParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.AUTH_REALM_INPUT_PARAMETER, 1);
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateAuthRealm());
    }
    
    @Test
    public void testCharsetParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.CHARSET_INPUT_PARAMETER, 1);
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateCharset());
    }
    
    @Test
    public void testConnectionTimeoutParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.CONNECTION_TIMEOUT_MS_PARAMETER, "1");
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateConnectionTimeoutMs());
    }
    
    @Test
    public void testSocketTimeoutParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.SOCKET_TIMEOUT_MS_PARAMETER, "1");
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateSocketTimeoutMs());
    }
    
    @Test
    public void testProxyHostParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.PROXY_HOST_INPUT_PARAMETER, 1);
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateProxyHost());
    }
    
    @Test
    public void testProxyPortParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.PROXY_PORT_INPUT_PARAMETER, "1");
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateProxyPort());
    }
    
    @Test
    public void testProxyUsernameParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.PROXY_USERNAME_INPUT_PARAMETER, 1);
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateProxyUsername());
    }
    
    @Test
    public void testProxyPasswordParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.PROXY_PASSWORD_INPUT_PARAMETER, 1);
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateProxyPassword());
    }
    
    @Test
    public void testProxyProtocolParameter() throws Exception {
       var connector =  new RESTConnector(false);
       Map<String, Object> input = new HashMap<>();
       input.put(RESTConnector.PROXY_PROTOCOL_INPUT_PARAMETER, 1);
       connector.setInputParameters(input);
       
       assertThrows(ConnectorValidationException.class , () -> connector.validateProxyProtocol());
    }
    
    
    /**
     * Build a request parameters set based on the given arguments
     *
     * @param url URL
     * @param port Port
     * @param method Method
     * @param contentType Content type
     * @param charset Charset
     * @param cookies Cookies
     * @param headers Headers
     * @param body Body content
     * @param redirect Is the redirection to be used
     * @param ignoreBody Does the response body is ignored
     * @param trustCertificateStrategy Trust self certificate
     * @param sslVerifier SSL Verifier
     * @return The set of parameters
     */
    private Map<String, Object> buildParametersSet(
            final String url,
            final String port,
            final String method,
            final String contentType,
            final String charset,
            final List<List<String>> cookies,
            final List<List<String>> headers,
            final String body,
            final Boolean redirect,
            final Boolean ignoreBody,
            final TrustCertificateStrategy trustCertificateStrategy,
            final String sslVerifier) {
        final Map<String, Object> parametersSet = new HashMap<>();
        if (url == null && port == null) {
            parametersSet.put(
                    AbstractRESTConnectorImpl.URL_INPUT_PARAMETER,
                    "http://" + LOCALHOST + ":" + wireMockServer.port() + "/");
        } else if (url != null && port == null) {
            parametersSet.put(
                    AbstractRESTConnectorImpl.URL_INPUT_PARAMETER,
                    "http://" + url + ":" + wireMockServer.port() + "/");
        } else if (url == null && port != null) {
            parametersSet.put(
                    AbstractRESTConnectorImpl.URL_INPUT_PARAMETER, "http://" + LOCALHOST + ":" + port + "/");
        } else {
            parametersSet.put(
                    AbstractRESTConnectorImpl.URL_INPUT_PARAMETER, "http://" + url + ":" + port + "/");
        }
        parametersSet.put(METHOD_INPUT_PARAMETER, method);
        parametersSet.put(AbstractRESTConnectorImpl.CONTENTTYPE_INPUT_PARAMETER, contentType);
        parametersSet.put(AbstractRESTConnectorImpl.CHARSET_INPUT_PARAMETER, charset);
        parametersSet.put(AbstractRESTConnectorImpl.URLCOOKIES_INPUT_PARAMETER, cookies);
        parametersSet.put(AbstractRESTConnectorImpl.URLHEADERS_INPUT_PARAMETER, headers);
        parametersSet.put(BODY_INPUT_PARAMETER, body);
        parametersSet.put(AbstractRESTConnectorImpl.DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER, redirect);
        parametersSet.put(AbstractRESTConnectorImpl.IGNORE_BODY_INPUT_PARAMETER, ignoreBody);
        parametersSet.put(
                AbstractRESTConnectorImpl.TRUST_CERTIFICATE_STRATEGY_INPUT_PARAMETER,
                trustCertificateStrategy.name());
        parametersSet.put(AbstractRESTConnectorImpl.HOSTNAME_VERIFIER_INPUT_PARAMETER, sslVerifier);
        return parametersSet;
    }

    /**
     * Build a request parameters set in order to test a specific URL
     *
     * @param url URL
     * @return The set of parameters
     */
    private Map<String, Object> buildURLParametersSet(final String url) {
        return buildParametersSet(
                url,
                null,
                POST,
                PLAIN_TEXT,
                UTF8,
                ONE_COOKIES,
                ONE_HEADERS,
                EMPTY,
                Boolean.FALSE,
                Boolean.FALSE,
                TrustCertificateStrategy.DEFAULT,
                STRICT);
    }

    /**
     * Build a request parameters set in order to test a specific port
     *
     * @param port Port
     * @return The set of parameters
     */
    private Map<String, Object> buildPortParametersSet(final String port) {
        return buildParametersSet(
                null,
                port,
                POST,
                PLAIN_TEXT,
                UTF8,
                ONE_COOKIES,
                ONE_HEADERS,
                EMPTY,
                Boolean.FALSE,
                Boolean.FALSE,
                TrustCertificateStrategy.DEFAULT,
                STRICT);
    }

    /**
     * Build a request parameters set in order to test a specific Method
     *
     * @param method Method
     * @return The set of parameters
     */
    private Map<String, Object> buildMethodParametersSet(final String method) {
        return buildParametersSet(
                null,
                null,
                method,
                PLAIN_TEXT,
                UTF8,
                ONE_COOKIES,
                ONE_HEADERS,
                EMPTY,
                Boolean.FALSE,
                Boolean.FALSE,
                TrustCertificateStrategy.DEFAULT,
                STRICT);
    }

    /**
     * Build a request parameters set in order to test a specific Content Type
     *
     * @param contentType Content Type
     * @return The set of parameters
     */
    private Map<String, Object> buildContentTypeParametersSet(final String contentType) {
        return buildParametersSet(
                null,
                null,
                POST,
                contentType,
                UTF8,
                ONE_COOKIES,
                ONE_HEADERS,
                EMPTY,
                Boolean.FALSE,
                Boolean.FALSE,
                TrustCertificateStrategy.DEFAULT,
                STRICT);
    }

    /**
     * Build a request parameters set in order to test a specific Charset
     *
     * @param charset Charset
     * @return The set of parameters
     */
    private Map<String, Object> buildCharsetParametersSet(final String charset) {
        return buildParametersSet(
                null,
                null,
                POST,
                PLAIN_TEXT,
                charset,
                ONE_COOKIES,
                ONE_HEADERS,
                EMPTY,
                Boolean.FALSE,
                Boolean.FALSE,
                TrustCertificateStrategy.DEFAULT,
                STRICT);
    }

    /**
     * Build a request parameters set in order to test a specific Cookies
     *
     * @param cookies Cookies
     * @return The set of parameters
     */
    private Map<String, Object> buildCookieParametersSet(final List<List<String>> cookies) {
        return buildParametersSet(
                null,
                null,
                GET,
                PLAIN_TEXT,
                UTF8,
                cookies,
                ONE_HEADERS,
                EMPTY,
                Boolean.FALSE,
                Boolean.FALSE,
                TrustCertificateStrategy.DEFAULT,
                STRICT);
    }

    /**
     * Build a request parameters set in order to test a specific headers
     *
     * @param headers Headers
     * @return The set of parameters
     */
    private Map<String, Object> buildHeaderParametersSet(final List<List<String>> headers) {
        return buildParametersSet(
                null,
                null,
                GET,
                PLAIN_TEXT,
                UTF8,
                ONE_COOKIES,
                headers,
                EMPTY,
                Boolean.FALSE,
                Boolean.FALSE,
                TrustCertificateStrategy.DEFAULT,
                STRICT);
    }

    /**
     * Build a request parameters set in order to test a specific body content
     *
     * @param body Body content
     * @return The set of parameters
     */
    private Map<String, Object> buildBodyParametersSet(final String body) {
        return buildParametersSet(
                null,
                null,
                POST,
                PLAIN_TEXT,
                UTF8,
                ONE_COOKIES,
                ONE_HEADERS,
                body,
                Boolean.FALSE,
                Boolean.FALSE,
                TrustCertificateStrategy.DEFAULT,
                STRICT);
    }

    /**
     * Build a request parameters set in order to test a specific Basic Authorization
     *
     * @param username Username
     * @param password Password
     * @param host Host
     * @param realm Realm
     * @param preemptive Preemptive
     * @return The set of parameters
     */
    private Map<String, Object> buildAuthorizationParametersSet(
            AuthorizationType type,
            final String username,
            final String password,
            final String host,
            final String realm,
            final Boolean preemptive) {
        final Map<String, Object> parametersSet = buildParametersSet(
                null,
                null,
                GET,
                PLAIN_TEXT,
                UTF8,
                ONE_COOKIES,
                ONE_HEADERS,
                EMPTY,
                Boolean.FALSE,
                Boolean.FALSE,
                TrustCertificateStrategy.DEFAULT,
                STRICT);

        parametersSet.put(
                AbstractRESTConnectorImpl.AUTH_TYPE_PARAMETER, type.name());
        parametersSet.put(AbstractRESTConnectorImpl.AUTH_USERNAME_INPUT_PARAMETER, username);
        parametersSet.put(AbstractRESTConnectorImpl.AUTH_PASSWORD_INPUT_PARAMETER, password);
        parametersSet.put(AbstractRESTConnectorImpl.AUTH_HOST_INPUT_PARAMETER, host);
        parametersSet.put(AbstractRESTConnectorImpl.AUTH_REALM_INPUT_PARAMETER, realm);
        parametersSet.put(AbstractRESTConnectorImpl.AUTH_PREEMPTIVE_INPUT_PARAMETER, preemptive);

        return parametersSet;
    }

    /**
     * Execute a connector call
     *
     * @param parameters The parameters of the connector call
     * @return The outputs of the connector
     * @throws BonitaException exception
     */
    private Map<String, Object> executeConnector(final Map<String, Object> parameters)
            throws BonitaException {
        final RESTConnector rest = new RESTConnector(Set.of("POST", "PUT", "PATCH").contains((String) parameters.get(METHOD_INPUT_PARAMETER)));
        rest.setExecutionContext(getEngineExecutionContext());
        rest.setAPIAccessor(getApiAccessor());
        rest.setInputParameters(parameters);
        rest.validateInputParameters();
        return rest.execute();
    }

    /**
     * Test the GET method
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void getMethod() throws BonitaException {
        stubFor(get(urlEqualTo("/")).willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildMethodParametersSet(GET)));
    }

    /**
     * Test the POST method
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void postMethod() throws BonitaException {
        stubFor(post(urlEqualTo("/")).willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildMethodParametersSet(POST)));
    }

    /**
     * Test the PUT method
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void putMethod() throws BonitaException {
        stubFor(put(urlEqualTo("/")).willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildMethodParametersSet(PUT)));
    }

    /**
     * Test the DELETE method
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void deleteMethod() throws BonitaException {
        stubFor(delete(urlEqualTo("/")).willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildMethodParametersSet(DELETE)));
    }

    /**
     * Test the HEAD method
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void headMethod() throws BonitaException {
        stubFor(head(urlEqualTo("/")).willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildMethodParametersSet(HEAD)));
    }

    /**
     * Test the PATCH method
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void patchMethod() throws BonitaException {
        stubFor(patch(urlEqualTo("/")).willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildMethodParametersSet(PATCH)));
    }

    @Test
    public void should_maximumBodyContentPrintedLogsParameter_be_positive_only() throws BonitaException {
        Map<String, Object> parameters = buildMethodParametersSet(HEAD);
        parameters.put(MAXIMUM_BODY_CONTENT_PRINTED_LOGS_PARAMETER, -1);
        var connector = new RESTConnector(false);
        connector.setInputParameters(parameters);

        assertThrows(ConnectorValidationException.class,() -> connector.validateInputParameters());
    }

    @Test
    public void testProxyConfiguration() throws BonitaException, ClientProtocolException, IOException {
        Map<String, Object> parameters = buildMethodParametersSet(HEAD);
        parameters.put(RESTConnector.PROXY_HOST_INPUT_PARAMETER, "proxy.host");
        parameters.put(RESTConnector.PROXY_PORT_INPUT_PARAMETER, 8888);
        parameters.put(RESTConnector.PROXY_PROTOCOL_INPUT_PARAMETER, "http");
        parameters.put(RESTConnector.PROXY_USERNAME_INPUT_PARAMETER, "hello");
        parameters.put(RESTConnector.PROXY_PASSWORD_INPUT_PARAMETER, "world");
        var connector = new RESTConnector(false);
        connector.setInputParameters(parameters);

        var proxy = connector.buildProxy();

        assertEquals("proxy.host", proxy.getHost());
        assertEquals((Integer) 8888, proxy.getPort());
        assertEquals(ProxyProtocol.HTTP, proxy.getProtocol());
        assertEquals("hello", proxy.getUsername());
        assertEquals("world", proxy.getPassword());
    }

    @Test
    public void testAutomaticProxyConfiguration() throws BonitaException, ClientProtocolException, IOException {
        System.setProperty(ProxyUtils.HTTP_PROXY_HOST, "my-http-proxy");
        System.setProperty(ProxyUtils.HTTP_PROXY_PORT, "8080");

        Map<String, Object> parameters = buildURLParametersSet("http://www.host1.com");
        parameters.put(RESTConnector.AUTOMATIC_PROXY_RESOLUTION_PARAMETER, true);
        var connector = new RESTConnector(false);
        connector.setInputParameters(parameters);

        var proxy = connector.buildProxy();

        assertEquals("my-http-proxy", proxy.getHost());
        assertEquals((Integer) 8080, proxy.getPort());
        assertEquals(ProxyProtocol.HTTP, proxy.getProtocol());
    }

    @Test
    public void testSslConfiguration() throws BonitaException, ClientProtocolException, IOException {
        Map<String, Object> parameters = buildMethodParametersSet(HEAD);
        parameters.put(RESTConnector.TRUST_CERTIFICATE_STRATEGY_INPUT_PARAMETER,
                TrustCertificateStrategy.TRUST_ALL.name());
        parameters.put(RESTConnector.TRUST_STORE_FILE_INPUT_PARAMETER, "/store/path");
        parameters.put(RESTConnector.TRUST_STORE_PASSWORD_INPUT_PARAMETER, "pass");
        parameters.put(RESTConnector.HOSTNAME_VERIFIER_INPUT_PARAMETER, SSLVerifier.STRICT.name());
        parameters.put(RESTConnector.KEY_STORE_FILE_INPUT_PARAMETER, "/key/path");
        parameters.put(RESTConnector.KEY_STORE_PASSWORD_INPUT_PARAMETER, "word");
        var connector = new RESTConnector(false);
        connector.setInputParameters(parameters);

        var ssl = connector.buildSSL();

        assertNotNull(ssl.getKeyStore());
        assertEquals(Paths.get("/key/path"), ssl.getKeyStore().getFile().toPath());
        assertEquals("word", ssl.getKeyStore().getPassword());
        assertEquals(SSLVerifier.STRICT, ssl.getSslVerifier());
        assertEquals(TrustCertificateStrategy.TRUST_ALL, ssl.getTrustCertificateStrategy());
        assertNotNull(ssl.getTrustStore());
        assertEquals(Paths.get("/store/path"), ssl.getTrustStore().getFile().toPath());
        assertEquals("pass", ssl.getTrustStore().getPassword());
    }

    @Test
    public void testDigestAuthorizationConfiguration() throws BonitaException, ClientProtocolException, IOException {
        Map<String, Object> parameters = buildMethodParametersSet(HEAD);
        parameters.put(RESTConnector.AUTH_HOST_INPUT_PARAMETER, "http://auth.host");
        parameters.put(RESTConnector.AUTH_USERNAME_INPUT_PARAMETER, "john");
        parameters.put(RESTConnector.AUTH_PASSWORD_INPUT_PARAMETER, "pass");
        parameters.put(RESTConnector.AUTH_PORT_INPUT_PARAMETER, 443);
        parameters.put(RESTConnector.AUTH_REALM_INPUT_PARAMETER, "realm");
        var connector = new RESTConnector(false);
        connector.setInputParameters(parameters);

        var digetAuthorization = connector.buildDigestAuthorization();

        assertEquals("http://auth.host", digetAuthorization.getHost());
        assertEquals("john", digetAuthorization.getUsername());
        assertEquals("pass", digetAuthorization.getPassword());
        assertEquals((Integer) 443, digetAuthorization.getPort());
        assertEquals("realm", digetAuthorization.getRealm());
        assertTrue(digetAuthorization.isPreemptive());
        assertFalse(digetAuthorization.isBasic());
    }

    /**
     * Test the FAKE method
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void fakeMethod() throws BonitaException {
        thrown.expect(BonitaException.class);
        thrown.expectMessage(
                "java.lang.IllegalArgumentException: No enum constant org.bonitasoft.connectors.rest.model.HTTPMethod.FAKE_METHOD");

        checkResultIsPresent(executeConnector(buildMethodParametersSet(METHOD_ERROR)));
    }

    /**
     * Test the plain text content type
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void plainTextContentType() throws BonitaException {
        stubFor(
                post(urlEqualTo("/"))
                        .withHeader(WM_CONTENT_TYPE, equalTo(PLAIN_TEXT + "; " + WM_CHARSET + "=" + UTF8))
                        .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildContentTypeParametersSet(PLAIN_TEXT)));
    }

    /**
     * Test the json content type
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void should_retrieve_response_as_a_Map_jsonContentType() throws BonitaException {
        stubFor(
                post(urlEqualTo("/"))
                        .withHeader(WM_CONTENT_TYPE, equalTo(JSON + "; " + WM_CHARSET + "=" + UTF8))
                        .willReturn(
                                aResponse()
                                        .withStatus(HttpStatus.SC_OK)
                                        .withBody("{ \"name\":\"Romain\" }")
                                        .withHeader(WM_CONTENT_TYPE, JSON)));

        final Map<String, Object> outputs = executeConnector(buildContentTypeParametersSet(JSON));
        checkResultIsPresent(outputs);
        final Map<String, Object> bodyAsMap = (Map<String, Object>) outputs
                .get(AbstractRESTConnectorImpl.BODY_AS_OBJECT_OUTPUT_PARAMETER);
        assertNotNull(bodyAsMap);
        assertEquals("Romain", bodyAsMap.get("name"));
    }

    /**
     * Test the json content type with wrong content
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void should_not_raise_exception_on_json_parsing_error() throws BonitaException {
        stubFor(
                post(urlEqualTo("/"))
                        .withHeader(WM_CONTENT_TYPE, equalTo(JSON + "; " + WM_CHARSET + "=" + UTF8))
                        .willReturn(
                                aResponse()
                                        .withStatus(HttpStatus.SC_OK)
                                        .withBody("{ this is not valid json ! }")
                                        .withHeader(WM_CONTENT_TYPE, JSON)));

        final Map<String, Object> outputs = executeConnector(buildContentTypeParametersSet(JSON));
        checkResultIsPresent(outputs);
        final Map<String, Object> bodyAsMap = (Map<String, Object>) outputs
                .get(AbstractRESTConnectorImpl.BODY_AS_OBJECT_OUTPUT_PARAMETER);
        assertNotNull(bodyAsMap);
        assertEquals(0, bodyAsMap.size());
    }

    /**
     * Test the json simple string value
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void json_simple_string_value_should_return_string_object() throws BonitaException {
        stubFor(
                post(urlEqualTo("/"))
                        .withHeader(WM_CONTENT_TYPE, equalTo(JSON + "; " + WM_CHARSET + "=" + UTF8))
                        .willReturn(
                                aResponse()
                                        .withStatus(HttpStatus.SC_OK)
                                        .withBody("\"this is a string\"")
                                        .withHeader(WM_CONTENT_TYPE, JSON)));

        final Map<String, Object> outputs = executeConnector(buildContentTypeParametersSet(JSON));
        checkResultIsPresent(outputs);
        final Object bodyAsObject = outputs.get(AbstractRESTConnectorImpl.BODY_AS_OBJECT_OUTPUT_PARAMETER);
        assertNotNull(bodyAsObject);
        final String bodyAsString = (String) bodyAsObject;
        assertEquals("this is a string", bodyAsString);
    }

    /**
     * Test the json simple numeric value
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void json_simple_numeric_value_should_return_number_object() throws BonitaException {
        stubFor(
                post(urlEqualTo("/"))
                        .withHeader(WM_CONTENT_TYPE, equalTo(JSON + "; " + WM_CHARSET + "=" + UTF8))
                        .willReturn(
                                aResponse()
                                        .withStatus(HttpStatus.SC_OK)
                                        .withBody("123.45")
                                        .withHeader(WM_CONTENT_TYPE, JSON)));

        final Map<String, Object> outputs = executeConnector(buildContentTypeParametersSet(JSON));
        checkResultIsPresent(outputs);
        final Object bodyAsObject = outputs.get(AbstractRESTConnectorImpl.BODY_AS_OBJECT_OUTPUT_PARAMETER);
        assertNotNull(bodyAsObject);
        final Number bodyAsNumber = (Number) bodyAsObject;
        assertEquals(123.45, bodyAsNumber);
    }

    /**
     * Test the json simple boolean value
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void json_simple_boolean_value_should_return_boolean_object() throws BonitaException {
        stubFor(
                post(urlEqualTo("/"))
                        .withHeader(WM_CONTENT_TYPE, equalTo(JSON + "; " + WM_CHARSET + "=" + UTF8))
                        .willReturn(
                                aResponse()
                                        .withStatus(HttpStatus.SC_OK)
                                        .withBody("true")
                                        .withHeader(WM_CONTENT_TYPE, JSON)));

        final Map<String, Object> outputs = executeConnector(buildContentTypeParametersSet(JSON));
        checkResultIsPresent(outputs);
        final Object bodyAsObject = outputs.get(AbstractRESTConnectorImpl.BODY_AS_OBJECT_OUTPUT_PARAMETER);
        assertNotNull(bodyAsObject);
        final Boolean bodyAsBoolean = (Boolean) bodyAsObject;
        assertTrue(bodyAsBoolean);
    }

    /**
     * Test the json simple date value
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void json_simple_date_value_should_return_iso8601_date_string() throws BonitaException {
        stubFor(
                post(urlEqualTo("/"))
                        .withHeader(WM_CONTENT_TYPE, equalTo(JSON + "; " + WM_CHARSET + "=" + UTF8))
                        .willReturn(
                                aResponse()
                                        .withStatus(HttpStatus.SC_OK)
                                        .withBody("\"2012-04-23T18:25:43+02:00\"")
                                        .withHeader(WM_CONTENT_TYPE, JSON)));

        final Map<String, Object> outputs = executeConnector(buildContentTypeParametersSet(JSON));
        checkResultIsPresent(outputs);
        final Object bodyAsObject = outputs.get(AbstractRESTConnectorImpl.BODY_AS_OBJECT_OUTPUT_PARAMETER);
        assertNotNull(bodyAsObject);
        final Instant bodyAsInstant = OffsetDateTime.parse((String) bodyAsObject).toInstant();
        assertEquals(
                bodyAsInstant,
                OffsetDateTime.of(2012, 4, 23, 18, 25, 43, 0, ZoneOffset.ofHours(2)).toInstant());
    }

    /**
     * Test the json simple null value
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void json_simple_null_value_should_return_null() throws BonitaException {
        stubFor(
                post(urlEqualTo("/"))
                        .withHeader(WM_CONTENT_TYPE, equalTo(JSON + "; " + WM_CHARSET + "=" + UTF8))
                        .willReturn(
                                aResponse()
                                        .withStatus(HttpStatus.SC_OK)
                                        .withBody("null")
                                        .withHeader(WM_CONTENT_TYPE, JSON)));

        final Map<String, Object> outputs = executeConnector(buildContentTypeParametersSet(JSON));
        checkResultIsPresent(outputs);
        final Object bodyAsObject = outputs.get(AbstractRESTConnectorImpl.BODY_AS_OBJECT_OUTPUT_PARAMETER);
        assertNull(bodyAsObject);
    }

    @Test
    public void should_retrieve_response_as_a_List_of_Map__jsonContentType() throws BonitaException {
        stubFor(
                post(urlEqualTo("/"))
                        .withHeader(WM_CONTENT_TYPE, equalTo(JSON + "; " + WM_CHARSET + "=" + UTF8))
                        .willReturn(
                                aResponse()
                                        .withStatus(HttpStatus.SC_OK)
                                        .withBody("[{ \"name\":\"Romain\" }]")
                                        .withHeader(WM_CONTENT_TYPE, JSON)));

        final Map<String, Object> outputs = executeConnector(buildContentTypeParametersSet(JSON));
        checkResultIsPresent(outputs);
        final Object bodyAsMap = outputs.get(AbstractRESTConnectorImpl.BODY_AS_OBJECT_OUTPUT_PARAMETER);
        assertNotNull(bodyAsMap);
        assertEquals("Romain", ((Map<String, Object>) ((List) bodyAsMap).get(0)).get("name"));
    }

    @Test
    public void should_retrieve_response_as_a_List_of_string() throws BonitaException {
        stubFor(
                post(urlEqualTo("/"))
                        .withHeader(WM_CONTENT_TYPE, equalTo(JSON + "; " + WM_CHARSET + "=" + UTF8))
                        .willReturn(
                                aResponse()
                                        .withStatus(HttpStatus.SC_OK)
                                        .withBody("[\"abc\", \"def\"]")
                                        .withHeader(WM_CONTENT_TYPE, JSON)));

        final Map<String, Object> outputs = executeConnector(buildContentTypeParametersSet(JSON));
        checkResultIsPresent(outputs);
        final List<String> bodyAsList = (List<String>) outputs
                .get(AbstractRESTConnectorImpl.BODY_AS_OBJECT_OUTPUT_PARAMETER);
        assertNotNull(bodyAsList);
        assertEquals("abc", bodyAsList.get(0));
        assertEquals("def", bodyAsList.get(1));
    }

    @Test
    public void should_close_connection_when_delay_is_more_than_socket_timeout()
            throws BonitaException {
        stubFor(
                post(urlEqualTo("/"))
                        .withHeader(WM_CONTENT_TYPE, equalTo(JSON + "; " + WM_CHARSET + "=" + UTF8))
                        .willReturn(
                                aResponse()
                                        .withFixedDelay(1000)
                                        .withStatus(HttpStatus.SC_OK)
                                        .withBody("")
                                        .withHeader(WM_CONTENT_TYPE, JSON)));

        thrown.expect(ConnectorException.class);
        Map<String, Object> parameters = buildContentTypeParametersSet(JSON);
        parameters.put("socket_timeout_ms", 50);
        executeConnector(parameters);
    }

    @Test
    public void should_have_default_timeout() {
        assertTrue(new RESTConnector(false).getSocketTimeoutMs() > 0);
        assertTrue(new RESTConnector(false).getConnectionTimeoutMs() > 0);
    }

    /**
     * Test the fake content type
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void fakeContentType() throws BonitaException {
        stubFor(
                post(urlEqualTo("/"))
                        .withHeader(
                                WM_CONTENT_TYPE, equalTo(CONTENT_TYPE_ERROR + "; " + WM_CHARSET + "=" + UTF8))
                        .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildContentTypeParametersSet(CONTENT_TYPE_ERROR)));
    }

    /**
     * Test the UTF8 charset
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void utf8Charset() throws BonitaException {
        stubFor(
                post(urlEqualTo("/"))
                        .withHeader(WM_CONTENT_TYPE, equalTo(PLAIN_TEXT + "; " + WM_CHARSET + "=" + UTF8))
                        .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildCharsetParametersSet(UTF8)));
    }

    /**
     * Test the ISO-8859-1 charset
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void iso88591CharsetRequest() throws BonitaException {
        stubFor(
                post(urlEqualTo("/"))
                        .withHeader(WM_CONTENT_TYPE, equalTo(PLAIN_TEXT + "; " + WM_CHARSET + "=" + ISO_8859_1))
                        .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildCharsetParametersSet(ISO_8859_1)));
    }

    @Test
    public void iso88591CharsetResponse() throws BonitaException, UnsupportedEncodingException {
        stubFor(
                post(urlEqualTo("/"))
                        .withHeader(WM_CONTENT_TYPE, equalTo(PLAIN_TEXT + "; " + WM_CHARSET + "=" + ISO_8859_1))
                        .willReturn(
                                aResponse()
                                        .withHeader(WM_CONTENT_TYPE, PLAIN_TEXT + "; " + WM_CHARSET + "=" + ISO_8859_1)
                                        .withBody(
                                                new String("le text reçu a été encodé en ISO-8859-1")
                                                        .getBytes(ISO_8859_1))
                                        .withStatus(HttpStatus.SC_OK)));

        Map<String, Object> output = executeConnector(buildCharsetParametersSet(ISO_8859_1));
        assertEquals(
                "le text reçu a été encodé en ISO-8859-1",
                output.get(RESTConnector.BODY_AS_STRING_OUTPUT_PARAMETER));
    }

    @Test
    public void useISO88591CharsetWhenNoContentType()
            throws BonitaException, UnsupportedEncodingException {
        stubFor(
                post(urlEqualTo("/"))
                        .withHeader(WM_CONTENT_TYPE, equalTo(PLAIN_TEXT + "; " + WM_CHARSET + "=" + ISO_8859_1))
                        .willReturn(
                                aResponse()
                                        .withBody(new String("le text reçu n'a pas de header").getBytes(ISO_8859_1))
                                        .withStatus(HttpStatus.SC_OK)));

        Map<String, Object> output = executeConnector(buildCharsetParametersSet(ISO_8859_1));
        assertEquals(
                "le text reçu n'a pas de header",
                output.get(RESTConnector.BODY_AS_STRING_OUTPUT_PARAMETER));
    }

    @Test
    public void useDefaultCharsetWhenNoContentTypeAndFallbackPropertyIsSet()
            throws BonitaException, UnsupportedEncodingException {
        System.setProperty(RESTConnector.DEFAULT_JVM_CHARSET_FALLBACK_PROPERTY, "true");
        stubFor(
                post(urlEqualTo("/"))
                        .withHeader(WM_CONTENT_TYPE, equalTo(PLAIN_TEXT + "; " + WM_CHARSET + "=" + ISO_8859_1))
                        .willReturn(
                                aResponse()
                                        .withBody(
                                                new String("le text reçu a été encodé avec le charset par default")
                                                        .getBytes(Charset.defaultCharset()))
                                        .withStatus(HttpStatus.SC_OK)));

        Map<String, Object> output = executeConnector(buildCharsetParametersSet(ISO_8859_1));
        assertEquals(
                "le text reçu a été encodé avec le charset par default",
                output.get(RESTConnector.BODY_AS_STRING_OUTPUT_PARAMETER));
    }

    @Test
    public void utf8CharsetResponse() throws BonitaException, UnsupportedEncodingException {
        stubFor(
                post(urlEqualTo("/"))
                        .withHeader(WM_CONTENT_TYPE, equalTo(PLAIN_TEXT + "; " + WM_CHARSET + "=" + UTF8))
                        .willReturn(
                                aResponse()
                                        .withHeader(WM_CONTENT_TYPE, PLAIN_TEXT + "; " + WM_CHARSET + "=" + UTF8)
                                        .withBody(new String("le text reçu a été encodé en UTF8").getBytes(UTF8))
                                        .withStatus(HttpStatus.SC_OK)));

        Map<String, Object> output = executeConnector(buildCharsetParametersSet(UTF8));
        assertEquals(
                "le text reçu a été encodé en UTF8",
                output.get(RESTConnector.BODY_AS_STRING_OUTPUT_PARAMETER));
    }

    /**
     * Test the US ASCII charset
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void usASCIICharset() throws BonitaException {
        stubFor(
                post(urlEqualTo("/"))
                        .withHeader(WM_CONTENT_TYPE, equalTo(PLAIN_TEXT + "; " + WM_CHARSET + "=" + US_ASCII))
                        .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildCharsetParametersSet(US_ASCII)));
    }

    /**
     * Test the FAKE charset
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void fakeCharset() throws BonitaException {
        thrown.expect(BonitaException.class);
        thrown.expectMessage("java.nio.charset.UnsupportedCharsetException: FAKE-CHARSET");

        checkResultIsPresent(executeConnector(buildCharsetParametersSet(CHARSET_ERROR)));
    }

    /**
     * Test one value cookie
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void oneValueCookie() throws BonitaException {
        stubFor(
                get(urlEqualTo("/"))
                        .withHeader(WM_COOKIES, equalTo(generateCookieSet(ONE_COOKIES)))
                        .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildCookieParametersSet(ONE_COOKIES)));
    }

    /**
     * Test two values cookie
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void twoValuesCookie() throws BonitaException {
        stubFor(
                get(urlEqualTo("/"))
                        .withHeader(WM_COOKIES, equalTo(generateCookieSet(TWO_COOKIES)))
                        .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildCookieParametersSet(TWO_COOKIES)));
    }

    /**
     * Generate the cookies string
     *
     * @param cookies The cookies values
     * @return The cookie string
     */
    private String generateCookieSet(final List<List<String>> cookies) {
        final StringBuffer strBuffer = new StringBuffer();

        if (!cookies.isEmpty()) {
            strBuffer.append(cookies.get(0).get(0) + "=" + cookies.get(0).get(1));
        }
        for (int i = 1; i < cookies.size(); i++) {
            strBuffer.append("; " + cookies.get(i).get(0) + "=" + cookies.get(i).get(1));
        }

        return strBuffer.toString();
    }

    /**
     * Test one value header
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void oneValueHeader() throws BonitaException {
        final MappingBuilder mb = get(urlEqualTo("/"));
        for (int j = 0; j < ONE_HEADERS.size(); j++) {
            mb.withHeader(ONE_HEADERS.get(j).get(0), equalTo(ONE_HEADERS.get(j).get(1)));
        }
        stubFor(mb.willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildHeaderParametersSet(ONE_HEADERS)));
    }

    @Test
    public void emptyHeader() throws BonitaException {
        stubFor(get(urlEqualTo("/")).willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildHeaderParametersSet(null)));
    }

    /**
     * Test two values header
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void twoValuesHeader() throws BonitaException {
        final MappingBuilder mb = get(urlEqualTo("/"));
        for (int j = 0; j < TWO_HEADERS.size(); j++) {
            mb.withHeader(TWO_HEADERS.get(j).get(0), equalTo(TWO_HEADERS.get(j).get(1)));
        }
        stubFor(mb.willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildHeaderParametersSet(TWO_HEADERS)));
    }

    @Test
    public void should_not_add_bonitaContextHeaders() throws BonitaException {
        when(getEngineExecutionContext().getActivityInstanceId()).thenReturn(3L);
        when(getEngineExecutionContext().getProcessInstanceId()).thenReturn(2L);
        when(getEngineExecutionContext().getRootProcessInstanceId()).thenReturn(1L);
        when(getEngineExecutionContext().getProcessDefinitionId()).thenReturn(4L);
        when(getEngineExecutionContext().getTaskAssigneeId()).thenReturn(5L);

        final MappingBuilder mb = get(urlEqualTo("/"));
        mb.withHeader("X-Bonita-Activity-Instance-Id", absent());
        mb.withHeader("X-Bonita-Process-Instance-Id", absent());
        mb.withHeader("X-Bonita-Root-Process-Instance-Id", absent());
        mb.withHeader("X-Bonita-Process-Definition-Id", absent());
        mb.withHeader("X-Bonita-Task-Assignee", absent());
        stubFor(mb.willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        Map<String, Object> parameters = buildMethodParametersSet(GET);
        parameters.put(AbstractRESTConnectorImpl.ADD_BONITA_CONTEXT_HEADERS_INPUT_PARAMETER, false);
        parameters.put(AbstractRESTConnectorImpl.BONITA_ACTIVITY_INSTANCE_ID_HEADER_INPUT_PARAMETER, "X-Bonita-Activity-Instance-Id");
        parameters.put(AbstractRESTConnectorImpl.BONITA_PROCESS_INSTANCE_ID_HEADER_INPUT_PARAMETER, "X-Bonita-Process-Instance-Id");
        parameters.put(AbstractRESTConnectorImpl.BONITA_ROOT_PROCESS_INSTANCE_ID_HEADER_INPUT_PARAMETER, "X-Bonita-Root-Process-Instance-Id");
        parameters.put(AbstractRESTConnectorImpl.BONITA_PROCESS_DEFINITION_ID_HEADER_INPUT_PARAMETER, "X-Bonita-Process-Definition-Id");
        parameters.put(AbstractRESTConnectorImpl.BONITA_TASK_ASSIGNEE_ID_HEADER_INPUT_PARAMETER, "X-Bonita-Task-Assignee-Id");

        checkResultIsPresent(executeConnector(parameters));
    }

    @Test
    public void should_add_bonitaContextHeaders() throws BonitaException {
        when(getEngineExecutionContext().getActivityInstanceId()).thenReturn(3L);
        when(getEngineExecutionContext().getProcessInstanceId()).thenReturn(2L);
        when(getEngineExecutionContext().getRootProcessInstanceId()).thenReturn(1L);
        when(getEngineExecutionContext().getProcessDefinitionId()).thenReturn(4L);
        when(getEngineExecutionContext().getTaskAssigneeId()).thenReturn(5L);

        final MappingBuilder mb = get(urlEqualTo("/"));
        mb.withHeader("X-Bonita-Activity-Instance-Id", equalTo("3"));
        mb.withHeader("X-Bonita-Process-Instance-Id", equalTo("2"));
        mb.withHeader("X-Bonita-Root-Process-Instance-Id", equalTo("1"));
        mb.withHeader("X-Bonita-Process-Definition-Id", equalTo("4"));
        mb.withHeader("X-Bonita-Task-Assignee", equalTo("5"));
        stubFor(mb.willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        Map<String, Object> parameters = buildMethodParametersSet(GET);
        parameters.put(AbstractRESTConnectorImpl.ADD_BONITA_CONTEXT_HEADERS_INPUT_PARAMETER, true);
        parameters.put(AbstractRESTConnectorImpl.BONITA_ACTIVITY_INSTANCE_ID_HEADER_INPUT_PARAMETER, "X-Bonita-Activity-Instance-Id");
        parameters.put(AbstractRESTConnectorImpl.BONITA_PROCESS_INSTANCE_ID_HEADER_INPUT_PARAMETER, "X-Bonita-Process-Instance-Id");
        parameters.put(AbstractRESTConnectorImpl.BONITA_ROOT_PROCESS_INSTANCE_ID_HEADER_INPUT_PARAMETER, "X-Bonita-Root-Process-Instance-Id");
        parameters.put(AbstractRESTConnectorImpl.BONITA_PROCESS_DEFINITION_ID_HEADER_INPUT_PARAMETER, "X-Bonita-Process-Definition-Id");
        parameters.put(AbstractRESTConnectorImpl.BONITA_TASK_ASSIGNEE_ID_HEADER_INPUT_PARAMETER, "X-Bonita-Task-Assignee");

        checkResultIsPresent(executeConnector(parameters));
    }

    @Test
    public void should_add_bonitaContextHeaders_only_if_header_name_is_set() throws BonitaException {
        when(getEngineExecutionContext().getActivityInstanceId()).thenReturn(3L);

        final MappingBuilder mb = get(urlEqualTo("/"));
        mb.withHeader("X-Bonita-Activity-Instance-Id", absent());
        stubFor(mb.willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        Map<String, Object> parameters = buildMethodParametersSet(GET);
        parameters.put(AbstractRESTConnectorImpl.ADD_BONITA_CONTEXT_HEADERS_INPUT_PARAMETER, true);
        parameters.put(AbstractRESTConnectorImpl.BONITA_ACTIVITY_INSTANCE_ID_HEADER_INPUT_PARAMETER, "");
        parameters.put(AbstractRESTConnectorImpl.BONITA_PROCESS_INSTANCE_ID_HEADER_INPUT_PARAMETER, "X-Bonita-Process-Instance-Id");
        parameters.put(AbstractRESTConnectorImpl.BONITA_ROOT_PROCESS_INSTANCE_ID_HEADER_INPUT_PARAMETER, "X-Bonita-Root-Process-Instance-Id");
        parameters.put(AbstractRESTConnectorImpl.BONITA_PROCESS_DEFINITION_ID_HEADER_INPUT_PARAMETER, "X-Bonita-Process-Definition-Id");
        parameters.put(AbstractRESTConnectorImpl.BONITA_TASK_ASSIGNEE_ID_HEADER_INPUT_PARAMETER, "X-Bonita-Task-Assignee-Id");

        checkResultIsPresent(executeConnector(parameters));
    }

    @Test
    public void should_not_failOn500Error() throws BonitaException {
        final MappingBuilder mb = get(urlEqualTo("/"));
        stubFor(mb.willReturn(aResponse().withStatus(HttpStatus.SC_INTERNAL_SERVER_ERROR)));

        Map<String, Object> parameters = buildMethodParametersSet(GET);

        checkResult(executeConnector(parameters), HttpStatus.SC_INTERNAL_SERVER_ERROR);
    }

    @Test
    public void should_failOn500Error() throws BonitaException {
        final MappingBuilder mb = get(urlEqualTo("/"));
        stubFor(mb.willReturn(aResponse().withStatus(HttpStatus.SC_INTERNAL_SERVER_ERROR)));

        Map<String, Object> parameters = buildMethodParametersSet(GET);
        parameters.put(AbstractRESTConnectorImpl.FAIL_ON_HTTP_5XX_INPUT_PARAMETER, true);

        assertThrows(ConnectorException.class, () -> executeConnector(parameters));
    }

    @Test
    public void should_not_failOn404Error() throws BonitaException {
        final MappingBuilder mb = get(urlEqualTo("/"));
        stubFor(mb.willReturn(aResponse().withStatus(HttpStatus.SC_NOT_FOUND)));

        Map<String, Object> parameters = buildMethodParametersSet(GET);

        checkResult(executeConnector(parameters), HttpStatus.SC_NOT_FOUND);
    }

    @Test
    public void should_failOn404Error() throws BonitaException {
        final MappingBuilder mb = get(urlEqualTo("/"));
        stubFor(mb.willReturn(aResponse().withStatus(HttpStatus.SC_NOT_FOUND)));

        Map<String, Object> parameters = buildMethodParametersSet(GET);
        parameters.put(AbstractRESTConnectorImpl.FAIL_ON_HTTP_4XX_INPUT_PARAMETER, true);

        assertThrows(ConnectorException.class, () -> executeConnector(parameters));
    }

    @Test
    public void should_not_failOnExceptionErrorCodes() throws BonitaException {
        final MappingBuilder mb = get(urlEqualTo("/"));
        stubFor(mb.willReturn(aResponse().withStatus(HttpStatus.SC_UNSUPPORTED_MEDIA_TYPE)));

        Map<String, Object> parameters = buildMethodParametersSet(GET);
        parameters.put(AbstractRESTConnectorImpl.FAIL_ON_HTTP_4XX_INPUT_PARAMETER, true);
        parameters.put(AbstractRESTConnectorImpl.FAILURE_EXCEPTIONS_HTTP_CODES_INPUT_PARAMETER, List.of(List.of(Integer.toString(HttpStatus.SC_UNSUPPORTED_MEDIA_TYPE))));

        checkResult(executeConnector(parameters), HttpStatus.SC_UNSUPPORTED_MEDIA_TYPE);
    }

    @Test
    public void should_retry_on500Error() throws BonitaException {
        final MappingBuilder mb = get(urlEqualTo("/"));
        stubFor(mb.willReturn(aResponse().withStatus(HttpStatus.SC_INTERNAL_SERVER_ERROR)));

        Map<String, Object> parameters = buildMethodParametersSet(GET);
        parameters.put(AbstractRESTConnectorImpl.FAIL_ON_HTTP_5XX_INPUT_PARAMETER, true);
        parameters.put(AbstractRESTConnectorImpl.RETRY_ON_HTTP_5XX_INPUT_PARAMETER, true);

        assertThrows(SRetryableException.class, () -> executeConnector(parameters));
    }

    @Test
    public void should_retry_on_additionalErrorCodes() throws BonitaException {
        final MappingBuilder mb = get(urlEqualTo("/"));
        stubFor(mb.willReturn(aResponse().withStatus(HttpStatus.SC_NOT_FOUND)));

        Map<String, Object> parameters = buildMethodParametersSet(GET);
        parameters.put(AbstractRESTConnectorImpl.FAIL_ON_HTTP_4XX_INPUT_PARAMETER, true);
        parameters.put(AbstractRESTConnectorImpl.RETRY_ADDITIONAL_HTTP_CODES_INPUT_PARAMETER, List.of(List.of(Integer.toString(HttpStatus.SC_NOT_FOUND))));

        assertThrows(SRetryableException.class, () -> executeConnector(parameters));
    }

    /**
     * Test empty body
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void emptyBody() throws BonitaException {
        stubFor(
                post(urlEqualTo("/"))
                        .withRequestBody(absent())
                        .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildBodyParametersSet(EMPTY)));
    }

    @Test
    public void shouldPostWithDocumentBody() throws BonitaException {
        byte[] content = "content".getBytes();

        Document aDocument = mock(Document.class);
        when(aDocument.getContentStorageId()).thenReturn("1");
        when(processAPI.getLastDocument(Mockito.anyLong(), Mockito.eq("myDocument"))).thenReturn(aDocument);
        when(processAPI.getDocumentContent(aDocument.getContentStorageId())).thenReturn(content);

        stubFor(post(urlEqualTo("/"))
                .withRequestBody(WireMock.binaryEqualTo(content))
                .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        Map<String, Object> parameters = buildBodyParametersSet(EMPTY);
        parameters.put(METHOD_INPUT_PARAMETER, POST);
        parameters.put(BODY_INPUT_PARAMETER, null);
        parameters.put(DOCUMENT_BODY_INPUT_PARAMETER, "myDocument");

        Map<String, Object> outputs = executeConnector(parameters);

        checkResultIsPresent(outputs);
    }

    @Test
    public void shouldPutWithDocumentBody() throws BonitaException {
        byte[] content = "content".getBytes();

        Document aDocument = mock(Document.class);
        when(aDocument.getContentStorageId()).thenReturn("1");
        when(processAPI.getLastDocument(Mockito.anyLong(), Mockito.eq("myDocument"))).thenReturn(aDocument);
        when(processAPI.getDocumentContent(aDocument.getContentStorageId())).thenReturn(content);

        stubFor(put(urlEqualTo("/"))
                .withHeader(WM_CONTENT_TYPE, equalTo(
                        ContentType.APPLICATION_OCTET_STREAM.getMimeType()
                                + "; "
                                + WM_CHARSET
                                + "="
                                + UTF8))
                .withRequestBody(WireMock.binaryEqualTo(content))
                .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        Map<String, Object> parameters = buildBodyParametersSet(EMPTY);
        parameters.put(METHOD_INPUT_PARAMETER, PUT);
        parameters.put(CONTENTTYPE_INPUT_PARAMETER, "application/octet-stream");
        parameters.put(CHARSET_INPUT_PARAMETER, "UTF-8");
        parameters.put(DOCUMENT_BODY_INPUT_PARAMETER, "myDocument");
        parameters.put(BODY_INPUT_PARAMETER, null);

        Map<String, Object> outputs = executeConnector(parameters);

        checkResultIsPresent(outputs);
    }

    /**
     * Test not empty body
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void notEmptyBody() throws BonitaException {
        stubFor(
                post(urlEqualTo("/"))
                        .withRequestBody(equalTo(FULL))
                        .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildBodyParametersSet(FULL)));
    }

    /**
     * Test the basic auth with username and password
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void basicAuthWithUsernameAndPassword() throws BonitaException {
        stubFor(
                get(urlEqualTo("/"))
                        .willReturn(aResponse()
                                .withHeader(AUTH.WWW_AUTH, "Basic")
                                .withStatus(HttpStatus.SC_UNAUTHORIZED)));
        
        stubFor(
                get(urlEqualTo("/"))
                        .withBasicAuth(USERNAME, PASSWORD)
                        .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));
        checkResultIsPresent(
                executeConnector(
                        buildAuthorizationParametersSet(AuthorizationType.BASIC, USERNAME, PASSWORD, EMPTY, EMPTY, Boolean.TRUE)));
    }
    
    @Test
    public void digestAuthWithUsernameAndPassword() throws BonitaException {
        // 401 with digest challenge
        stubFor(
                get(urlEqualTo("/"))
                        .willReturn(aResponse()
                                .withHeader(AUTH.WWW_AUTH, "Digest realm=\"*\",qop=\"auth,auth-int\",nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"")
                                .withStatus(HttpStatus.SC_UNAUTHORIZED)));
        
        // http client resolving the challenge
        stubFor(
                get(urlEqualTo("/"))
                        .withHeader("Authorization", containing("Digest username=\"username\"")
                                .and(containing("realm=\"*\""))
                                .and(containing("algorithm=MD5")))
                        .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));
        
        checkResultIsPresent(
                executeConnector(
                        buildAuthorizationParametersSet(AuthorizationType.DIGEST, USERNAME, PASSWORD, EMPTY, EMPTY,  Boolean.TRUE)));
    }

    /**
     * Test the basic auth with username password and localhost
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void basicAuthWithUsernamePasswordAndLocalhost() throws BonitaException {
        stubFor(
                get(urlEqualTo("/"))
                        .willReturn(aResponse()
                                .withHeader(AUTH.WWW_AUTH, "Basic")
                                .withStatus(HttpStatus.SC_UNAUTHORIZED)));
        
        stubFor(
                get(urlEqualTo("/"))
                        .withBasicAuth(USERNAME, PASSWORD)
                        .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(
                executeConnector(
                        buildAuthorizationParametersSet(AuthorizationType.BASIC, USERNAME, PASSWORD, HOST, EMPTY, Boolean.TRUE)));
    }

    /**
     * Test the basic auth with username password and realm
     *
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void basicAuthWithUsernamePasswordAndRealm() throws BonitaException {
        stubFor(
                get(urlEqualTo("/"))
                        .willReturn(aResponse()
                                .withHeader(AUTH.WWW_AUTH, "Basic realm=realm")
                                .withStatus(HttpStatus.SC_UNAUTHORIZED)));
        
        stubFor(
                get(urlEqualTo("/"))
                        .withBasicAuth(USERNAME, PASSWORD)
                        .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(
                executeConnector(
                        buildAuthorizationParametersSet(AuthorizationType.BASIC, USERNAME, PASSWORD, EMPTY, REALM, Boolean.TRUE)));
    }

    /**
     * Test no service available
     *
     * @throws InterruptedException exception
     * @throws BonitaException
     */
    @Test
    public void noServiceAvailable() throws BonitaException {
        Map<String, Object> output = executeConnector(buildMethodParametersSet(GET));
        assertEquals(404, output.get(RESTConnector.STATUS_CODE_OUTPUT_PARAMETER));
    }

    /**
     * Test unreachable URL
     *
     * @throws InterruptedException exception
     * @throws BonitaException
     */
    @Test
    public void unreachableURL() throws BonitaException {
        thrown.expect(BonitaException.class);
        thrown.expectCause(isA(UnknownHostException.class));

        executeConnector(buildURLParametersSet(FAKE_URL));
    }

    /**
     * Test unreachable port
     *
     * @throws InterruptedException exception
     * @throws BonitaException
     */
    @Test
    public void unreachablePort() throws BonitaException {
        final String fakePort = "666";
        thrown.expect(BonitaException.class);
        thrown.expectMessage("org.apache.http.conn.HttpHostConnectException");
        thrown.expectMessage(fakePort);

        executeConnector(buildPortParametersSet(fakePort));
    }

    @Test
    public void should_remove_empty_lines_from_input_tables() throws Exception {
        final RESTConnector restConnector = new RESTConnector(false);
        final Map<String, Object> parameters = Maps.newHashMap();

        final List<List<?>> cookies = new ArrayList<>();
        cookies.add(newArrayList("key1", "value"));
        cookies.add(newArrayList("", ""));
        cookies.add(newArrayList(null, null));
        cookies.add(newArrayList());
        cookies.add(null);
        parameters.put(RESTConnector.URLCOOKIES_INPUT_PARAMETER, cookies);
        restConnector.setInputParameters(parameters);

        final List<List<?>> urlCookies = restConnector.getUrlCookies();
        assertEquals(1, urlCookies.size());
    }

    @Test
    public void should_handle_null_cookie_list() throws Exception {
        final RESTConnector restConnector = new RESTConnector(false);
        final Map<String, Object> parameters = Maps.newHashMap();
        parameters.put(RESTConnector.URLCOOKIES_INPUT_PARAMETER, null);
        restConnector.setInputParameters(parameters);

        final List<List<?>> urlCookies = restConnector.getUrlCookies();
        assertEquals(0, urlCookies.size());
    }

    @Test
    public void should_set_empty_values_in_output_parameters_map_if_response_body_is_null()
            throws BonitaException {
        stubFor(get(urlEqualTo("/")).willReturn(aResponse().withStatus(HttpStatus.SC_NO_CONTENT)));
        Map<String, Object> outputs = executeConnector(buildMethodParametersSet(GET));

        Object bodyAsObject = outputs.get("bodyAsObject");
        assertTrue(bodyAsObject instanceof Map);
        assertTrue(((Map<?, ?>) bodyAsObject).isEmpty());

        Object bodyAsString = outputs.get("bodyAsString");
        assertTrue(bodyAsString instanceof String);
        assertTrue(((String) bodyAsString).isEmpty());
    }

    @Test
    public void should_set_a_default_trust_certificate_strategy_value() throws Exception {
        Map<String, Object> parameters = buildBodyParametersSet("");
        RESTConnector restConnector = new RESTConnector(false);
        parameters.put(RESTConnector.TRUST_CERTIFICATE_STRATEGY_INPUT_PARAMETER, null);
        restConnector.setInputParameters(parameters);
        restConnector.validateInputParameters();
        assertThat(restConnector.getTrustCertificateStrategy())
                .isEqualTo(TrustCertificateStrategy.DEFAULT);

        parameters.put(RESTConnector.TRUST_CERTIFICATE_STRATEGY_INPUT_PARAMETER, " ");
        restConnector.setInputParameters(parameters);
        restConnector.validateInputParameters();
        assertThat(restConnector.getTrustCertificateStrategy())
                .isEqualTo(TrustCertificateStrategy.DEFAULT);
    }

    @Test
    public void should_return_trust_certificate_strategy_value() throws Exception {
        Map<String, Object> parameters = buildBodyParametersSet("");
        RESTConnector restConnector = new RESTConnector(false);
        parameters.put(
                RESTConnector.TRUST_CERTIFICATE_STRATEGY_INPUT_PARAMETER,
                TrustCertificateStrategy.TRUST_ALL.name());
        restConnector.setInputParameters(parameters);
        restConnector.validateInputParameters();
        assertThat(restConnector.getTrustCertificateStrategy())
                .isEqualTo(TrustCertificateStrategy.TRUST_ALL);
    }

    @Test
    public void should_throw_validation_exception_for_unknown_trust_certificate_strategy_input()
            throws Exception {
        Map<String, Object> parameters = buildBodyParametersSet("");
        parameters.put(RESTConnector.TRUST_CERTIFICATE_STRATEGY_INPUT_PARAMETER, "unknownStrategy");
        RESTConnector restConnector = new RESTConnector(false);
        restConnector.setInputParameters(parameters);
        assertThatThrownBy(() -> restConnector.validateInputParameters())
                .isInstanceOf(ConnectorValidationException.class)
                .hasMessage(
                        "'unknownStrategy' option is invalid for trust_strategy. Only one of [DEFAULT, TRUST_SELF_SIGNED, TRUST_ALL] is supported.");
    }

    @Test
    public void should_support_url_encoded_content_type() throws Exception {
        LinkedHashMap<String, String> requestBody = new LinkedHashMap<>();
        requestBody.put("name", "value1");
        requestBody.put("token", "value2");
        stubFor(
                post(urlEqualTo("/"))
                        .withHeader(
                                WM_CONTENT_TYPE,
                                equalTo(
                                        ContentType.APPLICATION_FORM_URLENCODED.getMimeType()
                                                + "; "
                                                + WM_CHARSET
                                                + "="
                                                + UTF8))
                        .withRequestBody(containing(WireMockUtil.toFormUrlEncoded(requestBody)))
                        .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        Map<String, Object> parameters = buildContentTypeParametersSet(
                ContentType.APPLICATION_FORM_URLENCODED.getMimeType());
        parameters.put(BODY_INPUT_PARAMETER, "name=value1&token=value2");
        checkResultIsPresent(executeConnector(parameters));
    }

    @Test
    public void should_not_throw_exception_when_maximumBodyContentPrintedLogsParameter_is_zero()
            throws BonitaException {
        stubFor(
                post(urlEqualTo("/"))
                        .withHeader(WM_CONTENT_TYPE, equalTo(JSON + "; " + WM_CHARSET + "=" + UTF8))
                        .willReturn(
                                aResponse()
                                        .withStatus(HttpStatus.SC_OK)
                                        .withBody("{ \"name\":\"value\" }")
                                        .withHeader(WM_CONTENT_TYPE, JSON)));

        Map<String, Object> parameters = buildContentTypeParametersSet(JSON);
        parameters.put(BODY_INPUT_PARAMETER, "{ \"name\":\"value\" }");
        parameters.put(MAXIMUM_BODY_CONTENT_PRINTED_LOGS_PARAMETER, 0);
        final Map<String, Object> outputs = executeConnector(parameters);
        checkResultIsPresent(outputs);
    }

    /**
     * Generic test: should return OK STATUS as the WireMock stub is set each time for the good
     * request shape
     *
     * @param outputs The result of the request
     */
    private void checkResultIsPresent(final Map<String, Object> outputs) {
        checkResult(outputs, HttpStatus.SC_OK);
    }

    /**
     * Generic test: should return OK STATUS as the WireMock stub is set each time for the good
     * request shape
     *
     * @param outputs The result of the request
     * @param httpStatus HTTP Status to be found as a result
     */
    private void checkResult(final Map<String, Object> outputs, final int httpStatus) {
        assertEquals(NB_OUTPUTS, outputs.size());
        assertNotNull(outputs.get(AbstractRESTConnectorImpl.STATUS_CODE_OUTPUT_PARAMETER));
        final Object statusCode = outputs.get(AbstractRESTConnectorImpl.STATUS_CODE_OUTPUT_PARAMETER);
        assertTrue(statusCode instanceof Integer);
        final Integer restStatusCode = (Integer) statusCode;
        assertEquals(httpStatus, restStatusCode.intValue());
    }

    public static class WireMockUtil {

        public static String toFormUrlEncoded(LinkedHashMap<String, String> map) {
            if (map == null) {
                return "";
            }
            StringBuilder sb = new StringBuilder();
            Iterator<String> it = map.keySet().iterator();
            while (it.hasNext()) {
                String key = it.next();
                String value = map.get(key);
                appendFormUrlEncoded(key, value, sb);
                if (it.hasNext()) {
                    sb.append('&');
                }
            }
            return sb.toString();
        }

        public static String toFormUrlEncoded(String key, String value) {
            StringBuilder sb = new StringBuilder();
            appendFormUrlEncoded(key, value, sb);
            return sb.toString();
        }

        public static void appendFormUrlEncoded(String key, String value, StringBuilder sb) {
            sb.append(key).append('=');
            if (value != null) {
                sb.append(value);
            }
        }
    }
}

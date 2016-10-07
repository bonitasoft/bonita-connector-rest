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

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.delete;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.google.common.collect.Lists.newArrayList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.http.HttpStatus;
import org.bonitasoft.connectors.rest.model.AuthorizationType;
import org.bonitasoft.engine.connector.ConnectorException;
import org.bonitasoft.engine.exception.BonitaException;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.github.tomakehurst.wiremock.client.MappingBuilder;
import com.google.common.collect.Maps;

/**
 * The class for the UTs of the REST Connector
 */
public class RESTConnectorTest extends AcceptanceTestBase {


    private static final int NB_OUTPUTS = 5;
    //WireMock
    /**
     * All HTTP static strings used by WireMock to do tests
     */
    private static final String WM_CONTENT_TYPE = "Content-Type";
    private static final String WM_CHARSET = "charset";
    private static final String WM_COOKIES = "Cookie";
    private static final String WM_AUTHORIZATION = "Authorization";

    //METHODS
    /**
     * All the tested method values
     */
    private static final String GET = "GET";
    private static final String POST = "POST";
    private static final String PUT = "PUT";
    private static final String DELETE = "DELETE";
    private static final String METHOD_ERROR = "FAKE_METHOD";

    //CONTENT_TYPES
    /**
     * All the tested content type values
     */
    private static final String PLAIN_TEXT = "text/plain";
    private static final String JSON = "application/json";
    private static final String CONTENT_TYPE_ERROR = "fakecontenttype";

    //CHARSETS
    /**
     * All the tested charset values
     */
    private static final String UTF8 = "UTF-8";
    private static final String ISO_8859_1 = "ISO-8859-1";
    private static final String US_ASCII = "US-ASCII";
    private static final String CHARSET_ERROR = "FAKE-CHARSET";

    //COOKIES
    /**
     * All the tested cookies values
     */
    private static final List<List<String>> ONE_COOKIES = new ArrayList<>();
    private static final List<List<String>> TWO_COOKIES = new ArrayList<>();
    private static final List<List<String>> COOKIES_ERROR = new ArrayList<>();

    //HEADERS
    /**
     * All the tested headers values
     */
    private static final List<List<String>> ONE_HEADERS = new ArrayList<>();
    private static final List<List<String>> TWO_HEADERS = new ArrayList<>();
    private static final List<List<String>> HEADERS_ERROR = new ArrayList<>();

    //BODYS
    /**
     * All the tested bodies values
     */
    private static final String EMPTY = "";
    private static final String FULL = "there is something inside";

    //SSL VERIFIERS
    /**
     * All the tested SSL verifier values
     */
    private static final String STRICT = "Strict";

    //AUTHORIZATIONS
    /**
     * All the tested authorization values
     */
    private static final String BASIC_RULE = "Basic";
    private static final String USERNAME = "username";
    private static final String PASSWORD = "password";
    private static final String REALM = "realm";
    private static final String HOST = "localhost";
//    private static final String TOKEN = "token";

    //OTHER ERRORS
    /**
     * All the tested errors
     */
    private static final String FAKE_URL = "fakeURL";


    /**
     * Used to assert Exceptions
     */
    @Rule
    public ExpectedException thrown = ExpectedException.none();

    /**
     * Initialize the tested values
     */
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

    /**
     * Build a request parameters set based on the given arguments
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
     * @param trust Trust self certificate
     * @param sslVerifier SSL Verifier
     * @return The set of parameters
     */
    private Map<String, Object> buildParametersSet(final String url, final String port, final String method, 
            final String contentType, final String charset, final List<List<String>> cookies, final List<List<String>> headers, 
            final String body, final Boolean redirect, final Boolean ignoreBody, final Boolean trust, final String sslVerifier) {
        final Map<String, Object> parametersSet = new HashMap<>();
        if (url == null && port == null) {
            parametersSet.put(AbstractRESTConnectorImpl.URL_INPUT_PARAMETER, "http://" + LOCALHOST + ":" + wireMockServer.port() + "/");
        } else if (url != null && port == null) {
            parametersSet.put(AbstractRESTConnectorImpl.URL_INPUT_PARAMETER, "http://" + url + ":" + wireMockServer.port() + "/");
        } else if (url == null && port != null) {
            parametersSet.put(AbstractRESTConnectorImpl.URL_INPUT_PARAMETER, "http://" + LOCALHOST + ":" + port + "/");
        } else {
            parametersSet.put(AbstractRESTConnectorImpl.URL_INPUT_PARAMETER, "http://" + url + ":" + port + "/");
        }
        parametersSet.put(AbstractRESTConnectorImpl.METHOD_INPUT_PARAMETER, method);
        parametersSet.put(AbstractRESTConnectorImpl.CONTENTTYPE_INPUT_PARAMETER, contentType);
        parametersSet.put(AbstractRESTConnectorImpl.CHARSET_INPUT_PARAMETER, charset);
        parametersSet.put(AbstractRESTConnectorImpl.URLCOOKIES_INPUT_PARAMETER, cookies);
        parametersSet.put(AbstractRESTConnectorImpl.URLHEADERS_INPUT_PARAMETER, headers);
        parametersSet.put(AbstractRESTConnectorImpl.BODY_INPUT_PARAMETER, body);
        parametersSet.put(AbstractRESTConnectorImpl.DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER, redirect);
        parametersSet.put(AbstractRESTConnectorImpl.IGNORE_BODY_INPUT_PARAMETER, ignoreBody);
        parametersSet.put(AbstractRESTConnectorImpl.TRUST_SELF_SIGNED_CERTIFICATE_INPUT_PARAMETER, trust);
        parametersSet.put(AbstractRESTConnectorImpl.HOSTNAME_VERIFIER_INPUT_PARAMETER, sslVerifier);
        return parametersSet;
    }
    
    /**
     * Build a request parameters set in order to test a specific URL
     * @param url URL
     * @return The set of parameters
     */
    private Map<String, Object> buildURLParametersSet(final String url) {
        return buildParametersSet(url, null, POST, PLAIN_TEXT, UTF8, ONE_COOKIES, ONE_HEADERS, EMPTY, Boolean.FALSE, Boolean.FALSE, Boolean.FALSE, STRICT);
    }

    /**
     * Build a request parameters set in order to test a specific port
     * @param port Port
     * @return The set of parameters
     */
    private Map<String, Object> buildPortParametersSet(final String port) {
        return buildParametersSet(null, port, POST, PLAIN_TEXT, UTF8, ONE_COOKIES, ONE_HEADERS, EMPTY, Boolean.FALSE, Boolean.FALSE, Boolean.FALSE, STRICT);
    }

    /**
     * Build a request parameters set in order to test a specific Method
     * @param method Method
     * @return The set of parameters
     */
    private Map<String, Object> buildMethodParametersSet(final String method) {
        return buildParametersSet(null, null, method, PLAIN_TEXT, UTF8, ONE_COOKIES, ONE_HEADERS, EMPTY, Boolean.FALSE, Boolean.FALSE, Boolean.FALSE, STRICT);
    }
    
    /**
     * Build a request parameters set in order to test a specific Content Type
     * @param contentType Content Type
     * @return The set of parameters
     */
    private Map<String, Object> buildContentTypeParametersSet(final String contentType) {
        return buildParametersSet(null, null, POST, contentType, UTF8, ONE_COOKIES, ONE_HEADERS, EMPTY, Boolean.FALSE, Boolean.FALSE, Boolean.FALSE, STRICT);
    }

    /**
     * Build a request parameters set in order to test a specific Charset
     * @param charset Charset
     * @return The set of parameters
     */
    private Map<String, Object> buildCharsetParametersSet(final String charset) {
        return buildParametersSet(null, null, POST, PLAIN_TEXT, charset, ONE_COOKIES, ONE_HEADERS, EMPTY, Boolean.FALSE, Boolean.FALSE, Boolean.FALSE, STRICT);
    }
    
    /**
     * Build a request parameters set in order to test a specific Cookies
     * @param cookies Cookies
     * @return The set of parameters
     */
    private Map<String, Object> buildCookieParametersSet(final List<List<String>> cookies) {
        return buildParametersSet(null, null, GET, PLAIN_TEXT, UTF8, cookies, ONE_HEADERS, EMPTY, Boolean.FALSE, Boolean.FALSE, Boolean.FALSE, STRICT);
    }
    
    /**
     * Build a request parameters set in order to test a specific headers
     * @param headers Headers
     * @return The set of parameters
     */
    private Map<String, Object> buildHeaderParametersSet(final List<List<String>> headers) {
        return buildParametersSet(null, null, GET, PLAIN_TEXT, UTF8, ONE_COOKIES, headers, EMPTY, Boolean.FALSE, Boolean.FALSE, Boolean.FALSE, STRICT);
    }

    /**
     * Build a request parameters set in order to test a specific body content
     * @param body Body content
     * @return The set of parameters
     */
    private Map<String, Object> buildBodyParametersSet(final String body) {
        return buildParametersSet(null, null, POST, PLAIN_TEXT, UTF8, ONE_COOKIES, ONE_HEADERS, body, Boolean.FALSE, Boolean.FALSE, Boolean.FALSE, STRICT);
    }
    
    /**
     * Build a request parameters set in order to test a specific Basic Authorization
     * @param username Username
     * @param password Password
     * @param host Host
     * @param realm Realm
     * @param preemptive Preemptive
     * @return The set of parameters
     */
    private Map<String, Object> buildBasicAuthorizationParametersSet(final String username, 
            final String password, final String host, final String realm, final Boolean preemptive) {
        final Map<String, Object> parametersSet = buildParametersSet(null, null, GET, PLAIN_TEXT, UTF8, 
                ONE_COOKIES, ONE_HEADERS, EMPTY, Boolean.FALSE, Boolean.FALSE, Boolean.FALSE, STRICT);
        
        
        parametersSet.put(AbstractRESTConnectorImpl.AUTH_TYPE_PARAMETER, AuthorizationType.BASIC.name());
        parametersSet.put(AbstractRESTConnectorImpl.AUTH_USERNAME_INPUT_PARAMETER, username);
        parametersSet.put(AbstractRESTConnectorImpl.AUTH_PASSWORD_INPUT_PARAMETER, password);
        parametersSet.put(AbstractRESTConnectorImpl.AUTH_HOST_INPUT_PARAMETER, host);
        parametersSet.put(AbstractRESTConnectorImpl.AUTH_REALM_INPUT_PARAMETER, realm);
        parametersSet.put(AbstractRESTConnectorImpl.AUTH_PREEMPTIVE_INPUT_PARAMETER, preemptive);

        return parametersSet;
    }
    
    /**
     * Execute a connector call
     * @param parameters The parameters of the connector call
     * @return The outputs of the connector
     * @throws BonitaException exception
     */
    private Map<String, Object> executeConnector(final Map<String, Object> parameters) throws BonitaException {
        final RESTConnector rest = new RESTConnector();
        rest.setExecutionContext(getEngineExecutionContext());
        rest.setAPIAccessor(getApiAccessor());
        rest.setInputParameters(parameters);
        rest.validateInputParameters();
        return rest.execute();
    }

    /**
     * Test the GET method
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void getMethod() throws BonitaException, InterruptedException {
        stubFor(get(urlEqualTo("/"))
                .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildMethodParametersSet(GET)));
    }

    /**
     * Test the POST method
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void postMethod() throws BonitaException, InterruptedException {
        stubFor(post(urlEqualTo("/"))
                .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildMethodParametersSet(POST)));
    }

    /**
     * Test the PUT method
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void putMethod() throws BonitaException, InterruptedException {
        stubFor(put(urlEqualTo("/"))
                .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildMethodParametersSet(PUT)));
    }

    /**
     * Test the DELETE method
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void deleteMethod() throws BonitaException, InterruptedException {
        stubFor(delete(urlEqualTo("/"))
                .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildMethodParametersSet(DELETE)));
    }

    /**
     * Test the FAKE method
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void fakeMethod() throws BonitaException, InterruptedException {
        thrown.expect(BonitaException.class);
        thrown.expectMessage("java.lang.IllegalArgumentException: No enum constant org.bonitasoft.connectors.rest.model.HTTPMethod.FAKE_METHOD");

        checkResultIsPresent(executeConnector(buildMethodParametersSet(METHOD_ERROR)));
    }

    /**
     * Test the plain text content type
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void plainTextContentType() throws BonitaException, InterruptedException {
        stubFor(post(urlEqualTo("/"))
                .withHeader(WM_CONTENT_TYPE, equalTo(PLAIN_TEXT + "; " + WM_CHARSET + "=" + UTF8))
                .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildContentTypeParametersSet(PLAIN_TEXT)));
    }

    /**
     * Test the json content type
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void jsonContentType() throws BonitaException, InterruptedException {
        stubFor(post(urlEqualTo("/"))
                .withHeader(WM_CONTENT_TYPE, equalTo(JSON + "; " + WM_CHARSET + "=" + UTF8))
                .willReturn(aResponse().withStatus(HttpStatus.SC_OK).withBody("{ \"name\":\"Romain\" }").withHeader(WM_CONTENT_TYPE, JSON)));

        final Map<String, Object> outputs = executeConnector(buildContentTypeParametersSet(JSON));
        checkResultIsPresent(outputs);
        final Map<String, Object> bodyAsMap = (Map<String, Object>) outputs.get(AbstractRESTConnectorImpl.BODY_AS_MAP_OUTPUT_PARAMETER);
        assertNotNull(bodyAsMap);
        assertEquals(bodyAsMap.get("name"), "Romain");
    }

    /**
     * Test the fake content type
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void fakeContentType() throws BonitaException, InterruptedException {
        stubFor(post(urlEqualTo("/"))
                .withHeader(WM_CONTENT_TYPE, equalTo(CONTENT_TYPE_ERROR + "; " + WM_CHARSET + "=" + UTF8))
                .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildContentTypeParametersSet(CONTENT_TYPE_ERROR)));
    }

    /**
     * Test the UTF8 charset
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void utf8Charset() throws BonitaException, InterruptedException {
        stubFor(post(urlEqualTo("/"))
                .withHeader(WM_CONTENT_TYPE, equalTo(PLAIN_TEXT + "; " + WM_CHARSET + "=" + UTF8))
                .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildCharsetParametersSet(UTF8)));
    }

    /**
     * Test the ISO-8859-1 charset
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void iso88591Charset() throws BonitaException, InterruptedException {
        stubFor(post(urlEqualTo("/"))
                .withHeader(WM_CONTENT_TYPE, equalTo(PLAIN_TEXT + "; " + WM_CHARSET + "=" + ISO_8859_1))
                .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildCharsetParametersSet(ISO_8859_1)));
    }

    /**
     * Test the US ASCII charset
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void usASCIICharset() throws BonitaException, InterruptedException {
        stubFor(post(urlEqualTo("/"))
                .withHeader(WM_CONTENT_TYPE, equalTo(PLAIN_TEXT + "; " + WM_CHARSET + "=" + US_ASCII))
                .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildCharsetParametersSet(US_ASCII)));
    }

    /**
     * Test the FAKE charset
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void fakeCharset() throws BonitaException, InterruptedException {
    	thrown.expect(BonitaException.class);
        thrown.expectMessage("java.nio.charset.UnsupportedCharsetException: FAKE-CHARSET");

        checkResultIsPresent(executeConnector(buildCharsetParametersSet(CHARSET_ERROR)));
    }

    /**
     * Test one value cookie
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void oneValueCookie() throws BonitaException, InterruptedException {
        stubFor(get(urlEqualTo("/"))
                .withHeader(WM_COOKIES, equalTo(generateCookieSet(ONE_COOKIES)))
                .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildCookieParametersSet(ONE_COOKIES)));
    }

    /**
     * Test two values cookie
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void twoValuesCookie() throws BonitaException, InterruptedException {
        stubFor(get(urlEqualTo("/"))
                .withHeader(WM_COOKIES, equalTo(generateCookieSet(TWO_COOKIES)))
                .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildCookieParametersSet(TWO_COOKIES)));
    }

    /**
     * Generate the cookies string
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
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void oneValueHeader() throws BonitaException, InterruptedException {
        final MappingBuilder mb = get(urlEqualTo("/"));
        for (int j = 0; j < ONE_HEADERS.size(); j++) {
            mb.withHeader(ONE_HEADERS.get(j).get(0), equalTo(ONE_HEADERS.get(j).get(1)));
        }
        stubFor(mb.willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildHeaderParametersSet(ONE_HEADERS)));
    }

    /**
     * Test two values header
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void twoValuesHeader() throws BonitaException, InterruptedException {
        final MappingBuilder mb = get(urlEqualTo("/"));
        for (int j = 0; j < TWO_HEADERS.size(); j++) {
            mb.withHeader(TWO_HEADERS.get(j).get(0), equalTo(TWO_HEADERS.get(j).get(1)));
        }
        stubFor(mb.willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildHeaderParametersSet(TWO_HEADERS)));
    }


    /**
     * Test empty body
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void emptyBody() throws BonitaException, InterruptedException {
        stubFor(post(urlEqualTo("/"))
                .withRequestBody(equalTo(EMPTY))
                .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildBodyParametersSet(EMPTY)));
    }

    /**
     * Test not empty body
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void notEmptyBody() throws BonitaException, InterruptedException {
        stubFor(post(urlEqualTo("/"))
                .withRequestBody(equalTo(FULL))
                .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildBodyParametersSet(FULL)));
    }

    /**
     * Test the basic auth with username and password
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void basicAuthWithUsernameAndPassword() throws BonitaException, InterruptedException {
        stubFor(get(urlEqualTo("/"))
                .withHeader(WM_AUTHORIZATION, containing(BASIC_RULE))
                .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));
        checkResultIsPresent(executeConnector(buildBasicAuthorizationParametersSet(USERNAME, PASSWORD, EMPTY, EMPTY, Boolean.TRUE)));
    }

    /**
     * Test the basic auth with username password and localhost
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void basicAuthWithUsernamePasswordAndLocalhost() throws BonitaException, InterruptedException {
        stubFor(get(urlEqualTo("/"))
                .withHeader(WM_AUTHORIZATION, containing(BASIC_RULE))
                .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildBasicAuthorizationParametersSet(USERNAME, PASSWORD, HOST, EMPTY, Boolean.TRUE)));
    }

    /**
     * Test the basic auth with username password and realm
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void basicAuthWithUsernamePasswordAndRealm() throws BonitaException, InterruptedException {
        stubFor(get(urlEqualTo("/"))
                .withHeader(WM_AUTHORIZATION, containing(BASIC_RULE))
                .willReturn(aResponse().withStatus(HttpStatus.SC_OK)));

        checkResultIsPresent(executeConnector(buildBasicAuthorizationParametersSet(USERNAME, PASSWORD, EMPTY, REALM, Boolean.TRUE)));
    }
    
    /**
     * Test no service available
     * @throws InterruptedException exception
     * @throws BonitaException 
     */
    @Test
    public void noServiceAvailable() throws InterruptedException, BonitaException {
        thrown.expect(ConnectorException.class);
        executeConnector(buildMethodParametersSet(GET));
    }

    /**
     * Test unreachable URL
     * @throws InterruptedException exception
     * @throws BonitaException 
     */
    @Test
    public void unreachableURL() throws InterruptedException, BonitaException {
        thrown.expect(BonitaException.class);
        thrown.expectMessage("java.net.UnknownHostException: fakeURL");

        executeConnector(buildURLParametersSet(FAKE_URL));
    }

    /**
     * Test unreachable port
     * @throws InterruptedException exception
     * @throws BonitaException 
     */
    @Test
    public void unreachablePort() throws InterruptedException, BonitaException {
        final String fakePort = "666";
        thrown.expect(BonitaException.class);
        thrown.expectMessage("org.apache.http.conn.HttpHostConnectException");
        thrown.expectMessage(fakePort);

        executeConnector(buildPortParametersSet(fakePort));
    }

    @Test
    public void should_remove_empty_lines_from_input_tables() throws Exception {
        final RESTConnector restConnector = new RESTConnector();
        final Map<String, Object> parameters = Maps.newHashMap();

        final List<List<?>> cookies = new ArrayList<>();
        cookies.add(newArrayList("key1", "value"));
        cookies.add(newArrayList("", ""));
        cookies.add(newArrayList(null, null));
        cookies.add(newArrayList());
        cookies.add(null);
        parameters.put(RESTConnector.URLCOOKIES_INPUT_PARAMETER, cookies);
        restConnector.setInputParameters(parameters);

        final List urlCookies = restConnector.getUrlCookies();
        assertTrue(urlCookies.size() == 1);
    }

    /**
     * Generic test: should return OK STATUS as the WireMock stub is set each time for the good request shape
     * 
     * @param outputs The result of the request
     */
    private void checkResultIsPresent(final Map<String, Object> outputs) {
        checkResult(outputs, HttpStatus.SC_OK);
    }

    /**
     * Generic test: should return OK STATUS as the WireMock stub is set each time for the good request shape
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
}

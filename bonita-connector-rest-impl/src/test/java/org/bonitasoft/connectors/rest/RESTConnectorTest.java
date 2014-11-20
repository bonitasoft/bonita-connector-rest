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
import static com.github.tomakehurst.wiremock.client.WireMock.delete;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.BeforeClass;
import org.junit.Rule;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bonitasoft.connectors.rest.AbstractRESTConnectorImpl;
import org.bonitasoft.connectors.rest.RESTConnector;
import org.bonitasoft.connectors.rest.RESTResult;
import org.bonitasoft.engine.exception.BonitaException;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.github.tomakehurst.wiremock.client.MappingBuilder;

/**
 * The class for the UTs of the REST Connector
 */
public class RESTConnectorTest extends AcceptanceTestBase {

    /**
     * HTTP STATUS
     */
    private static final int OK_STATUS = 200;
    private static final int NOT_FOUND_STATUS = 404;

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
    private static final List<String> METHODS = new ArrayList<String>();
    private static final List<Map<String, Object>> METHODS_TC = new ArrayList<Map<String, Object>>();

    //CONTENT_TYPES
    /**
     * All the tested content type values
     */
    private static final String PLAIN_TEXT = "text/plain";
    private static final String JSON = "application/json";
    private static final String CONTENT_TYPE_ERROR = "fakecontenttype";
    private static final List<String> CONTENT_TYPES = new ArrayList<String>();
    private static final List<Map<String, Object>> CONTENT_TYPES_TC = new ArrayList<Map<String, Object>>();

    //CHARSETS
    /**
     * All the tested charset values
     */
    private static final String UTF8 = "UTF-8";
    private static final String UTF16 = "UTF-16";
    private static final String UTF16BE = "UTF-16BE";
    private static final String UTF16LE = "UTF-16LE";
    private static final String ISO_8859_1 = "ISO-8859-1";
    private static final String US_ASCII = "US-ASCII";
    private static final String CHARSET_ERROR = "FAKE-CHARSET";
    private static final List<String> CHARSETS = new ArrayList<String>();
    private static final List<Map<String, Object>> CHARSETS_TC = new ArrayList<Map<String, Object>>();

    //COOKIES
    /**
     * All the tested cookies values
     */
    private static final List<List<String>> ONE_COOKIES = new ArrayList<List<String>>();
    private static final List<List<String>> TWO_COOKIES = new ArrayList<List<String>>();
    private static final List<List<String>> COOKIES_ERROR = new ArrayList<List<String>>();
    private static final List<List<List<String>>> COOKIESS = new ArrayList<List<List<String>>>();
    private static final List<Map<String, Object>> COOKIESS_TC = new ArrayList<Map<String, Object>>();

    //HEADERS
    /**
     * All the tested headers values
     */
    private static final List<List<String>> ONE_HEADERS = new ArrayList<List<String>>();
    private static final List<List<String>> TWO_HEADERS = new ArrayList<List<String>>();
    private static final List<List<String>> HEADERS_ERROR = new ArrayList<List<String>>();
    private static final List<List<List<String>>> HEADERSS = new ArrayList<List<List<String>>>();
    private static final List<Map<String, Object>> HEADERSS_TC = new ArrayList<Map<String, Object>>();

    //BODYS
    /**
     * All the tested bodies values
     */
    private static final String EMPTY = "";
    private static final String FULL = "there is something inside";
    private static final List<String> BODYS = new ArrayList<String>();
    private static final List<Map<String, Object>> BODYS_TC = new ArrayList<Map<String, Object>>();

    //SSL VERIFIERS
    /**
     * All the tested SSL verifier values
     */
    private static final String STRICT = "Strict";
    private static final String BROWSER_COMPATIBLE = "Browser Compatible";
    private static final String ALLOW_ALL = "Allow All";
    private static final List<String> SSL_VERIFIERS = new ArrayList<String>();

    //AUTHORIZATIONS
    /**
     * All the tested authorization values
     */
    private static final String BASIC = "BASIC";
    private static final String DIGEST = "DIGEST";
    private static final String NTLM = "NTLM";
    private static final String OAUTH2BEARER = "OAuth2Bearer";
    private static final String BASIC_RULE = "Basic";
    //    private static final String DIGEST_RULE = "Digest";
    //    private static final String NTLM_RULE = "NTLM";
    private static final List<List<Object>> AUTHORIZATIONS = new ArrayList<List<Object>>();
    private static final List<Map<String, Object>> AUTHORIZATIONS_TC = new ArrayList<Map<String, Object>>();

    //ERRORS
    /**
     * All the tested errors
     */
    private static final String FAKE_URL = "fakeURL";
    private static final String FAKE_PORT = "0000";
    private static final List<String> ERRORS = new ArrayList<String>();
    private static final List<Map<String, Object>> ERRORS_TC = new ArrayList<Map<String, Object>>();

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
        List<String> cookie1 = new ArrayList<String>();
        cookie1.add("cookie1name");
        cookie1.add("cookie1value");
        ONE_COOKIES.add(cookie1);

        List<String> cookie2 = new ArrayList<String>();
        cookie2.add("cookie2name");
        cookie2.add("cookie2value");
        TWO_COOKIES.add(cookie1);
        TWO_COOKIES.add(cookie2);

        List<String> cookie3 = new ArrayList<String>();
        cookie3.add("cookie3name");
        cookie3.add("cookie3value");
        cookie3.add("cookie3extrat");
        List<String> cookie4 = new ArrayList<String>();
        cookie4.add("cookie4nameonly");
        COOKIES_ERROR.add(cookie1);
        COOKIES_ERROR.add(cookie2);
        COOKIES_ERROR.add(cookie3);
        COOKIES_ERROR.add(cookie4);

        List<String> header1 = new ArrayList<String>();
        header1.add("header1name");
        header1.add("header1value");
        ONE_HEADERS.add(header1);

        List<String> header2 = new ArrayList<String>();
        header2.add("header2name");
        header2.add("header2value");
        TWO_HEADERS.add(header1);
        TWO_HEADERS.add(header2);

        List<String> header3 = new ArrayList<String>();
        header3.add("header3name");
        header3.add("header3value");
        header3.add("header3extrat");
        List<String> header4 = new ArrayList<String>();
        header4.add("header4nameonly");
        HEADERS_ERROR.add(header1);
        HEADERS_ERROR.add(header2);
        HEADERS_ERROR.add(header3);
        HEADERS_ERROR.add(header4);

        METHODS.add(GET);
        METHODS.add(POST);
        METHODS.add(PUT);
        METHODS.add(DELETE);
        METHODS.add(METHOD_ERROR);

        CONTENT_TYPES.add(PLAIN_TEXT);
        CONTENT_TYPES.add(JSON);
        CONTENT_TYPES.add(CONTENT_TYPE_ERROR);

        CHARSETS.add(UTF8);
        CHARSETS.add(UTF16);
        CHARSETS.add(UTF16BE);
        CHARSETS.add(UTF16LE);
        CHARSETS.add(ISO_8859_1);
        CHARSETS.add(US_ASCII);
        CHARSETS.add(CHARSET_ERROR);

        COOKIESS.add(ONE_COOKIES);
        COOKIESS.add(TWO_COOKIES);
        COOKIESS.add(COOKIES_ERROR);

        HEADERSS.add(ONE_HEADERS);
        HEADERSS.add(TWO_HEADERS);
        HEADERSS.add(HEADERS_ERROR);

        BODYS.add(EMPTY);
        BODYS.add(FULL);

        SSL_VERIFIERS.add(STRICT);
        SSL_VERIFIERS.add(BROWSER_COMPATIBLE);
        SSL_VERIFIERS.add(ALLOW_ALL);

        List<Object> basicAuth1 = new ArrayList<Object>();
        basicAuth1.add(BASIC);
        basicAuth1.add(BASIC_RULE);
        basicAuth1.add("username");
        basicAuth1.add("password");
        basicAuth1.add("");
        basicAuth1.add("");
        basicAuth1.add(Boolean.TRUE);
        AUTHORIZATIONS.add(basicAuth1);

        List<Object> basicAuth2 = new ArrayList<Object>();
        basicAuth2.add(BASIC);
        basicAuth2.add(BASIC_RULE);
        basicAuth2.add("username");
        basicAuth2.add("password");
        basicAuth2.add("localhost");
        basicAuth2.add("");
        basicAuth2.add(Boolean.TRUE);
        AUTHORIZATIONS.add(basicAuth2);

        List<Object> basicAuth3 = new ArrayList<Object>();
        basicAuth3.add(BASIC);
        basicAuth3.add(BASIC_RULE);
        basicAuth3.add("username");
        basicAuth3.add("password");
        basicAuth3.add("");
        basicAuth3.add("realm");
        basicAuth3.add(Boolean.TRUE);
        AUTHORIZATIONS.add(basicAuth3);

        List<Object> oauth2bearer = new ArrayList<Object>();
        oauth2bearer.add(OAUTH2BEARER);
        oauth2bearer.add("token");
        oauth2bearer.add("token");
        AUTHORIZATIONS.add(oauth2bearer);

        ERRORS.add(FAKE_URL);
        ERRORS.add(FAKE_PORT);

        buildParameters();
    }

    /**
     * Build the parameters for all the tested values
     */
    private static void buildParameters() {
        Map<String, Object> parameters = new HashMap<String, Object>();
        for (int i = 0; i < METHODS.size(); i++) {
            parameters = new HashMap<String, Object>();
            parameters.put(AbstractRESTConnectorImpl.URL_INPUT_PARAMETER, "http://" + getUrl() + ":" + getPort() + "/");
            parameters.put(AbstractRESTConnectorImpl.METHOD_INPUT_PARAMETER, METHODS.get(i));
            parameters.put(AbstractRESTConnectorImpl.CONTENTTYPE_INPUT_PARAMETER, CONTENT_TYPES.get(0));
            parameters.put(AbstractRESTConnectorImpl.CHARSET_INPUT_PARAMETER, CHARSETS.get(0));
            parameters.put(AbstractRESTConnectorImpl.URLCOOKIES_INPUT_PARAMETER, COOKIESS.get(0));
            parameters.put(AbstractRESTConnectorImpl.URLHEADERS_INPUT_PARAMETER, HEADERSS.get(0));
            parameters.put(AbstractRESTConnectorImpl.BODY_INPUT_PARAMETER, BODYS.get(0));
            parameters.put(AbstractRESTConnectorImpl.DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(AbstractRESTConnectorImpl.IGNORE_BODY_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(AbstractRESTConnectorImpl.TRUST_SELF_SIGNED_CERTIFICATE_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(AbstractRESTConnectorImpl.HOSTNAME_VERIFIER_INPUT_PARAMETER, SSL_VERIFIERS.get(0));
            METHODS_TC.add(parameters);
        }

        for (int i = 0; i < CONTENT_TYPES.size(); i++) {
            parameters = new HashMap<String, Object>();
            parameters.put(AbstractRESTConnectorImpl.URL_INPUT_PARAMETER, "http://" + getUrl() + ":" + getPort() + "/");
            parameters.put(AbstractRESTConnectorImpl.METHOD_INPUT_PARAMETER, METHODS.get(1));
            parameters.put(AbstractRESTConnectorImpl.CONTENTTYPE_INPUT_PARAMETER, CONTENT_TYPES.get(i));
            parameters.put(AbstractRESTConnectorImpl.CHARSET_INPUT_PARAMETER, CHARSETS.get(0));
            parameters.put(AbstractRESTConnectorImpl.URLCOOKIES_INPUT_PARAMETER, COOKIESS.get(0));
            parameters.put(AbstractRESTConnectorImpl.URLHEADERS_INPUT_PARAMETER, HEADERSS.get(0));
            parameters.put(AbstractRESTConnectorImpl.BODY_INPUT_PARAMETER, BODYS.get(0));
            parameters.put(AbstractRESTConnectorImpl.DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(AbstractRESTConnectorImpl.IGNORE_BODY_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(AbstractRESTConnectorImpl.TRUST_SELF_SIGNED_CERTIFICATE_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(AbstractRESTConnectorImpl.HOSTNAME_VERIFIER_INPUT_PARAMETER, SSL_VERIFIERS.get(0));
            CONTENT_TYPES_TC.add(parameters);
        }

        for (int i = 0; i < CHARSETS.size(); i++) {
            parameters = new HashMap<String, Object>();
            parameters.put(AbstractRESTConnectorImpl.URL_INPUT_PARAMETER, "http://" + getUrl() + ":" + getPort() + "/");
            parameters.put(AbstractRESTConnectorImpl.METHOD_INPUT_PARAMETER, METHODS.get(1));
            parameters.put(AbstractRESTConnectorImpl.CONTENTTYPE_INPUT_PARAMETER, CONTENT_TYPES.get(0));
            parameters.put(AbstractRESTConnectorImpl.CHARSET_INPUT_PARAMETER, CHARSETS.get(i));
            parameters.put(AbstractRESTConnectorImpl.URLCOOKIES_INPUT_PARAMETER, COOKIESS.get(0));
            parameters.put(AbstractRESTConnectorImpl.URLHEADERS_INPUT_PARAMETER, HEADERSS.get(0));
            parameters.put(AbstractRESTConnectorImpl.BODY_INPUT_PARAMETER, BODYS.get(0));
            parameters.put(AbstractRESTConnectorImpl.DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(AbstractRESTConnectorImpl.IGNORE_BODY_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(AbstractRESTConnectorImpl.TRUST_SELF_SIGNED_CERTIFICATE_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(AbstractRESTConnectorImpl.HOSTNAME_VERIFIER_INPUT_PARAMETER, SSL_VERIFIERS.get(0));
            CHARSETS_TC.add(parameters);
        }

        for (int i = 0; i < COOKIESS.size(); i++) {
            parameters = new HashMap<String, Object>();
            parameters.put(AbstractRESTConnectorImpl.URL_INPUT_PARAMETER, "http://" + getUrl() + ":" + getPort() + "/");
            parameters.put(AbstractRESTConnectorImpl.METHOD_INPUT_PARAMETER, METHODS.get(0));
            parameters.put(AbstractRESTConnectorImpl.CONTENTTYPE_INPUT_PARAMETER, CONTENT_TYPES.get(0));
            parameters.put(AbstractRESTConnectorImpl.CHARSET_INPUT_PARAMETER, CHARSETS.get(0));
            parameters.put(AbstractRESTConnectorImpl.URLCOOKIES_INPUT_PARAMETER, COOKIESS.get(i));
            parameters.put(AbstractRESTConnectorImpl.URLHEADERS_INPUT_PARAMETER, HEADERSS.get(0));
            parameters.put(AbstractRESTConnectorImpl.BODY_INPUT_PARAMETER, BODYS.get(0));
            parameters.put(AbstractRESTConnectorImpl.DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(AbstractRESTConnectorImpl.IGNORE_BODY_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(AbstractRESTConnectorImpl.TRUST_SELF_SIGNED_CERTIFICATE_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(AbstractRESTConnectorImpl.HOSTNAME_VERIFIER_INPUT_PARAMETER, SSL_VERIFIERS.get(0));
            COOKIESS_TC.add(parameters);
        }

        for (int i = 0; i < HEADERSS.size(); i++) {
            parameters = new HashMap<String, Object>();
            parameters.put(AbstractRESTConnectorImpl.URL_INPUT_PARAMETER, "http://" + getUrl() + ":" + getPort() + "/");
            parameters.put(AbstractRESTConnectorImpl.METHOD_INPUT_PARAMETER, METHODS.get(0));
            parameters.put(AbstractRESTConnectorImpl.CONTENTTYPE_INPUT_PARAMETER, CONTENT_TYPES.get(0));
            parameters.put(AbstractRESTConnectorImpl.CHARSET_INPUT_PARAMETER, CHARSETS.get(0));
            parameters.put(AbstractRESTConnectorImpl.URLCOOKIES_INPUT_PARAMETER, COOKIESS.get(0));
            parameters.put(AbstractRESTConnectorImpl.URLHEADERS_INPUT_PARAMETER, HEADERSS.get(i));
            parameters.put(AbstractRESTConnectorImpl.BODY_INPUT_PARAMETER, BODYS.get(0));
            parameters.put(AbstractRESTConnectorImpl.DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(AbstractRESTConnectorImpl.IGNORE_BODY_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(AbstractRESTConnectorImpl.TRUST_SELF_SIGNED_CERTIFICATE_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(AbstractRESTConnectorImpl.HOSTNAME_VERIFIER_INPUT_PARAMETER, SSL_VERIFIERS.get(0));
            HEADERSS_TC.add(parameters);
        }

        for (int i = 0; i < BODYS.size(); i++) {
            parameters = new HashMap<String, Object>();
            parameters.put(AbstractRESTConnectorImpl.URL_INPUT_PARAMETER, "http://" + getUrl() + ":" + getPort() + "/");
            parameters.put(AbstractRESTConnectorImpl.METHOD_INPUT_PARAMETER, METHODS.get(1));
            parameters.put(AbstractRESTConnectorImpl.CONTENTTYPE_INPUT_PARAMETER, CONTENT_TYPES.get(0));
            parameters.put(AbstractRESTConnectorImpl.CHARSET_INPUT_PARAMETER, CHARSETS.get(0));
            parameters.put(AbstractRESTConnectorImpl.URLCOOKIES_INPUT_PARAMETER, COOKIESS.get(0));
            parameters.put(AbstractRESTConnectorImpl.URLHEADERS_INPUT_PARAMETER, HEADERSS.get(0));
            parameters.put(AbstractRESTConnectorImpl.BODY_INPUT_PARAMETER, BODYS.get(i));
            parameters.put(AbstractRESTConnectorImpl.DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(AbstractRESTConnectorImpl.IGNORE_BODY_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(AbstractRESTConnectorImpl.TRUST_SELF_SIGNED_CERTIFICATE_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(AbstractRESTConnectorImpl.HOSTNAME_VERIFIER_INPUT_PARAMETER, SSL_VERIFIERS.get(0));
            BODYS_TC.add(parameters);
        }

        for (int i = 0; i < AUTHORIZATIONS.size(); i++) {
            parameters = new HashMap<String, Object>();
            parameters.put(AbstractRESTConnectorImpl.URL_INPUT_PARAMETER, "http://" + getUrl() + ":" + getPort() + "/");
            parameters.put(AbstractRESTConnectorImpl.METHOD_INPUT_PARAMETER, METHODS.get(0));
            parameters.put(AbstractRESTConnectorImpl.CONTENTTYPE_INPUT_PARAMETER, CONTENT_TYPES.get(0));
            parameters.put(AbstractRESTConnectorImpl.CHARSET_INPUT_PARAMETER, CHARSETS.get(0));
            parameters.put(AbstractRESTConnectorImpl.URLCOOKIES_INPUT_PARAMETER, COOKIESS.get(0));
            parameters.put(AbstractRESTConnectorImpl.URLHEADERS_INPUT_PARAMETER, HEADERSS.get(0));
            parameters.put(AbstractRESTConnectorImpl.BODY_INPUT_PARAMETER, BODYS.get(0));
            parameters.put(AbstractRESTConnectorImpl.DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(AbstractRESTConnectorImpl.IGNORE_BODY_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(AbstractRESTConnectorImpl.TRUST_SELF_SIGNED_CERTIFICATE_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(AbstractRESTConnectorImpl.HOSTNAME_VERIFIER_INPUT_PARAMETER, SSL_VERIFIERS.get(0));
            int authIndex = 0;
            if (BASIC.equals(AUTHORIZATIONS.get(i).get(authIndex))) {
                authIndex += 2;
                parameters.put(AbstractRESTConnectorImpl.AUTH_BASIC_USERNAME_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
                parameters.put(AbstractRESTConnectorImpl.AUTH_BASIC_PASSWORD_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
                parameters.put(AbstractRESTConnectorImpl.AUTH_BASIC_HOST_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
                parameters.put(AbstractRESTConnectorImpl.AUTH_BASIC_REALM_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
                parameters.put(AbstractRESTConnectorImpl.AUTH_BASIC_PREEMPTIVE_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
            } else if (DIGEST.equals(AUTHORIZATIONS.get(i).get(authIndex))) {
                authIndex += 2;
                parameters.put(AbstractRESTConnectorImpl.AUTH_DIGEST_USERNAME_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
                parameters.put(AbstractRESTConnectorImpl.AUTH_DIGEST_PASSWORD_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
                parameters.put(AbstractRESTConnectorImpl.AUTH_DIGEST_HOST_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
                parameters.put(AbstractRESTConnectorImpl.AUTH_DIGEST_REALM_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
                parameters.put(AbstractRESTConnectorImpl.AUTH_DIGEST_PREEMPTIVE_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
            } else if (NTLM.equals(AUTHORIZATIONS.get(i).get(authIndex))) {
                authIndex += 2;
                parameters.put(AbstractRESTConnectorImpl.AUTH_NTLM_USERNAME_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
                parameters.put(AbstractRESTConnectorImpl.AUTH_NTLM_PASSWORD_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
                parameters.put(AbstractRESTConnectorImpl.AUTH_NTLM_WORKSTATION_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
                parameters.put(AbstractRESTConnectorImpl.AUTH_NTLM_DOMAIN_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
            } else if (OAUTH2BEARER.equals(AUTHORIZATIONS.get(i).get(authIndex))) {
                parameters.put(AbstractRESTConnectorImpl.AUTH_OAUTH2_BEARER_TOKEN_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(2));
            }

            AUTHORIZATIONS_TC.add(parameters);
        }

        parameters = new HashMap<String, Object>();
        parameters.put(AbstractRESTConnectorImpl.URL_INPUT_PARAMETER, "http://" + ERRORS.get(0) + ":" + getPort() + "/");
        parameters.put(AbstractRESTConnectorImpl.METHOD_INPUT_PARAMETER, METHODS.get(1));
        parameters.put(AbstractRESTConnectorImpl.CONTENTTYPE_INPUT_PARAMETER, CONTENT_TYPES.get(0));
        parameters.put(AbstractRESTConnectorImpl.CHARSET_INPUT_PARAMETER, CHARSETS.get(0));
        parameters.put(AbstractRESTConnectorImpl.URLCOOKIES_INPUT_PARAMETER, COOKIESS.get(0));
        parameters.put(AbstractRESTConnectorImpl.URLHEADERS_INPUT_PARAMETER, HEADERSS.get(0));
        parameters.put(AbstractRESTConnectorImpl.BODY_INPUT_PARAMETER, BODYS.get(0));
        parameters.put(AbstractRESTConnectorImpl.DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER, Boolean.FALSE);
        parameters.put(AbstractRESTConnectorImpl.IGNORE_BODY_INPUT_PARAMETER, Boolean.FALSE);
        parameters.put(AbstractRESTConnectorImpl.TRUST_SELF_SIGNED_CERTIFICATE_INPUT_PARAMETER, Boolean.FALSE);
        parameters.put(AbstractRESTConnectorImpl.HOSTNAME_VERIFIER_INPUT_PARAMETER, SSL_VERIFIERS.get(0));
        ERRORS_TC.add(parameters);
        parameters = new HashMap<String, Object>();
        parameters.put(AbstractRESTConnectorImpl.URL_INPUT_PARAMETER, "http://" + getUrl() + ":" + ERRORS.get(1) + "/");
        parameters.put(AbstractRESTConnectorImpl.METHOD_INPUT_PARAMETER, METHODS.get(1));
        parameters.put(AbstractRESTConnectorImpl.CONTENTTYPE_INPUT_PARAMETER, CONTENT_TYPES.get(0));
        parameters.put(AbstractRESTConnectorImpl.CHARSET_INPUT_PARAMETER, CHARSETS.get(0));
        parameters.put(AbstractRESTConnectorImpl.URLCOOKIES_INPUT_PARAMETER, COOKIESS.get(0));
        parameters.put(AbstractRESTConnectorImpl.URLHEADERS_INPUT_PARAMETER, HEADERSS.get(0));
        parameters.put(AbstractRESTConnectorImpl.BODY_INPUT_PARAMETER, BODYS.get(0));
        parameters.put(AbstractRESTConnectorImpl.DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER, Boolean.FALSE);
        parameters.put(AbstractRESTConnectorImpl.IGNORE_BODY_INPUT_PARAMETER, Boolean.FALSE);
        parameters.put(AbstractRESTConnectorImpl.TRUST_SELF_SIGNED_CERTIFICATE_INPUT_PARAMETER, Boolean.FALSE);
        parameters.put(AbstractRESTConnectorImpl.HOSTNAME_VERIFIER_INPUT_PARAMETER, SSL_VERIFIERS.get(0));
        ERRORS_TC.add(parameters);
    }

    /**
     * Execute a connector call
     * @param parameters The parameters of the connector call
     * @return The outputs of the connector
     * @throws BonitaException exception
     */
    private Map<String, Object> executeConnector(final Map<String, Object> parameters) throws BonitaException {
        RESTConnector rest = new RESTConnector();
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
                .willReturn(aResponse().withStatus(OK_STATUS)));

        checkResultIsPresent(executeConnector(METHODS_TC.get(0)));
    }

    /**
     * Test the POST method
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void postMethod() throws BonitaException, InterruptedException {
        stubFor(post(urlEqualTo("/"))
                .willReturn(aResponse().withStatus(OK_STATUS)));

        checkResultIsPresent(executeConnector(METHODS_TC.get(1)));
    }

    /**
     * Test the PUT method
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void putMethod() throws BonitaException, InterruptedException {
        stubFor(put(urlEqualTo("/"))
                .willReturn(aResponse().withStatus(OK_STATUS)));

        checkResultIsPresent(executeConnector(METHODS_TC.get(2)));
    }

    /**
     * Test the DELETE method
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void deleteMethod() throws BonitaException, InterruptedException {
        stubFor(delete(urlEqualTo("/"))
                .willReturn(aResponse().withStatus(OK_STATUS)));

        checkResultIsPresent(executeConnector(METHODS_TC.get(3)));
    }

    /**
     * Test the FAKE method
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void fakeMethod() throws BonitaException, InterruptedException {
        thrown.expect(BonitaException.class);
        thrown.expectMessage("java.lang.IllegalArgumentException: No enum constant org.bonitasoft.connectors.rest.model.RESTHTTPMethod.FAKE_METHOD");

        checkResultIsPresent(executeConnector(METHODS_TC.get(4)));
    }

    /**
     * Test the plain text content type
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void plainTextContentType() throws BonitaException, InterruptedException {
        stubFor(post(urlEqualTo("/"))
                .withHeader(WM_CONTENT_TYPE, equalTo(CONTENT_TYPES.get(0) + "; " + WM_CHARSET + "=" + CHARSETS.get(0)))
                .willReturn(aResponse().withStatus(OK_STATUS)));

        checkResultIsPresent(executeConnector(CONTENT_TYPES_TC.get(0)));
    }

    /**
     * Test the json content type
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void jsonContentType() throws BonitaException, InterruptedException {
        stubFor(post(urlEqualTo("/"))
                .withHeader(WM_CONTENT_TYPE, equalTo(CONTENT_TYPES.get(1) + "; " + WM_CHARSET + "=" + CHARSETS.get(0)))
                .willReturn(aResponse().withStatus(OK_STATUS)));

        checkResultIsPresent(executeConnector(CONTENT_TYPES_TC.get(1)));
    }

    /**
     * Test the fake content type
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void fakeContentType() throws BonitaException, InterruptedException {
        stubFor(post(urlEqualTo("/"))
                .withHeader(WM_CONTENT_TYPE, equalTo(CONTENT_TYPES.get(2) + "; " + WM_CHARSET + "=" + CHARSETS.get(0)))
                .willReturn(aResponse().withStatus(OK_STATUS)));

        checkResultIsPresent(executeConnector(CONTENT_TYPES_TC.get(2)));
    }

    /**
     * Test the UTF8 charset
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void utf8Charset() throws BonitaException, InterruptedException {
        stubFor(post(urlEqualTo("/"))
                .withHeader(WM_CONTENT_TYPE, equalTo(CONTENT_TYPES.get(0) + "; " + WM_CHARSET + "=" + CHARSETS.get(0)))
                .willReturn(aResponse().withStatus(OK_STATUS)));

        checkResultIsPresent(executeConnector(CHARSETS_TC.get(0)));
    }

    /**
     * Test the UTF16 charset
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void utf16Charset() throws BonitaException, InterruptedException {
        stubFor(post(urlEqualTo("/"))
                .withHeader(WM_CONTENT_TYPE, equalTo(CONTENT_TYPES.get(0) + "; " + WM_CHARSET + "=" + CHARSETS.get(1)))
                .willReturn(aResponse().withStatus(OK_STATUS)));

        checkResultIsPresent(executeConnector(CHARSETS_TC.get(1)));
    }

    /**
     * Test the UTF16BE charset
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void utf16beCharset() throws BonitaException, InterruptedException {
        stubFor(post(urlEqualTo("/"))
                .withHeader(WM_CONTENT_TYPE, equalTo(CONTENT_TYPES.get(0) + "; " + WM_CHARSET + "=" + CHARSETS.get(2)))
                .willReturn(aResponse().withStatus(OK_STATUS)));

        checkResultIsPresent(executeConnector(CHARSETS_TC.get(2)));
    }

    /**
     * Test the UTF16LE charset
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void utf16leCharset() throws BonitaException, InterruptedException {
        stubFor(post(urlEqualTo("/"))
                .withHeader(WM_CONTENT_TYPE, equalTo(CONTENT_TYPES.get(0) + "; " + WM_CHARSET + "=" + CHARSETS.get(3)))
                .willReturn(aResponse().withStatus(OK_STATUS)));

        checkResultIsPresent(executeConnector(CHARSETS_TC.get(3)));
    }

    /**
     * Test the ISO-8859-1 charset
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void iso88591Charset() throws BonitaException, InterruptedException {
        stubFor(post(urlEqualTo("/"))
                .withHeader(WM_CONTENT_TYPE, equalTo(CONTENT_TYPES.get(0) + "; " + WM_CHARSET + "=" + CHARSETS.get(4)))
                .willReturn(aResponse().withStatus(OK_STATUS)));

        checkResultIsPresent(executeConnector(CHARSETS_TC.get(4)));
    }

    /**
     * Test the US ASCII charset
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void usASCIICharset() throws BonitaException, InterruptedException {
        stubFor(post(urlEqualTo("/"))
                .withHeader(WM_CONTENT_TYPE, equalTo(CONTENT_TYPES.get(0) + "; " + WM_CHARSET + "=" + CHARSETS.get(5)))
                .willReturn(aResponse().withStatus(OK_STATUS)));

        checkResultIsPresent(executeConnector(CHARSETS_TC.get(5)));
    }

    /**
     * Test the FAKE charset
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void fakeCharset() throws BonitaException, InterruptedException {
        stubFor(post(urlEqualTo("/"))
                .withHeader(WM_CONTENT_TYPE, equalTo(CONTENT_TYPES.get(0) + "; " + WM_CHARSET + "=" + CHARSETS.get(0)))
                .willReturn(aResponse().withStatus(OK_STATUS)));

        checkResultIsPresent(executeConnector(CHARSETS_TC.get(6)));
    }

    /**
     * Test one value cookie
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void oneValueCookie() throws BonitaException, InterruptedException {
        stubFor(get(urlEqualTo("/"))
                .withHeader(WM_COOKIES, equalTo(generateCookieSet(COOKIESS.get(0))))
                .willReturn(aResponse().withStatus(OK_STATUS)));

        checkResultIsPresent(executeConnector(COOKIESS_TC.get(0)));
    }

    /**
     * Test two values cookie
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void twoValuesCookie() throws BonitaException, InterruptedException {
        stubFor(get(urlEqualTo("/"))
                .withHeader(WM_COOKIES, equalTo(generateCookieSet(COOKIESS.get(1))))
                .willReturn(aResponse().withStatus(OK_STATUS)));

        checkResultIsPresent(executeConnector(COOKIESS_TC.get(1)));
    }

    /**
     * Test fake cookie
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void fakeValuesCookie() throws BonitaException, InterruptedException {
        thrown.expect(BonitaException.class);
        thrown.expectMessage("Error validating connector org.bonitasoft.connectors.rest.RESTConnector:\nurlCookies - columns - 3\nurlCookies - columns - 1");

        checkResultIsPresent(executeConnector(COOKIESS_TC.get(2)));
    }

    /**
     * Generate the cookies string
     * @param cookies The cookies values
     * @return The cookie string
     */
    private String generateCookieSet(final List<List<String>> cookies) {
        StringBuffer strBuffer = new StringBuffer();

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
        MappingBuilder mb = get(urlEqualTo("/"));
        for (int j = 0; j < HEADERSS.get(0).size(); j++) {
            mb.withHeader(HEADERSS.get(0).get(j).get(0), equalTo(HEADERSS.get(0).get(j).get(1)));
        }
        stubFor(mb.willReturn(aResponse().withStatus(OK_STATUS)));

        checkResultIsPresent(executeConnector(HEADERSS_TC.get(0)));
    }

    /**
     * Test two values header
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void twoValuesHeader() throws BonitaException, InterruptedException {
        MappingBuilder mb = get(urlEqualTo("/"));
        for (int j = 0; j < HEADERSS.get(1).size(); j++) {
            mb.withHeader(HEADERSS.get(1).get(j).get(0), equalTo(HEADERSS.get(1).get(j).get(1)));
        }
        stubFor(mb.willReturn(aResponse().withStatus(OK_STATUS)));

        checkResultIsPresent(executeConnector(HEADERSS_TC.get(1)));
    }

    /**
     * Test fake header
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void fakeValuesHeader() throws BonitaException, InterruptedException {
        thrown.expect(BonitaException.class);
        thrown.expectMessage("Error validating connector org.bonitasoft.connectors.rest.RESTConnector:\nurlHeaders - columns - 3\nurlHeaders - columns - 1");
        
        checkResultIsPresent(executeConnector(HEADERSS_TC.get(2)));
    }

    /**
     * Test empty body
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void emptyBody() throws BonitaException, InterruptedException {
        stubFor(post(urlEqualTo("/"))
                .withRequestBody(equalTo(BODYS.get(0)))
                .willReturn(aResponse().withStatus(OK_STATUS)));

        checkResultIsPresent(executeConnector(BODYS_TC.get(0)));
    }

    /**
     * Test not empty body
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void notEmptyBody() throws BonitaException, InterruptedException {
        stubFor(post(urlEqualTo("/"))
                .withRequestBody(equalTo(BODYS.get(1)))
                .willReturn(aResponse().withStatus(OK_STATUS)));

        checkResultIsPresent(executeConnector(BODYS_TC.get(1)));
    }

    /**
     * Test the basic auth with username and password
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void basicAuthWithUsernameAndPassword() throws BonitaException, InterruptedException {
        stubFor(get(urlEqualTo("/"))
                .withHeader(WM_AUTHORIZATION, containing(AUTHORIZATIONS.get(0).get(1).toString()))
                .willReturn(aResponse().withStatus(OK_STATUS)));

        checkResultIsPresent(executeConnector(AUTHORIZATIONS_TC.get(0)));
    }

    /**
     * Test the basic auth with username password and localhost
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void basicAuthWithUsernamePasswordAndLocalhost() throws BonitaException, InterruptedException {
        stubFor(get(urlEqualTo("/"))
                .withHeader(WM_AUTHORIZATION, containing(AUTHORIZATIONS.get(1).get(1).toString()))
                .willReturn(aResponse().withStatus(OK_STATUS)));

        checkResultIsPresent(executeConnector(AUTHORIZATIONS_TC.get(1)));
    }

    /**
     * Test the basic auth with username password and realm
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void basicAuthWithUsernamePasswordAndRealm() throws BonitaException, InterruptedException {
        stubFor(get(urlEqualTo("/"))
                .withHeader(WM_AUTHORIZATION, containing(AUTHORIZATIONS.get(2).get(1).toString()))
                .willReturn(aResponse().withStatus(OK_STATUS)));

        checkResultIsPresent(executeConnector(AUTHORIZATIONS_TC.get(2)));
    }

    /**
     * Test the OAuth2 Bearer with token
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void oAuth2BearerAuthWithToken() throws BonitaException, InterruptedException {
        stubFor(get(urlEqualTo("/"))
                .withHeader(WM_AUTHORIZATION, containing(AUTHORIZATIONS.get(3).get(1).toString()))
                .willReturn(aResponse().withStatus(OK_STATUS)));

        checkResultIsPresent(executeConnector(AUTHORIZATIONS_TC.get(3)));
    }

    /**
     * Test no service available
     * @throws InterruptedException exception
     * @throws BonitaException 
     */
    @Test
    public void noServiceAvailable() throws InterruptedException, BonitaException {
        checkResult(executeConnector(METHODS_TC.get(0)), NOT_FOUND_STATUS);
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

        executeConnector(ERRORS_TC.get(0));
    }

    /**
     * Test unreachable port
     * @throws InterruptedException exception
     * @throws BonitaException 
     */
    @Test
    public void unreachablePort() throws InterruptedException, BonitaException {
        thrown.expect(BonitaException.class);
        thrown.expectMessage("org.apache.http.conn.HttpHostConnectException: Connect to localhost:80 [localhost/127.0.0.1, localhost/0:0:0:0:0:0:0:1] failed: Connection refused: connect");

        executeConnector(ERRORS_TC.get(1));
    }

    /**
     * Generic test: should return OK STATUS as the WireMock stub is set each time for the good request shape
     * @param restResult The result of the request
     */
    private void checkResultIsPresent(final Map<String, Object> restResult) {
        checkResult(restResult, OK_STATUS);
    }

    /**
     * Generic test: should return OK STATUS as the WireMock stub is set each time for the good request shape
     * @param restResult The result of the request
     * @param httpStatus HTTP Status to be found as a result
     */
    private void checkResult(final Map<String, Object> restResult, final int httpStatus) {
        assertEquals(restResult.size(), 1);
        assertNotNull(restResult.get(AbstractRESTConnectorImpl.RESULT_OUTPUT_PARAMETER));
        Object result = restResult.get(AbstractRESTConnectorImpl.RESULT_OUTPUT_PARAMETER);
        assertTrue(result instanceof RESTResult);
        RESTResult restResultContent = (RESTResult) result;
        assertEquals(httpStatus, restResultContent.getStatusCode());
    }
}

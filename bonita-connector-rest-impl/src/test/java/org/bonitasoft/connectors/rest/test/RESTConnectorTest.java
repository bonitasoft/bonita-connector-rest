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

package org.bonitasoft.connectors.rest.test;

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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bonitasoft.connectors.rest.RESTConnector;
import org.bonitasoft.connectors.rest.RESTResult;
import org.bonitasoft.engine.exception.BonitaException;
import org.junit.Test;

import com.github.tomakehurst.wiremock.client.MappingBuilder;

/**
 * The class for the UTs of the REST Connector
 */
public class RESTConnectorTest extends AcceptanceTestBase {

    /**
     * HTTP OK STATUS
     */
    private static final int OK_STATUS = 200;
    
    //WireMock
    /**
     * All HTTP static strings used by WireMock to do tests
     */
    private static final String WM_CONTENT_TYPE = "Content-Type";
    private static final String WM_CHARSET = "charset";
    private static final String WM_COOKIES = "Cookie";
    private static final String WM_AUTHORIZATION = "Authorization";
    
    //connector input names
    /**
     * All inputs and outputs accessible from the REST Connector
     */
    private static final String URL_INPUT_PARAMETER = "url";
    private static final String METHOD_INPUT_PARAMETER = "method";
    private static final String CONTENTTYPE_INPUT_PARAMETER = "contentType";
    private static final String CHARSET_INPUT_PARAMETER = "charset";
    private static final String URLCOOKIES_INPUT_PARAMETER = "urlCookies";
    private static final String URLHEADERS_INPUT_PARAMETER = "urlHeaders";
    private static final String BODY_INPUT_PARAMETER = "body";
    private static final String DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER = "do_not_follow_redirect";
    private static final String IGNORE_BODY_INPUT_PARAMETER = "ignore_body";
    private static final String TRUST_SELF_SIGNED_CERTIFICATE_INPUT_PARAMETER = "trust_self_signed_certificate";
    private static final String HOSTNAME_VERIFIER_INPUT_PARAMETER = "hostname_verifier";
    private static final String AUTH_BASIC_USERNAME_INPUT_PARAMETER = "auth_basic_username";
    private static final String AUTH_BASIC_PASSWORD_INPUT_PARAMETER = "auth_basic_password";
    private static final String AUTH_BASIC_HOST_INPUT_PARAMETER = "auth_basic_host";
    private static final String AUTH_BASIC_REALM_INPUT_PARAMETER = "auth_basic_realm";
    private static final String AUTH_BASIC_PREEMPTIVE_INPUT_PARAMETER = "auth_basic_preemptive";
    private static final String AUTH_DIGEST_USERNAME_INPUT_PARAMETER = "auth_digest_username";
    private static final String AUTH_DIGEST_PASSWORD_INPUT_PARAMETER = "auth_digest_password";
    private static final String AUTH_DIGEST_HOST_INPUT_PARAMETER = "auth_digest_host";
    private static final String AUTH_DIGEST_REALM_INPUT_PARAMETER = "auth_digest_realm";
    private static final String AUTH_DIGEST_PREEMPTIVE_INPUT_PARAMETER = "auth_digest_preemptive";
    private static final String AUTH_NTLM_USERNAME_INPUT_PARAMETER = "auth_NTLM_username";
    private static final String AUTH_NTLM_PASSWORD_INPUT_PARAMETER = "auth_NTLM_password";
    private static final String AUTH_NTLM_WORKSTATION_INPUT_PARAMETER = "auth_NTLM_workstation";
    private static final String AUTH_NTLM_DOMAIN_INPUT_PARAMETER = "auth_NTLM_domain";
    private static final String AUTH_OAUTH2_BEARER_TOKEN_INPUT_PARAMETER = "auth_OAuth2_bearer_token";
    private final static String RESULT_OUTPUT_PARAMETER = "result";

    //METHODS
    /**
     * All the tested method values
     */
    private static final String GET = "GET";
    private static final String POST = "POST";
    private static final String PUT = "PUT";
    private static final String DELETE = "DELETE";
    private static final List<String> METHODS = new ArrayList<String>();
    private static final List<Map<String, Object>> METHODS_TC = new ArrayList<Map<String, Object>>();

    //CONTENT_TYPES
    /**
     * All the tested content type values
     */
    private static final String JSON = "application/json";
    private static final String PLAIN_TEXT = "text/plain";
    private static final List<String> CONTENT_TYPES = new ArrayList<String>();
    private static final List<Map<String, Object>> CONTENT_TYPES_TC = new ArrayList<Map<String, Object>>();

    //CHARSETS
    /**
     * All the tested charset values
     */
    private static final String UTF8 = "UTF-8";
    private static final List<String> CHARSETS = new ArrayList<String>();
    private static final List<Map<String, Object>> CHARSETS_TC = new ArrayList<Map<String, Object>>();

    //COOKIES
    /**
     * All the tested cookies values
     */
    private static final List<List<String>> ONE_COOKIES = new ArrayList<List<String>>();
    private static final List<List<String>> TWO_COOKIES = new ArrayList<List<String>>();
    private static final List<List<List<String>>> COOKIESS = new ArrayList<List<List<String>>>();
    private static final List<Map<String, Object>> COOKIESS_TC = new ArrayList<Map<String, Object>>();

    //HEADERS
    /**
     * All the tested headers values
     */
    private static final List<List<String>> ONE_HEADERS = new ArrayList<List<String>>();
    private static final List<List<String>> TWO_HEADERS = new ArrayList<List<String>>();
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

        List<String> header1 = new ArrayList<String>();
        header1.add("header1name");
        header1.add("header1value");
        ONE_HEADERS.add(header1);

        List<String> header2 = new ArrayList<String>();
        header2.add("header2name");
        header2.add("header2value");
        TWO_HEADERS.add(header1);
        TWO_HEADERS.add(header2);

        METHODS.add(GET);
        METHODS.add(POST);
        METHODS.add(PUT);
        METHODS.add(DELETE);

        CONTENT_TYPES.add(PLAIN_TEXT);
        CONTENT_TYPES.add(JSON);

        CHARSETS.add(UTF8);

        COOKIESS.add(ONE_COOKIES);
        COOKIESS.add(TWO_COOKIES);

        HEADERSS.add(ONE_HEADERS);
        HEADERSS.add(TWO_HEADERS);

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

        buildParameters();
    }

    /**
     * Build the parameters for all the tested values
     */
    private static void buildParameters() {
        for (int i = 0; i < METHODS.size(); i++) {
            Map<String, Object> parameters = new HashMap<String, Object>();
            parameters.put(URL_INPUT_PARAMETER, "http://" + getUrl() + ":" + getPort() + "/");
            parameters.put(METHOD_INPUT_PARAMETER, METHODS.get(i));
            parameters.put(CONTENTTYPE_INPUT_PARAMETER, CONTENT_TYPES.get(0));
            parameters.put(CHARSET_INPUT_PARAMETER, CHARSETS.get(0));
            parameters.put(URLCOOKIES_INPUT_PARAMETER, COOKIESS.get(0));
            parameters.put(URLHEADERS_INPUT_PARAMETER, HEADERSS.get(0));
            parameters.put(BODY_INPUT_PARAMETER, BODYS.get(0));
            parameters.put(DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(IGNORE_BODY_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(TRUST_SELF_SIGNED_CERTIFICATE_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(HOSTNAME_VERIFIER_INPUT_PARAMETER, SSL_VERIFIERS.get(0));
            METHODS_TC.add(parameters);
        }

        for (int i = 0; i < CONTENT_TYPES.size(); i++) {
            Map<String, Object> parameters = new HashMap<String, Object>();
            parameters.put(URL_INPUT_PARAMETER, "http://" + getUrl() + ":" + getPort() + "/");
            parameters.put(METHOD_INPUT_PARAMETER, METHODS.get(1));
            parameters.put(CONTENTTYPE_INPUT_PARAMETER, CONTENT_TYPES.get(i));
            parameters.put(CHARSET_INPUT_PARAMETER, CHARSETS.get(0));
            parameters.put(URLCOOKIES_INPUT_PARAMETER, COOKIESS.get(0));
            parameters.put(URLHEADERS_INPUT_PARAMETER, HEADERSS.get(0));
            parameters.put(BODY_INPUT_PARAMETER, BODYS.get(0));
            parameters.put(DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(IGNORE_BODY_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(TRUST_SELF_SIGNED_CERTIFICATE_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(HOSTNAME_VERIFIER_INPUT_PARAMETER, SSL_VERIFIERS.get(0));
            CONTENT_TYPES_TC.add(parameters);
        }

        for (int i = 0; i < CHARSETS.size(); i++) {
            Map<String, Object> parameters = new HashMap<String, Object>();
            parameters.put(URL_INPUT_PARAMETER, "http://" + getUrl() + ":" + getPort() + "/");
            parameters.put(METHOD_INPUT_PARAMETER, METHODS.get(1));
            parameters.put(CONTENTTYPE_INPUT_PARAMETER, CONTENT_TYPES.get(0));
            parameters.put(CHARSET_INPUT_PARAMETER, CHARSETS.get(i));
            parameters.put(URLCOOKIES_INPUT_PARAMETER, COOKIESS.get(0));
            parameters.put(URLHEADERS_INPUT_PARAMETER, HEADERSS.get(0));
            parameters.put(BODY_INPUT_PARAMETER, BODYS.get(0));
            parameters.put(DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(IGNORE_BODY_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(TRUST_SELF_SIGNED_CERTIFICATE_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(HOSTNAME_VERIFIER_INPUT_PARAMETER, SSL_VERIFIERS.get(0));
            CHARSETS_TC.add(parameters);
        }

        for (int i = 0; i < COOKIESS.size(); i++) {
            Map<String, Object> parameters = new HashMap<String, Object>();
            parameters.put(URL_INPUT_PARAMETER, "http://" + getUrl() + ":" + getPort() + "/");
            parameters.put(METHOD_INPUT_PARAMETER, METHODS.get(0));
            parameters.put(CONTENTTYPE_INPUT_PARAMETER, CONTENT_TYPES.get(0));
            parameters.put(CHARSET_INPUT_PARAMETER, CHARSETS.get(0));
            parameters.put(URLCOOKIES_INPUT_PARAMETER, COOKIESS.get(i));
            parameters.put(URLHEADERS_INPUT_PARAMETER, HEADERSS.get(0));
            parameters.put(BODY_INPUT_PARAMETER, BODYS.get(0));
            parameters.put(DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(IGNORE_BODY_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(TRUST_SELF_SIGNED_CERTIFICATE_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(HOSTNAME_VERIFIER_INPUT_PARAMETER, SSL_VERIFIERS.get(0));
            COOKIESS_TC.add(parameters);
        }

        for (int i = 0; i < HEADERSS.size(); i++) {
            Map<String, Object> parameters = new HashMap<String, Object>();
            parameters.put(URL_INPUT_PARAMETER, "http://" + getUrl() + ":" + getPort() + "/");
            parameters.put(METHOD_INPUT_PARAMETER, METHODS.get(0));
            parameters.put(CONTENTTYPE_INPUT_PARAMETER, CONTENT_TYPES.get(0));
            parameters.put(CHARSET_INPUT_PARAMETER, CHARSETS.get(0));
            parameters.put(URLCOOKIES_INPUT_PARAMETER, COOKIESS.get(0));
            parameters.put(URLHEADERS_INPUT_PARAMETER, HEADERSS.get(i));
            parameters.put(BODY_INPUT_PARAMETER, BODYS.get(0));
            parameters.put(DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(IGNORE_BODY_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(TRUST_SELF_SIGNED_CERTIFICATE_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(HOSTNAME_VERIFIER_INPUT_PARAMETER, SSL_VERIFIERS.get(0));
            HEADERSS_TC.add(parameters);
        }

        for (int i = 0; i < BODYS.size(); i++) {
            Map<String, Object> parameters = new HashMap<String, Object>();
            parameters.put(URL_INPUT_PARAMETER, "http://" + getUrl() + ":" + getPort() + "/");
            parameters.put(METHOD_INPUT_PARAMETER, METHODS.get(1));
            parameters.put(CONTENTTYPE_INPUT_PARAMETER, CONTENT_TYPES.get(0));
            parameters.put(CHARSET_INPUT_PARAMETER, CHARSETS.get(0));
            parameters.put(URLCOOKIES_INPUT_PARAMETER, COOKIESS.get(0));
            parameters.put(URLHEADERS_INPUT_PARAMETER, HEADERSS.get(0));
            parameters.put(BODY_INPUT_PARAMETER, BODYS.get(i));
            parameters.put(DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(IGNORE_BODY_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(TRUST_SELF_SIGNED_CERTIFICATE_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(HOSTNAME_VERIFIER_INPUT_PARAMETER, SSL_VERIFIERS.get(0));
            BODYS_TC.add(parameters);
        }

        for (int i = 0; i < AUTHORIZATIONS.size(); i++) {
            Map<String, Object> parameters = new HashMap<String, Object>();
            parameters.put(URL_INPUT_PARAMETER, "http://" + getUrl() + ":" + getPort() + "/");
            parameters.put(METHOD_INPUT_PARAMETER, METHODS.get(0));
            parameters.put(CONTENTTYPE_INPUT_PARAMETER, CONTENT_TYPES.get(0));
            parameters.put(CHARSET_INPUT_PARAMETER, CHARSETS.get(0));
            parameters.put(URLCOOKIES_INPUT_PARAMETER, COOKIESS.get(0));
            parameters.put(URLHEADERS_INPUT_PARAMETER, HEADERSS.get(0));
            parameters.put(BODY_INPUT_PARAMETER, BODYS.get(0));
            parameters.put(DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(IGNORE_BODY_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(TRUST_SELF_SIGNED_CERTIFICATE_INPUT_PARAMETER, Boolean.FALSE);
            parameters.put(HOSTNAME_VERIFIER_INPUT_PARAMETER, SSL_VERIFIERS.get(0));
            int authIndex = 0;
            if (BASIC.equals(AUTHORIZATIONS.get(i).get(authIndex))) {
                authIndex += 2;
                parameters.put(AUTH_BASIC_USERNAME_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
                parameters.put(AUTH_BASIC_PASSWORD_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
                parameters.put(AUTH_BASIC_HOST_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
                parameters.put(AUTH_BASIC_REALM_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
                parameters.put(AUTH_BASIC_PREEMPTIVE_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
            } else if (DIGEST.equals(AUTHORIZATIONS.get(i).get(authIndex))) {
                authIndex += 2;
                parameters.put(AUTH_DIGEST_USERNAME_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
                parameters.put(AUTH_DIGEST_PASSWORD_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
                parameters.put(AUTH_DIGEST_HOST_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
                parameters.put(AUTH_DIGEST_REALM_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
                parameters.put(AUTH_DIGEST_PREEMPTIVE_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
            } else if (NTLM.equals(AUTHORIZATIONS.get(i).get(authIndex))) {
                authIndex += 2;
                parameters.put(AUTH_NTLM_USERNAME_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
                parameters.put(AUTH_NTLM_PASSWORD_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
                parameters.put(AUTH_NTLM_WORKSTATION_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
                parameters.put(AUTH_NTLM_DOMAIN_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(authIndex++));
            } else if (OAUTH2BEARER.equals(AUTHORIZATIONS.get(i).get(authIndex))) {
                parameters.put(AUTH_OAUTH2_BEARER_TOKEN_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(2));
            }

            AUTHORIZATIONS_TC.add(parameters);
        }
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
     * Test the method values
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void sendMethodRESTRequests() throws BonitaException, InterruptedException {
        for (int i = 0; i < METHODS.size(); i++) {
            if (METHODS.get(i).equals(GET)) {
                stubFor(get(urlEqualTo("/"))
                        .willReturn(aResponse().withStatus(OK_STATUS)));
            } else if (METHODS.get(i).equals(POST)) {
                stubFor(post(urlEqualTo("/"))
                        .willReturn(aResponse().withStatus(OK_STATUS)));
            } else if (METHODS.get(i).equals(PUT)) {
                stubFor(put(urlEqualTo("/"))
                        .willReturn(aResponse().withStatus(OK_STATUS)));
            } else if (METHODS.get(i).equals(DELETE)) {
                stubFor(delete(urlEqualTo("/"))
                        .willReturn(aResponse().withStatus(OK_STATUS)));
            }

            checkResultIsPresent(executeConnector(METHODS_TC.get(i)));
            init();
        }
    }

    /**
     * Test the content type values
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void sendContentTypeRESTRequests() throws BonitaException, InterruptedException {
        for (int i = 0; i < CONTENT_TYPES.size(); i++) {
            stubFor(post(urlEqualTo("/"))
                    .withHeader(WM_CONTENT_TYPE, equalTo(CONTENT_TYPES.get(i) + "; " + WM_CHARSET + "=" + CHARSETS.get(0)))
                    .willReturn(aResponse().withStatus(OK_STATUS)));

            checkResultIsPresent(executeConnector(CONTENT_TYPES_TC.get(i)));
            init();
        }
    }

    /**
     * Test the charset values
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void sendCharsetRESTRequests() throws BonitaException, InterruptedException {
        for (int i = 0; i < CHARSETS.size(); i++) {
            stubFor(post(urlEqualTo("/"))
                    .withHeader(WM_CONTENT_TYPE, equalTo(CONTENT_TYPES.get(0) + "; " + WM_CHARSET + "=" + CHARSETS.get(i)))
                    .willReturn(aResponse().withStatus(OK_STATUS)));

            checkResultIsPresent(executeConnector(CHARSETS_TC.get(i)));
            init();
        }
    }

    /**
     * Test the cookies values
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void sendCookiesRESTRequests() throws BonitaException, InterruptedException {
        for (int i = 0; i < COOKIESS.size(); i++) {
            stubFor(get(urlEqualTo("/"))
                    .withHeader(WM_COOKIES, equalTo(generateCookieSet(COOKIESS.get(i))))
                    .willReturn(aResponse().withStatus(OK_STATUS)));

            checkResultIsPresent(executeConnector(COOKIESS_TC.get(i)));
            init();
        }
    }

    /**
     * Generate the cookies string
     * @param cookies The cookies values
     * @return The cookie string
     */
    private String generateCookieSet(final List<List<String>> cookies) {
        StringBuffer strBuffer = new StringBuffer();

        if (!cookies.isEmpty()) {
//            strBuffer.append("$Version=1; " + cookies.get(0).get(0) + "=\"" + cookies.get(0).get(1) + "\"");
          strBuffer.append(cookies.get(0).get(0) + "=" + cookies.get(0).get(1));
        }
        for (int i = 1; i < cookies.size(); i++) {
//            strBuffer.append("; " + cookies.get(i).get(0) + "=\"" + cookies.get(i).get(1) + "\"");
          strBuffer.append("; " + cookies.get(i).get(0) + "=" + cookies.get(i).get(1));
        }

        return strBuffer.toString();
    }

    /**
     * Test the headers values
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void sendHeadersRESTRequests() throws BonitaException, InterruptedException {
        for (int i = 0; i < HEADERSS.size(); i++) {
            MappingBuilder mb = get(urlEqualTo("/"));
            for (int j = 0; j < HEADERSS.get(i).size(); j++) {
                mb.withHeader(HEADERSS.get(i).get(j).get(0), equalTo(HEADERSS.get(i).get(j).get(1)));
            }
            stubFor(mb.willReturn(aResponse().withStatus(OK_STATUS)));

            checkResultIsPresent(executeConnector(HEADERSS_TC.get(i)));
            init();
        }
    }

    /**
     * Test the bodies values
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void sendBodyRESTRequests() throws BonitaException, InterruptedException {
        for (int i = 0; i < BODYS.size(); i++) {
            stubFor(post(urlEqualTo("/"))
                    .withRequestBody(equalTo(BODYS.get(i)))
                    .willReturn(aResponse().withStatus(OK_STATUS)));

            checkResultIsPresent(executeConnector(BODYS_TC.get(i)));
            init();
        }
    }

    /**
     * Test the authentication values
     * @throws BonitaException exception
     * @throws InterruptedException exception
     */
    @Test
    public void sendAuthRESTRequests() throws BonitaException, InterruptedException {
        for (int i = 0; i < AUTHORIZATIONS.size(); i++) {
            stubFor(get(urlEqualTo("/"))
                    .withHeader(WM_AUTHORIZATION, containing(AUTHORIZATIONS.get(i).get(1).toString()))
                    .willReturn(aResponse().withStatus(OK_STATUS)));

            checkResultIsPresent(executeConnector(AUTHORIZATIONS_TC.get(i)));
            init();
        }
    }

    /**
     * Generic test: should return OK STATUS as the WireMock stub is set each time for the good request shape
     * @param restResult The result of the request
     */
    private void checkResultIsPresent(final Map<String, Object> restResult) {
        assertEquals(restResult.size(), 1);
        assertNotNull(restResult.get(RESULT_OUTPUT_PARAMETER));
        Object result = restResult.get(RESULT_OUTPUT_PARAMETER);
        assertTrue(result instanceof RESTResult);
        RESTResult restResultContent = (RESTResult) result;
        assertEquals(OK_STATUS, restResultContent.getStatusCode());
    }
}

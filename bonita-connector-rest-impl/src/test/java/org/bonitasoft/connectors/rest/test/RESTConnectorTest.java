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
import static com.github.tomakehurst.wiremock.client.WireMock.matching;
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

public class RESTConnectorTest extends AcceptanceTestBase {
	//wiser
	final private static String WS_CONTENT_TYPE = "Content-Type";
	final private static String WS_CHARSET = "charset";
	final private static String WS_COOKIES = "Cookie";
	final private static String WS_AUTHORIZATION = "Authorization";
	final private static String WS_FOLLOW_REDIRECT = "Follow-redirect";

	//connector input names
	private final static String URL_INPUT_PARAMETER = "url";
	private final static String METHOD_INPUT_PARAMETER = "method";
	private final static String CONTENTTYPE_INPUT_PARAMETER = "contentType";
	private final static String CHARSET_INPUT_PARAMETER = "charset";
	private final static String URLCOOKIES_INPUT_PARAMETER = "urlCookies";
	private final static String URLHEADERS_INPUT_PARAMETER = "urlHeaders";
	private final static String BODY_INPUT_PARAMETER = "body";
	private final static String DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER = "do_not_follow_redirect";
	private final static String AUTH_BASIC_USERNAME_INPUT_PARAMETER = "auth_basic_username";
	private final static String AUTH_BASIC_PASSWORD_INPUT_PARAMETER = "auth_basic_password";
	private final static String AUTH_BASIC_HOST_INPUT_PARAMETER = "auth_basic_host";
	private final static String AUTH_BASIC_REALM_INPUT_PARAMETER = "auth_basic_realm";
	private final static String AUTH_BASIC_PREEMPTIVE_INPUT_PARAMETER = "auth_basic_preemptive";
	private final static String AUTH_DIGEST_USERNAME_INPUT_PARAMETER = "auth_digest_username";
	private final static String AUTH_DIGEST_PASSWORD_INPUT_PARAMETER = "auth_digest_password";
	private final static String AUTH_DIGEST_HOST_INPUT_PARAMETER = "auth_digest_host";
	private final static String AUTH_DIGEST_REALM_INPUT_PARAMETER = "auth_digest_realm";
	private final static String AUTH_DIGEST_PREEMPTIVE_INPUT_PARAMETER = "auth_digest_preemptive";
	private final static String AUTH_NTLM_USERNAME_INPUT_PARAMETER = "auth_NTLM_username";
	private final static String AUTH_NTLM_PASSWORD_INPUT_PARAMETER = "auth_NTLM_password";
	private final static String AUTH_NTLM_WORKSTATION_INPUT_PARAMETER = "auth_NTLM_workstation";
	private final static String AUTH_NTLM_DOMAIN_INPUT_PARAMETER = "auth_NTLM_domain";
	private final static String AUTH_OAUTH2_BEARER_TOKEN_INPUT_PARAMETER = "auth_OAuth2_bearer_token";

	//connector output names
	private final static String RESULT_OUTPUT_PARAMETER = "result";

	//METHODS
	final private static String GET = "GET";
	final private static String POST = "POST";
	final private static String PUT = "PUT";
	final private static String DELETE = "DELETE";
	final private static List<String> METHODS = new ArrayList<String>();
	final private static List<Map<String, Object>> METHODS_TC = new ArrayList<Map<String, Object>>();

	//CONTENT_TYPES
	final private static String JSON = "application/json";
	final private static String PLAIN_TEXT = "text/plain";
	final private static List<String> CONTENT_TYPES = new ArrayList<String>();
	final private static List<Map<String, Object>> CONTENT_TYPES_TC = new ArrayList<Map<String, Object>>();

	//CHARSETS
	final private static String UTF8 = "UTF-8";
	final private static List<String> CHARSETS = new ArrayList<String>();
	final private static List<Map<String, Object>> CHARSETS_TC = new ArrayList<Map<String, Object>>();

	//COOKIES
	final private static List<List<String>> ONE_COOKIES = new ArrayList<List<String>>();
	final private static List<List<String>> TWO_COOKIES = new ArrayList<List<String>>();
	final private static List<List<List<String>>> COOKIESS = new ArrayList<List<List<String>>>();
	final private static List<Map<String, Object>> COOKIESS_TC = new ArrayList<Map<String, Object>>();

	//HEADERS
	final private static List<List<String>> ONE_HEADERS = new ArrayList<List<String>>();
	final private static List<List<String>> TWO_HEADERS = new ArrayList<List<String>>();
	final private static List<List<List<String>>> HEADERSS = new ArrayList<List<List<String>>>();
	final private static List<Map<String, Object>> HEADERSS_TC = new ArrayList<Map<String, Object>>();

	//BODYS
	final private static String EMPTY = "";
	final private static String FULL ="there is something inside";
	final private static List<String> BODYS = new ArrayList<String>();
	final private static List<Map<String, Object>> BODYS_TC = new ArrayList<Map<String, Object>>();

	//AUTHORIZATIONS
	final private static String BASIC = "BASIC";
	final private static String DIGEST = "DIGEST";
	final private static String NTLM = "NTLM";
	final private static String OAUTH2BEARER = "OAuth2Bearer";
	final private static String BASIC_RULE = "Basic";
	final private static String DIGEST_RULE = "Digest";
	final private static String NTLM_RULE = "NTLM";
	final private static List<List<Object>> AUTHORIZATIONS = new ArrayList<List<Object>>();
	final private static List<Map<String, Object>> AUTHORIZATIONS_TC = new ArrayList<Map<String, Object>>();

	@BeforeClass
	final public static void initValues() {
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
		
		for(int i = 0; i < METHODS.size(); i++) {
			Map<String, Object> parameters = new HashMap<String, Object>();
			parameters.put(URL_INPUT_PARAMETER, "http://" + url + ":" + port + "/");
			parameters.put(METHOD_INPUT_PARAMETER, METHODS.get(i));
			parameters.put(CONTENTTYPE_INPUT_PARAMETER, CONTENT_TYPES.get(0));
			parameters.put(CHARSET_INPUT_PARAMETER, CHARSETS.get(0));
			parameters.put(URLCOOKIES_INPUT_PARAMETER, COOKIESS.get(0));
			parameters.put(URLHEADERS_INPUT_PARAMETER, HEADERSS.get(0));
			parameters.put(BODY_INPUT_PARAMETER, BODYS.get(0));
			parameters.put(DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER, Boolean.FALSE);
			METHODS_TC.add(parameters);
		}

		for(int i = 0; i < CONTENT_TYPES.size(); i++) {
			Map<String, Object> parameters = new HashMap<String, Object>();
			parameters.put(URL_INPUT_PARAMETER, "http://" + url + ":" + port + "/");
			parameters.put(METHOD_INPUT_PARAMETER, METHODS.get(1));
			parameters.put(CONTENTTYPE_INPUT_PARAMETER, CONTENT_TYPES.get(i));
			parameters.put(CHARSET_INPUT_PARAMETER, CHARSETS.get(0));
			parameters.put(URLCOOKIES_INPUT_PARAMETER, COOKIESS.get(0));
			parameters.put(URLHEADERS_INPUT_PARAMETER, HEADERSS.get(0));
			parameters.put(BODY_INPUT_PARAMETER, BODYS.get(0));
			parameters.put(DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER, Boolean.FALSE);
			CONTENT_TYPES_TC.add(parameters);
		}

		for(int i = 0; i < CHARSETS.size(); i++) {
			Map<String, Object> parameters = new HashMap<String, Object>();
			parameters.put(URL_INPUT_PARAMETER, "http://" + url + ":" + port + "/");
			parameters.put(METHOD_INPUT_PARAMETER, METHODS.get(1));
			parameters.put(CONTENTTYPE_INPUT_PARAMETER, CONTENT_TYPES.get(0));
			parameters.put(CHARSET_INPUT_PARAMETER, CHARSETS.get(i));
			parameters.put(URLCOOKIES_INPUT_PARAMETER, COOKIESS.get(0));
			parameters.put(URLHEADERS_INPUT_PARAMETER, HEADERSS.get(0));
			parameters.put(BODY_INPUT_PARAMETER, BODYS.get(0));
			parameters.put(DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER, Boolean.FALSE);
			CHARSETS_TC.add(parameters);
		}

		for(int i = 0; i < COOKIESS.size(); i++) {
			Map<String, Object> parameters = new HashMap<String, Object>();
			parameters.put(URL_INPUT_PARAMETER, "http://" + url + ":" + port + "/");
			parameters.put(METHOD_INPUT_PARAMETER, METHODS.get(0));
			parameters.put(CONTENTTYPE_INPUT_PARAMETER, CONTENT_TYPES.get(0));
			parameters.put(CHARSET_INPUT_PARAMETER, CHARSETS.get(0));
			parameters.put(URLCOOKIES_INPUT_PARAMETER, COOKIESS.get(i));
			parameters.put(URLHEADERS_INPUT_PARAMETER, HEADERSS.get(0));
			parameters.put(BODY_INPUT_PARAMETER, BODYS.get(0));
			parameters.put(DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER, Boolean.FALSE);
			COOKIESS_TC.add(parameters);
		}

		for(int i = 0; i < HEADERSS.size(); i++) {
			Map<String, Object> parameters = new HashMap<String, Object>();
			parameters.put(URL_INPUT_PARAMETER, "http://" + url + ":" + port + "/");
			parameters.put(METHOD_INPUT_PARAMETER, METHODS.get(0));
			parameters.put(CONTENTTYPE_INPUT_PARAMETER, CONTENT_TYPES.get(0));
			parameters.put(CHARSET_INPUT_PARAMETER, CHARSETS.get(0));
			parameters.put(URLCOOKIES_INPUT_PARAMETER, COOKIESS.get(0));
			parameters.put(URLHEADERS_INPUT_PARAMETER, HEADERSS.get(i));
			parameters.put(BODY_INPUT_PARAMETER, BODYS.get(0));
			parameters.put(DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER, Boolean.FALSE);
			HEADERSS_TC.add(parameters);
		}

		for(int i = 0; i < BODYS.size(); i++) {
			Map<String, Object> parameters = new HashMap<String, Object>();
			parameters.put(URL_INPUT_PARAMETER, "http://" + url + ":" + port + "/");
			parameters.put(METHOD_INPUT_PARAMETER, METHODS.get(1));
			parameters.put(CONTENTTYPE_INPUT_PARAMETER, CONTENT_TYPES.get(0));
			parameters.put(CHARSET_INPUT_PARAMETER, CHARSETS.get(0));
			parameters.put(URLCOOKIES_INPUT_PARAMETER, COOKIESS.get(0));
			parameters.put(URLHEADERS_INPUT_PARAMETER, HEADERSS.get(0));
			parameters.put(BODY_INPUT_PARAMETER, BODYS.get(i));
			parameters.put(DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER, Boolean.FALSE);
			BODYS_TC.add(parameters);
		}

		for(int i = 0; i < AUTHORIZATIONS.size(); i++) {
			Map<String, Object> parameters = new HashMap<String, Object>();
			parameters.put(URL_INPUT_PARAMETER, "http://" + url + ":" + port + "/");
			parameters.put(METHOD_INPUT_PARAMETER, METHODS.get(0));
			parameters.put(CONTENTTYPE_INPUT_PARAMETER, CONTENT_TYPES.get(0));
			parameters.put(CHARSET_INPUT_PARAMETER, CHARSETS.get(0));
			parameters.put(URLCOOKIES_INPUT_PARAMETER, COOKIESS.get(0));
			parameters.put(URLHEADERS_INPUT_PARAMETER, HEADERSS.get(0));
			parameters.put(BODY_INPUT_PARAMETER, BODYS.get(0));
			parameters.put(DO_NOT_FOLLOW_REDIRECT_INPUT_PARAMETER, Boolean.FALSE);
			if(BASIC.equals(AUTHORIZATIONS.get(i).get(0))) {
				parameters.put(AUTH_BASIC_USERNAME_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(2));
				parameters.put(AUTH_BASIC_PASSWORD_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(3));
				parameters.put(AUTH_BASIC_HOST_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(4));
				parameters.put(AUTH_BASIC_REALM_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(5));
				parameters.put(AUTH_BASIC_PREEMPTIVE_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(6));
			} else if(DIGEST.equals(AUTHORIZATIONS.get(i).get(0))) {
				parameters.put(AUTH_DIGEST_USERNAME_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(2));
				parameters.put(AUTH_DIGEST_PASSWORD_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(3));
				parameters.put(AUTH_DIGEST_HOST_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(4));
				parameters.put(AUTH_DIGEST_REALM_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(5));
				parameters.put(AUTH_DIGEST_PREEMPTIVE_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(6));
			} else if(NTLM.equals(AUTHORIZATIONS.get(i).get(0))) {
				parameters.put(AUTH_NTLM_USERNAME_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(2));
				parameters.put(AUTH_NTLM_PASSWORD_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(3));
				parameters.put(AUTH_NTLM_WORKSTATION_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(4));
				parameters.put(AUTH_NTLM_DOMAIN_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(5));
			} else if(OAUTH2BEARER.equals(AUTHORIZATIONS.get(i).get(0))) {
				parameters.put(AUTH_OAUTH2_BEARER_TOKEN_INPUT_PARAMETER, AUTHORIZATIONS.get(i).get(2));
			}
			
			AUTHORIZATIONS_TC.add(parameters);
		}
	}

	final private Map<String, Object> executeConnector(final Map<String, Object> parameters) throws BonitaException {
		RESTConnector rest = new RESTConnector();
		rest.setExecutionContext(engineExecutionContext);
		rest.setAPIAccessor(apiAccessor);
		rest.setInputParameters(parameters);
		rest.validateInputParameters();
		return rest.execute();
	}

	@Test
	public void sendMethodRESTRequests() throws BonitaException, InterruptedException {
		for(int i = 0; i < METHODS.size(); i++) {
			if(METHODS.get(i).equals(GET)) {
				stubFor(get(urlEqualTo("/"))
						.willReturn(aResponse().withStatus(200)));
			} else if(METHODS.get(i).equals(POST)) {
				stubFor(post(urlEqualTo("/"))
						.willReturn(aResponse().withStatus(200)));
			} else if(METHODS.get(i).equals(PUT)) {
				stubFor(put(urlEqualTo("/"))
						.willReturn(aResponse().withStatus(200)));
			} else if(METHODS.get(i).equals(DELETE)) {
				stubFor(delete(urlEqualTo("/"))
						.willReturn(aResponse().withStatus(200)));
			}

			checkResultIsPresent(executeConnector(METHODS_TC.get(i)));
			init();
		}
	}

	@Test
	public void sendContentTypeRESTRequests() throws BonitaException, InterruptedException {
		for(int i = 0; i < CONTENT_TYPES.size(); i++) {
			stubFor(post(urlEqualTo("/"))
					.withHeader(WS_CONTENT_TYPE, equalTo(CONTENT_TYPES.get(i) + "; " + WS_CHARSET + "=" + CHARSETS.get(0)))
					.willReturn(aResponse().withStatus(200)));

			checkResultIsPresent(executeConnector(CONTENT_TYPES_TC.get(i)));
			init();
		}
	}

	@Test
	public void sendCharsetRESTRequests() throws BonitaException, InterruptedException {
		for(int i = 0; i < CHARSETS.size(); i++) {
			stubFor(post(urlEqualTo("/"))
					.withHeader(WS_CONTENT_TYPE, equalTo(CONTENT_TYPES.get(0) + "; " + WS_CHARSET + "=" + CHARSETS.get(i)))
					.willReturn(aResponse().withStatus(200)));

			checkResultIsPresent(executeConnector(CHARSETS_TC.get(i)));
			init();
		}
	}

	@Test
	public void sendCookiesRESTRequests() throws BonitaException, InterruptedException {
		for(int i = 0; i < COOKIESS.size(); i++) {
			stubFor(get(urlEqualTo("/"))
					.withHeader(WS_COOKIES, equalTo(generateCookieSet(COOKIESS.get(i))))
					.willReturn(aResponse().withStatus(200)));

			checkResultIsPresent(executeConnector(COOKIESS_TC.get(i)));
			init();
		}
	}

	private String generateCookieSet(List<List<String>> cookies) {
		StringBuffer strBuffer = new StringBuffer();

		if(!cookies.isEmpty()) {
			strBuffer.append(cookies.get(0).get(0) + "=" + cookies.get(0).get(1));
		}
		for(int i = 1; i < cookies.size(); i++) {
			strBuffer.append("; " + cookies.get(i).get(0) + "=" + cookies.get(i).get(1));
		}

		return strBuffer.toString();
	}

	@Test
	public void sendHeadersRESTRequests() throws BonitaException, InterruptedException {
		for(int i = 0; i < HEADERSS.size(); i++) {
			MappingBuilder mb = get(urlEqualTo("/"));
			for(int j = 0; j < HEADERSS.get(i).size(); j++) {
				mb.withHeader(HEADERSS.get(i).get(j).get(0), equalTo(HEADERSS.get(i).get(j).get(1)));
			}
			stubFor(
					mb.willReturn(aResponse().withStatus(200)));

			checkResultIsPresent(executeConnector(HEADERSS_TC.get(i)));
			init();
		}
	}

	@Test
	public void sendBodyRESTRequests() throws BonitaException, InterruptedException {
		for(int i = 0; i < BODYS.size(); i++) {
			stubFor(post(urlEqualTo("/"))
					.withRequestBody(equalTo(BODYS.get(i)))
					.willReturn(aResponse().withStatus(200)));

			checkResultIsPresent(executeConnector(BODYS_TC.get(i)));
			init();
		}
	}
	
	@Test
	public void sendAuthRESTRequests() throws BonitaException, InterruptedException {
		for(int i = 0; i < AUTHORIZATIONS.size(); i++) {
			stubFor(get(urlEqualTo("/"))
					.withHeader(WS_AUTHORIZATION, containing(AUTHORIZATIONS.get(i).get(1).toString()))
					.willReturn(aResponse().withStatus(200)));

			checkResultIsPresent(executeConnector(AUTHORIZATIONS_TC.get(i)));
			init();
		}
	}

	private void checkResultIsPresent(Map<String, Object> restResult) {
		assertEquals(restResult.size(), 1);
		assertNotNull(restResult.get(RESULT_OUTPUT_PARAMETER));
		Object result = restResult.get(RESULT_OUTPUT_PARAMETER);
		assertTrue(result instanceof RESTResult);
		RESTResult restResultContent = (RESTResult) result;
		assertEquals(200, restResultContent.getStatusCode());
	}
}

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
	
	//connector input names
	final private static String URL = "url";
	final private static String METHOD = "method";
	final private static String CONTENT_TYPE = "contentType";
	final private static String CHARSET = "charset";
	final private static String COOKIES = "urlCookies";
	final private static String HEADERS = "urlHeaders";
	final private static String BODY = "body";

	//connector output names
	final private static String RESULT = "result";

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

		for(int i = 0; i < METHODS.size(); i++) {
			Map<String, Object> parameters = new HashMap<String, Object>();
			parameters.put(URL, "http://" + url + ":" + port + "/");
			parameters.put(METHOD, METHODS.get(i));
			parameters.put(CONTENT_TYPE, CONTENT_TYPES.get(0));
			parameters.put(CHARSET, CHARSETS.get(0));
			parameters.put(COOKIES, COOKIESS.get(0));
			parameters.put(HEADERS, HEADERSS.get(0));
			parameters.put(BODY, BODYS.get(0));
			METHODS_TC.add(parameters);
		}

		for(int i = 0; i < CONTENT_TYPES.size(); i++) {
			Map<String, Object> parameters = new HashMap<String, Object>();
			parameters.put(URL, "http://" + url + ":" + port + "/");
			parameters.put(METHOD, METHODS.get(1));
			parameters.put(CONTENT_TYPE, CONTENT_TYPES.get(i));
			parameters.put(CHARSET, CHARSETS.get(0));
			parameters.put(COOKIES, COOKIESS.get(0));
			parameters.put(HEADERS, HEADERSS.get(0));
			parameters.put(BODY, BODYS.get(0));
			CONTENT_TYPES_TC.add(parameters);
		}

		for(int i = 0; i < CHARSETS.size(); i++) {
			Map<String, Object> parameters = new HashMap<String, Object>();
			parameters.put(URL, "http://" + url + ":" + port + "/");
			parameters.put(METHOD, METHODS.get(1));
			parameters.put(CONTENT_TYPE, CONTENT_TYPES.get(0));
			parameters.put(CHARSET, CHARSETS.get(i));
			parameters.put(COOKIES, COOKIESS.get(0));
			parameters.put(HEADERS, HEADERSS.get(0));
			parameters.put(BODY, BODYS.get(0));
			CHARSETS_TC.add(parameters);
		}

		for(int i = 0; i < COOKIESS.size(); i++) {
			Map<String, Object> parameters = new HashMap<String, Object>();
			parameters.put(URL, "http://" + url + ":" + port + "/");
			parameters.put(METHOD, METHODS.get(0));
			parameters.put(CONTENT_TYPE, CONTENT_TYPES.get(0));
			parameters.put(CHARSET, CHARSETS.get(0));
			parameters.put(COOKIES, COOKIESS.get(i));
			parameters.put(HEADERS, HEADERSS.get(0));
			parameters.put(BODY, BODYS.get(0));
			COOKIESS_TC.add(parameters);
		}

		for(int i = 0; i < HEADERSS.size(); i++) {
			Map<String, Object> parameters = new HashMap<String, Object>();
			parameters.put(URL, "http://" + url + ":" + port + "/");
			parameters.put(METHOD, METHODS.get(0));
			parameters.put(CONTENT_TYPE, CONTENT_TYPES.get(0));
			parameters.put(CHARSET, CHARSETS.get(0));
			parameters.put(COOKIES, COOKIESS.get(0));
			parameters.put(HEADERS, HEADERSS.get(i));
			parameters.put(BODY, BODYS.get(0));
			HEADERSS_TC.add(parameters);
		}

		for(int i = 0; i < BODYS.size(); i++) {
			Map<String, Object> parameters = new HashMap<String, Object>();
			parameters.put(URL, "http://" + url + ":" + port + "/");
			parameters.put(METHOD, METHODS.get(1));
			parameters.put(CONTENT_TYPE, CONTENT_TYPES.get(0));
			parameters.put(CHARSET, CHARSETS.get(0));
			parameters.put(COOKIES, COOKIESS.get(0));
			parameters.put(HEADERS, HEADERSS.get(0));
			parameters.put(BODY, BODYS.get(i));
			BODYS_TC.add(parameters);
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

	private void checkResultIsPresent(Map<String, Object> restResult) {
		assertEquals(restResult.size(), 1);
		assertNotNull(restResult.get(RESULT));
		Object result = restResult.get(RESULT);
		assertTrue(result instanceof RESTResult);
		RESTResult restResultContent = (RESTResult) result;
		assertEquals(200, restResultContent.getStatusCode());
	}
}

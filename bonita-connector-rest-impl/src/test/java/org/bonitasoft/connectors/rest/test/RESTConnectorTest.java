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
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.bonitasoft.connectors.rest.RESTConnector;
import org.bonitasoft.connectors.rest.RESTResult;
import org.bonitasoft.engine.exception.BonitaException;
import org.junit.Test;

public class RESTConnectorTest extends AcceptanceTestBase {
	private Map<String, Object> executeConnector(final Map<String, Object> parameters) throws BonitaException {
		RESTConnector rest = new RESTConnector();
		rest.setExecutionContext(engineExecutionContext);
		rest.setAPIAccessor(apiAccessor);
		rest.setInputParameters(parameters);
		rest.validateInputParameters();
		return rest.execute();
	}

	private Map<String, Object> getGetSettings() {
		final Map<String, Object> parameters = new HashMap<String, Object>();
		parameters.put("url", "http://localhost:" + port + "/");
		parameters.put("method", "GET");
		parameters.put("contentType", "application/json");
		parameters.put("charset", "UTF-8");
		parameters.put("urlCookies", new ArrayList<String>());
		parameters.put("urlHeaders", new ArrayList<String>());
		parameters.put("body", "");
		return parameters;
	}

	private Map<String, Object> getPostSettings() {
		final Map<String, Object> parameters = new HashMap<String, Object>();
		return parameters;
	}

	private Map<String, Object> getPutSettings() {
		final Map<String, Object> parameters = new HashMap<String, Object>();
		return parameters;
	}

	private Map<String, Object> getDeleteSettings() {
		final Map<String, Object> parameters = new HashMap<String, Object>();
		return parameters;
	}

	@Test
	public void sendGetRESTRequest() throws BonitaException, InterruptedException {
		stubFor(get(urlEqualTo("/"))
				.willReturn(aResponse()
						.withStatus(200)
						.withHeader("Content-Type", "text/plain")
						.withBody("bonita")));

		Map<String, Object> restResult = executeConnector(getGetSettings());
		assertEquals(restResult.size(), 1);
		assertNotNull(restResult.get("result"));
		Object result = restResult.get("result");
		assertTrue(result instanceof RESTResult);
		RESTResult restResultContent = (RESTResult) result;
		assertEquals(200, restResultContent.getStatusCode());
		assertTrue(restResultContent.getEntity().contains("bonitasoft"));
	}

//	@Test
//	public void sendPostRESTRequest() throws BonitaException, InterruptedException {
//		assertTrue(true);
//	}
//
//	@Test
//	public void sendPutRESTRequest() throws BonitaException, InterruptedException {
//		assertTrue(true);
//	}
//
//	@Test
//	public void sendDeleteRESTRequest() throws BonitaException, InterruptedException {
//		assertTrue(true);
//	}
}

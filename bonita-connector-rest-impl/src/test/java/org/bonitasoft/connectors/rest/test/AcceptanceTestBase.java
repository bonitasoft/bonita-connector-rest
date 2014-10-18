/*
 * Copyright (C) 2011 Thomas Akehurst
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.bonitasoft.connectors.rest.test;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.ServerSocket;

import org.bonitasoft.engine.api.APIAccessor;
import org.bonitasoft.engine.api.ProcessAPI;
import org.bonitasoft.engine.connector.EngineExecutionContext;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;

import com.github.tomakehurst.wiremock.Log4jConfiguration;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.common.Log4jNotifier;

public class AcceptanceTestBase {
	protected EngineExecutionContext engineExecutionContext;
	protected APIAccessor apiAccessor;
	protected ProcessAPI processAPI;

	protected static WireMockServer wireMockServer;
	protected static int port = 8089;
	protected static String url = "localhost";
	
	@BeforeClass
	public static void setupServer() {
		port = findFreePort(port);
		wireMockServer = new WireMockServer(wireMockConfig().port(port).notifier(new Log4jNotifier()));
		wireMockServer.start();
		try {
			Thread.sleep(500);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

	protected static void initValues() {}

	@AfterClass
	public static void serverShutdown() {
		wireMockServer.stop();
	}

	@Before
	public void init() throws InterruptedException {
		engineExecutionContext = mock(EngineExecutionContext.class);
		apiAccessor = mock(APIAccessor.class);
		processAPI = mock(ProcessAPI.class);
		when(apiAccessor.getProcessAPI()).thenReturn(processAPI);
		WireMock.configureFor(url, port);
		Log4jConfiguration.configureLogging(true);
		WireMock.reset();
		Thread.sleep(200);
	}

	private static int findFreePort(int myport) {
		boolean free = false;
		while (!free && myport <= 65535) {
			if (isFreePort(myport)) {
				free = true;
			} else {
				myport++;
			}
		}
		return myport;
	}

	private static boolean isFreePort(final int myport) {
		try {
			final ServerSocket socket = new ServerSocket(myport);
			socket.close();
			return true;
		} catch (final IOException e) {
			return false;
		}
	}

}
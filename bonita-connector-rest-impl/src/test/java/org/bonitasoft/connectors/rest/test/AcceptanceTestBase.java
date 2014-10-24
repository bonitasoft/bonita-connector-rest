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

/**
 * This class is used to handle WireMock Jetty server and BonitaSoft mock for the REST Connector UTs.
 *
 */
public class AcceptanceTestBase {

    /**
     * The sleep time after each WireMock reset
     */
    private static final int SLEEP = 200;
    
    /**
     * The engine execution context of the BonitaSoft mock
     */
    private EngineExecutionContext engineExecutionContext;
    
    /**
     * The apiAccessor BonitaSoft mock
     */
    private APIAccessor apiAccessor;
    
    /**
     * The process API BonitaSoft mock
     */
    private ProcessAPI processAPI;

    /**
     * The WireMock server (mock of the REST services)
     */
    private static WireMockServer wireMockServer;
    
    /**
     * The default port number to use for the WireMock server
     */
    private static final int DEFAULT_PORT = 8089;
    
    /**
     * The maximum number of the port to use for the WireMock server
     */
    private static final int MAX_PORT = 65535;
    
    /**
     * The currently used port for the WireMock server
     */
    private static int port = DEFAULT_PORT;
    
    /**
     * The URL of the WireMock server
     */
    private static String url = "localhost";

    /**
     * The setup of the WireMock server
     */
    @BeforeClass
    public static void setupServer() {
        port = findFreePort(port);
        wireMockServer = new WireMockServer(wireMockConfig().port(port).notifier(new Log4jNotifier()));
        wireMockServer.start();
        try {
            Thread.sleep(SLEEP);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    /**
     * The setdown of the WireMock server
     */
    @AfterClass
    public static void serverShutdown() {
        wireMockServer.stop();
    }

    /**
     * Initialization of the whole test environment
     * 
     * @throws InterruptedException exception
     */
    @Before
    public void init() throws InterruptedException {
        setEngineExecutionContext(mock(EngineExecutionContext.class));
        apiAccessor = mock(APIAccessor.class);
        processAPI = mock(ProcessAPI.class);
        when(apiAccessor.getProcessAPI()).thenReturn(processAPI);
        WireMock.configureFor(url, port);
        Log4jConfiguration.configureLogging(true);
        WireMock.reset();
        Thread.sleep(SLEEP);
    }

    /**
     * Compute the first free port on the localhost
     * 
     * @param myport The first port to check (increment from there)
     * @return The number of the port
     */
    private static int findFreePort(final int myport) {
        int newPort = myport;
        boolean free = false;
        while (!free && newPort <= MAX_PORT) {
            if (isFreePort(newPort)) {
                free = true;
            } else {
                newPort++;
            }
        }
        return newPort;
    }

    /**
     * Is the given port free?
     * @param myport The port to test
     * @return THe answer as boolean
     */
    private static boolean isFreePort(final int myport) {
        try {
            final ServerSocket socket = new ServerSocket(myport);
            socket.close();
            return true;
        } catch (final IOException e) {
            return false;
        }
    }

    /**
     * Get the engine execution context
     * @return the engine execution context
     */
    public EngineExecutionContext getEngineExecutionContext() {
        return engineExecutionContext;
    }

    /**
     * Set the engine execution context
     * @param engineExecutionContext the engine execution context
     */
    public void setEngineExecutionContext(final EngineExecutionContext engineExecutionContext) {
        this.engineExecutionContext = engineExecutionContext;
    }

    /**
     * Get the API accessor
     * @return the API accessor
     */
    public APIAccessor getApiAccessor() {
        return apiAccessor;
    }

    /**
     * Set the API accessor
     * @param apiAccessor the API accessor
     */
    public void setApiAccessor(final APIAccessor apiAccessor) {
        this.apiAccessor = apiAccessor;
    }

    /**
     * Get the port
     * @return the port
     */
    public static int getPort() {
        return port;
    }

    /**
     * Set the port
     * @param port the port
     */
    public static void setPort(final int port) {
        AcceptanceTestBase.port = port;
    }

    /**
     * Get the URL
     * @return the URL
     */
    public static String getUrl() {
        return url;
    }

    /**
     * Set the URL
     * @param url the URL
     */
    public static void setUrl(final String url) {
        AcceptanceTestBase.url = url;
    }

}

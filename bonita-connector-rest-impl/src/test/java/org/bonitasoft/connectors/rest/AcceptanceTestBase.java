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

import org.bonitasoft.engine.api.APIAccessor;
import org.bonitasoft.engine.api.ProcessAPI;
import org.bonitasoft.engine.connector.EngineExecutionContext;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.mockito.Mockito;

import com.github.tomakehurst.wiremock.Log4jConfiguration;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.common.Log4jNotifier;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

/**
 * This class is used to handle WireMock Jetty server and BonitaSoft mock for the REST Connector UTs.
 *
 */
public class AcceptanceTestBase {
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
    protected static WireMockServer wireMockServer;
    
    /**
     * The URL of the WireMock server
     */
    protected static final String LOCALHOST = "LOCALHOST";

    /**
     * The setup of the WireMock server
     */
    @BeforeClass
    public static void setupServer() {
        wireMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig().port(0).notifier(new Log4jNotifier()));
        wireMockServer.start();
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
        setEngineExecutionContext(Mockito.mock(EngineExecutionContext.class));
        apiAccessor = Mockito.mock(APIAccessor.class);
        processAPI = Mockito.mock(ProcessAPI.class);
        Mockito.when(apiAccessor.getProcessAPI()).thenReturn(processAPI);
        WireMock.configureFor(LOCALHOST, wireMockServer.port());
        Log4jConfiguration.configureLogging(true);
        WireMock.reset();
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



}

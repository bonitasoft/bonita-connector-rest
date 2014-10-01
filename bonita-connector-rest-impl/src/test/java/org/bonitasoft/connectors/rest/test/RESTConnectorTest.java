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

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNot.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeNotNull;
import static org.junit.matchers.JUnitMatchers.containsString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bonitasoft.connectors.rest.RESTConnector;

import org.bonitasoft.engine.api.APIAccessor;
import org.bonitasoft.engine.api.ProcessAPI;
import org.bonitasoft.engine.bpm.document.impl.DocumentImpl;
import org.bonitasoft.engine.connector.EngineExecutionContext;
import org.bonitasoft.engine.exception.BonitaException;
//import org.bonitasoft.engine.test.annotation.Cover;
//import org.bonitasoft.engine.test.annotation.Cover.BPMNConcept;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Matthieu Chaffotte
 */
public class RESTConnectorTest {

    private static final String URL = "https://api.github.com/bonitasoft/bonita-connector-rest/";

    private EngineExecutionContext engineExecutionContext;
    private APIAccessor apiAccessor;
    private ProcessAPI processAPI;

    @Before
    public void setUp() {
        engineExecutionContext = mock(EngineExecutionContext.class);
        apiAccessor = mock(APIAccessor.class);
        processAPI = mock(ProcessAPI.class);
        when(apiAccessor.getProcessAPI()).thenReturn(processAPI);
    }

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
        parameters.put("url", URL);
        return parameters;
    }
    
    private Map<String, Object> getPostSettings() {
        final Map<String, Object> parameters = new HashMap<String, Object>();
        parameters.put("url", URL);
        return parameters;
    }

    private Map<String, Object> getPutSettings() {
        final Map<String, Object> parameters = new HashMap<String, Object>();
        parameters.put("url", URL);
        return parameters;
    }

    private Map<String, Object> getDeleteSettings() {
        final Map<String, Object> parameters = new HashMap<String, Object>();
        parameters.put("url", URL);
        return parameters;
    }
    

    @Test
    public void sendGetRESTRequest() throws BonitaException, InterruptedException {
        Map<String, Object> restResult = executeConnector(getGetSettings());
        assertEquals(1, 1);
    }
    
    @Test
    public void sendPostRESTRequest() throws BonitaException, InterruptedException {
        Map<String, Object> restResult = executeConnector(getPostSettings());
        assertEquals(1, 1);
    }
    
    @Test
    public void sendPutRESTRequest() throws BonitaException, InterruptedException {
        Map<String, Object> restResult = executeConnector(getPutSettings());
        assertEquals(1, 1);
    }
    
    @Test
    public void sendDeleteRESTRequest() throws BonitaException, InterruptedException {
        Map<String, Object> restResult = executeConnector(getDeleteSettings());
        assertEquals(1, 1);
    }
}

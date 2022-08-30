package org.bonitasoft.connectors.rest;

import static org.awaitility.Awaitility.await;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import org.bonitasoft.web.client.BonitaClient;
import org.bonitasoft.web.client.api.ArchivedProcessInstanceApi;
import org.bonitasoft.web.client.api.ProcessInstanceApi;
import org.bonitasoft.web.client.exception.NotFoundException;
import org.bonitasoft.web.client.model.ArchivedProcessInstance;
import org.bonitasoft.web.client.services.policies.OrganizationImportPolicy;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import com.fasterxml.jackson.databind.ObjectMapper;


public class RestConnectorIT {

    private static final Logger LOGGER = LoggerFactory.getLogger(RestConnectorIT.class);

    @Rule
    public GenericContainer bonita = new GenericContainer(
            DockerImageName.parse("bonita:7.14.0")) // 7.14.0 only because no archiveinstance support with 7.13.0 (can't test the output)
                    .withExposedPorts(8080)
                    .waitingFor(Wait.forHttp("/bonita"))
                    .withLogConsumer(new Slf4jLogConsumer(LOGGER));
    private BonitaClient client;

    @Before
    public void setup() {
        client = BonitaClient
                .builder(String.format("http://%s:%s/bonita", bonita.getHost(), bonita.getFirstMappedPort())).build();
        client.login("install", "install");
        client.users().importOrganization(new File(RestConnectorIT.class.getResource("/ACME.xml").getFile()),
                OrganizationImportPolicy.IGNORE_DUPLICATES);
        client.logout();
    }

    @Test
    public void testRestGetConnectorIntegration() throws Exception {
        // Id connector and version to be tested.
        var connectorId = "rest-get";
        var versionId = "1.2.0";

        // Inputs
        Map<String, String> inputsConnector = new HashMap<>();
        inputsConnector.put("url", "https://jsonplaceholder.typicode.com/todos/1");

        // Outputs
        Map<String, String> outputsConnector = new HashMap<>();
        outputsConnector.put("resultRestGet", "bodyAsString");

        // Building process with connector 
        var barFile = ConnectorTestToolkit.buildConnectorToTest(connectorId, versionId, inputsConnector,
                outputsConnector, "bonita-connector-rest-1.3.0-SNAPSHOT.jar");

        // Importing and launching the process contained in the business archive
        var processResponse = ConnectorTestToolkit.importAndLaunchProcess(barFile, client);

        // Wait until the process launched is completed (and not failed)
        await().until(pollInstanceState(client, processResponse.getCaseId()), "completed"::equals);
        assertTrue(client.system().isCommunity());

        // Getting the result of the rest call.
        String resultRestGetResult = (String) ConnectorTestToolkit.getProcessVariableValue(client, processResponse.getCaseId(), "resultRestGet");
        assertNotNull(resultRestGetResult);

        ObjectMapper mapper = new ObjectMapper();
        var map = mapper.readValue(resultRestGetResult, Map.class);
        assertEquals(map.get("userId"), 1);
        assertEquals(map.get("id"), 1);
        assertEquals(map.get("title"), "delectus aut autem");
        assertEquals(map.get("completed"), false);

        client.logout();
    }

    @Test
    public void testRestHeadConnectorIntegration() throws Exception {
        // Id connector and version to be tested.
        var connectorId = "rest-head";
        var versionId = "1.0.0";

        // Inputs
        Map<String, String> inputsConnector = new HashMap<>();
        inputsConnector.put("url", "https://jsonplaceholder.typicode.com/posts/1");

        // Outputs
        //TODO Adding output with the map type.

        // Building process with connector 
        var barFile = ConnectorTestToolkit.buildConnectorToTest(connectorId, versionId, inputsConnector, null,
                "bonita-connector-rest-1.3.0-SNAPSHOT.jar");

        // Importing and launching the process contained in the business archive
        var processResponse = ConnectorTestToolkit.importAndLaunchProcess(barFile, client);

        // Wait until the process launched is completed (and not failed)
        await().until(pollInstanceState(client, processResponse.getCaseId()), "completed"::equals);

        assertTrue(client.system().isCommunity());

        client.logout();
    }

    @Test
    public void testRestPostConnectorIntegration() throws Exception {
        // Id connector and version to be tested.
        var connectorId = "rest-post";
        var versionId = "1.3.0";

        // Inputs
        Map<String, String> inputsConnector = new HashMap<>();
        inputsConnector.put("url", "https://jsonplaceholder.typicode.com/posts/1");
        inputsConnector.put("contentType", "application/json");
        inputsConnector.put("charset", "UTF-8");

        // Outputs

        // Building process with connector 
        var barFile = ConnectorTestToolkit.buildConnectorToTest(connectorId, versionId, inputsConnector, null,
                "bonita-connector-rest-1.3.0-SNAPSHOT.jar");

        // Importing and launching the process contained in the business archive
        var processResponse = ConnectorTestToolkit.importAndLaunchProcess(barFile, client);

        // Wait until the process launched is completed (and not failed)
        await().until(pollInstanceState(client, processResponse.getCaseId()), "completed"::equals);

        assertTrue(client.system().isCommunity());

        client.logout();
    }

    @Test
    public void testRestPutConnectorIntegration() throws Exception {
        // Id connector and version to be tested.
        var connectorId = "rest-put";
        var versionId = "1.3.0";

        // Inputs
        Map<String, String> inputsConnector = new HashMap<>();
        inputsConnector.put("url", "https://jsonplaceholder.typicode.com/posts/1");
        inputsConnector.put("contentType", "application/json");
        inputsConnector.put("charset", "UTF-8");

        // Outputs

        // Building process with connector 
        var barFile = ConnectorTestToolkit.buildConnectorToTest(connectorId, versionId, inputsConnector, null,
                "bonita-connector-rest-1.3.0-SNAPSHOT.jar");

        // Importing and launching the process contained in the business archive
        var processResponse = ConnectorTestToolkit.importAndLaunchProcess(barFile, client);

        // Wait until the process launched is completed (and not failed)
        await().until(pollInstanceState(client, processResponse.getCaseId()), "completed"::equals);

        assertTrue(client.system().isCommunity());

        client.logout();
    }
    
    @Test
    public void testRestFilePutConnectorIntegration() throws Exception {
        // Id connector and version to be tested.
        var connectorId = "rest-file-put";
        var versionId = "1.0.0";

        // Inputs
        Map<String, String> inputsConnector = new HashMap<>();
        inputsConnector.put("url", "https://jsonplaceholder.typicode.com/posts/1");
        inputsConnector.put("contentType", "application/json");
        inputsConnector.put("charset", "UTF-8");

        // Outputs

        // Building process with connector 
        var barFile = ConnectorTestToolkit.buildConnectorToTest(connectorId, versionId, inputsConnector, null,
                "bonita-connector-rest-1.3.0-SNAPSHOT.jar");

        // Importing and launching the process contained in the business archive
        var processResponse = ConnectorTestToolkit.importAndLaunchProcess(barFile, client);

        // Wait until the process launched is completed (and not failed)
        await().until(pollInstanceState(client, processResponse.getCaseId()), "completed"::equals);

        assertTrue(client.system().isCommunity());

        client.logout();
    }
    
    @Test
    public void testRestFilePostConnectorIntegration() throws Exception {
        // Id connector and version to be tested.
        var connectorId = "rest-file-post";
        var versionId = "1.0.0";

        // Inputs
        Map<String, String> inputsConnector = new HashMap<>();
        inputsConnector.put("url", "https://jsonplaceholder.typicode.com/posts/1");
        inputsConnector.put("contentType", "application/json");
        inputsConnector.put("charset", "UTF-8");

        // Outputs

        // Building process with connector 
        var barFile = ConnectorTestToolkit.buildConnectorToTest(connectorId, versionId, inputsConnector, null,
                "bonita-connector-rest-1.3.0-SNAPSHOT.jar");

        // Importing and launching the process contained in the business archive
        var processResponse = ConnectorTestToolkit.importAndLaunchProcess(barFile, client);

        // Wait until the process launched is completed (and not failed)
        await().until(pollInstanceState(client, processResponse.getCaseId()), "completed"::equals);

        assertTrue(client.system().isCommunity());

        client.logout();
    }
    
    @Test
    public void testRestDeleteConnectorIntegration() throws Exception {
        // Id connector and version to be tested.
        var connectorId = "rest-delete";
        var versionId = "1.2.0";

        // Inputs
        Map<String, String> inputsConnector = new HashMap<>();
        inputsConnector.put("url", "https://jsonplaceholder.typicode.com/posts/1");

        // Outputs

        // Building process with connector 
        var barFile = ConnectorTestToolkit.buildConnectorToTest(connectorId, versionId, inputsConnector, null,
                "bonita-connector-rest-1.3.0-SNAPSHOT.jar");

        // Importing and launching the process contained in the business archive
        var processResponse = ConnectorTestToolkit.importAndLaunchProcess(barFile, client);

        // Wait until the process launched is completed (and not failed)
        await().until(pollInstanceState(client, processResponse.getCaseId()), "completed"::equals);

        assertTrue(client.system().isCommunity());

        client.logout();
    }

    private Callable<String> pollInstanceState(BonitaClient client, String id) {
        return () -> {
            try {
                var instance = client.get(ProcessInstanceApi.class).getProcessInstanceById(id, (String) null);
                return instance.getState().toLowerCase();
            } catch (NotFoundException e) {
                return getCompletedProcess(id).getState().toLowerCase();
            }
        };
    }

    private ArchivedProcessInstance getCompletedProcess(String id) {
        var archivedInstances = client.get(ArchivedProcessInstanceApi.class)
                .searchArchivedProcessInstances(
                        new ArchivedProcessInstanceApi.SearchArchivedProcessInstancesQueryParams()
                                .c(1)
                                .p(0)
                                .f(List.of("caller=any", "sourceObjectId=" + id)));
        if (!archivedInstances.isEmpty()) {
            return archivedInstances.get(0);
        }
        return null;
    }

}

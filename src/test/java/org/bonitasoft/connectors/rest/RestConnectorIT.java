package org.bonitasoft.connectors.rest;

import static org.awaitility.Awaitility.await;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Callable;

import org.bonitasoft.web.client.BonitaClient;
import org.bonitasoft.web.client.api.ArchivedProcessInstanceApi;
import org.bonitasoft.web.client.api.ProcessInstanceApi;
import org.bonitasoft.web.client.exception.NotFoundException;
import org.bonitasoft.web.client.model.ArchivedProcessInstance;
import org.bonitasoft.web.client.services.policies.OrganizationImportPolicy;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import com.fasterxml.jackson.databind.ObjectMapper;

public class RestConnectorIT {

    private static final String REST_HEAD_DEF_VERSION = "1.0.0";
    private static final String REST_HEAD_DEF_ID = "rest-head";
    
    private static final String REST_GET_DEF_VERSION = "1.2.0";
    private static final String REST_GET_DEF_ID = "rest-get";
    
    private static final String REST_POST_DEF_VERSION = "1.3.0";
    private static final String REST_POST_DEF_ID = "rest-post";
    
    private static final String REST_FILE_POST_DEF_VERSION = "1.0.0";
    private static final String REST_FILE_POST_DEF_ID = "rest-file-post";
    
    private static final String REST_PUT_DEF_VERSION = "1.3.0";
    private static final String REST_PUT_DEF_ID = "rest-put";
    
    private static final String REST_FILE_PUT_DEF_VERSION = "1.0.0";
    private static final String REST_FILE_PUT_DEF_ID = "rest-file-put";
    
    private static final String REST_DELETE_DEF_VERSION = "1.2.0";
    private static final String REST_DELETE_DEF_ID = "rest-delete";

    private static final Logger LOGGER = LoggerFactory.getLogger(RestConnectorIT.class);

    private static final String ARTIFACT_ID = "bonita-connector-rest";
    private static final String BONITA_VERSION = Objects.requireNonNull(System.getProperty("bonita.version"), "'bonita.version' system property not defined !");

    @ClassRule
    public static GenericContainer<?> BONITA_CONTAINER = new GenericContainer<>(
            DockerImageName.parse(String.format("bonita:%s", BONITA_VERSION)))
                    .withExposedPorts(8080)
                    .waitingFor(Wait.forHttp("/bonita"))
                    .withLogConsumer(new Slf4jLogConsumer(LOGGER));

    @BeforeClass
    public static void installOrganization() {
        var client = BonitaClient
                .builder(String.format("http://%s:%s/bonita", BONITA_CONTAINER.getHost(),
                        BONITA_CONTAINER.getFirstMappedPort()))
                .build();
        client.login("install", "install");
        client.users().importOrganization(new File(RestConnectorIT.class.getResource("/ACME.xml").getFile()),
                OrganizationImportPolicy.IGNORE_DUPLICATES);
        client.logout();
    }

    private BonitaClient client;

    @Before
    public void login() {
        client = BonitaClient
                .builder(String.format("http://%s:%s/bonita", BONITA_CONTAINER.getHost(),
                        BONITA_CONTAINER.getFirstMappedPort()))
                .build();
        client.login("install", "install");
    }

    @After
    public void logout() {
        client.logout();
    }

    @Test
    public void testRestGetConnectorIntegration() throws Exception {
        // Inputs
        Map<String, String> inputsConnector = new HashMap<>();
        inputsConnector.put("url", "https://jsonplaceholder.typicode.com/todos/1");

        // Outputs
        Map<String, String> outputsConnector = new HashMap<>();
        outputsConnector.put("resultRestGet", "bodyAsString");

        // Building process with connector 
        var barFile = ConnectorTestToolkit.buildConnectorToTest(REST_GET_DEF_ID, REST_GET_DEF_VERSION, inputsConnector,
                outputsConnector, ARTIFACT_ID);

        // Importing and launching the process contained in the business archive
        var processResponse = ConnectorTestToolkit.importAndLaunchProcess(barFile, client);

        // Wait until the process launched is started (and not failed)
        await().until(pollInstanceState(client, processResponse.getCaseId()), "started"::equals);

        // Getting the result of the rest call.
        String resultRestGetResult = (String) ConnectorTestToolkit.getProcessVariableValue(client,
                processResponse.getCaseId(), "resultRestGet");
        assertNotNull(resultRestGetResult);

        ObjectMapper mapper = new ObjectMapper();
        var map = mapper.readValue(resultRestGetResult, Map.class);
        assertEquals(1, map.get("userId"));
        assertEquals(1, map.get("id"));
        assertEquals("delectus aut autem", map.get("title"));
        assertFalse((boolean) map.get("completed"));
    }

    @Test
    public void testRestHeadConnectorIntegration() throws Exception {
        // Inputs
        Map<String, String> inputsConnector = new HashMap<>();
        inputsConnector.put("url", "https://jsonplaceholder.typicode.com/posts/1");

        // Outputs
        //TODO Adding output with the map type.

        // Building process with connector 
        var barFile = ConnectorTestToolkit.buildConnectorToTest(REST_HEAD_DEF_ID, REST_HEAD_DEF_VERSION, inputsConnector, null,
                ARTIFACT_ID);

        // Importing and launching the process contained in the business archive
        var processResponse = ConnectorTestToolkit.importAndLaunchProcess(barFile, client);

        // Wait until the process launched is started (and not failed)
        await().until(pollInstanceState(client, processResponse.getCaseId()), "started"::equals);
    }

    @Test
    public void testRestPostConnectorIntegration() throws Exception {
        // Inputs
        Map<String, String> inputsConnector = new HashMap<>();
        inputsConnector.put("url", "https://jsonplaceholder.typicode.com/posts/1");
        inputsConnector.put("contentType", "application/json");
        inputsConnector.put("charset", "UTF-8");

        // Outputs

        // Building process with connector 
        var barFile = ConnectorTestToolkit.buildConnectorToTest(REST_POST_DEF_ID, REST_POST_DEF_VERSION, inputsConnector, null,
                ARTIFACT_ID);

        // Importing and launching the process contained in the business archive
        var processResponse = ConnectorTestToolkit.importAndLaunchProcess(barFile, client);

        // Wait until the process launched is started (and not failed)
        await().until(pollInstanceState(client, processResponse.getCaseId()), "started"::equals);
    }

    @Test
    public void testRestPutConnectorIntegration() throws Exception {
        // Inputs
        Map<String, String> inputsConnector = new HashMap<>();
        inputsConnector.put("url", "https://jsonplaceholder.typicode.com/posts/1");
        inputsConnector.put("contentType", "application/json");
        inputsConnector.put("charset", "UTF-8");

        // Outputs

        // Building process with connector 
        var barFile = ConnectorTestToolkit.buildConnectorToTest(REST_PUT_DEF_ID, REST_PUT_DEF_VERSION, inputsConnector, null,
                ARTIFACT_ID);

        // Importing and launching the process contained in the business archive
        var processResponse = ConnectorTestToolkit.importAndLaunchProcess(barFile, client);

        // Wait until the process launched is started (and not failed)
        await().until(pollInstanceState(client, processResponse.getCaseId()), "started"::equals);
    }

    @Test
    public void testRestFilePutConnectorIntegration() throws Exception {
        // Inputs
        Map<String, String> inputsConnector = new HashMap<>();
        inputsConnector.put("url", "https://jsonplaceholder.typicode.com/posts/1");
        inputsConnector.put("contentType", "application/json");
        inputsConnector.put("charset", "UTF-8");

        // Outputs

        // Building process with connector 
        var barFile = ConnectorTestToolkit.buildConnectorToTest(REST_FILE_PUT_DEF_ID, REST_FILE_PUT_DEF_VERSION, inputsConnector, null,
                ARTIFACT_ID);

        // Importing and launching the process contained in the business archive
        var processResponse = ConnectorTestToolkit.importAndLaunchProcess(barFile, client);

        // Wait until the process launched is started (and not failed)
        await().until(pollInstanceState(client, processResponse.getCaseId()), "started"::equals);
    }

    @Test
    public void testRestFilePostConnectorIntegration() throws Exception {
        // Inputs
        Map<String, String> inputsConnector = new HashMap<>();
        inputsConnector.put("url", "https://jsonplaceholder.typicode.com/posts/1");
        inputsConnector.put("contentType", "application/json");
        inputsConnector.put("charset", "UTF-8");

        // Outputs

        // Building process with connector 
        var barFile = ConnectorTestToolkit.buildConnectorToTest(REST_FILE_POST_DEF_ID, REST_FILE_POST_DEF_VERSION, inputsConnector, null,
                ARTIFACT_ID);

        // Importing and launching the process contained in the business archive
        var processResponse = ConnectorTestToolkit.importAndLaunchProcess(barFile, client);

        // Wait until the process launched is started (and not failed)
        await().until(pollInstanceState(client, processResponse.getCaseId()), "started"::equals);
    }

    @Test
    public void testRestDeleteConnectorIntegration() throws Exception {
        // Inputs
        Map<String, String> inputsConnector = new HashMap<>();
        inputsConnector.put("url", "https://jsonplaceholder.typicode.com/posts/1");

        // Outputs

        // Building process with connector 
        var barFile = ConnectorTestToolkit.buildConnectorToTest(REST_DELETE_DEF_ID, REST_DELETE_DEF_VERSION, inputsConnector, null,
                ARTIFACT_ID);

        // Importing and launching the process contained in the business archive
        var processResponse = ConnectorTestToolkit.importAndLaunchProcess(barFile, client);

        // Wait until the process launched is started (and not failed)
        await().until(pollInstanceState(client, processResponse.getCaseId()), "started"::equals);
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

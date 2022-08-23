package org.bonitasoft.connectors.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.function.Predicate;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;

import org.bonitasoft.engine.bpm.bar.BarResource;
import org.bonitasoft.engine.bpm.bar.BusinessArchiveBuilder;
import org.bonitasoft.engine.bpm.bar.BusinessArchiveFactory;
import org.bonitasoft.engine.bpm.bar.actorMapping.Actor;
import org.bonitasoft.engine.bpm.bar.actorMapping.ActorMapping;
import org.bonitasoft.engine.bpm.connector.ConnectorEvent;
import org.bonitasoft.engine.bpm.process.DesignProcessDefinition;
import org.bonitasoft.engine.bpm.process.impl.ProcessDefinitionBuilder;
import org.bonitasoft.engine.expression.ExpressionBuilder;
import org.bonitasoft.engine.operation.OperationBuilder;
import org.bonitasoft.web.client.BonitaClient;
import org.bonitasoft.web.client.api.ArchivedProcessInstanceApi;
import org.bonitasoft.web.client.api.ProcessInstanceApi;
import org.bonitasoft.web.client.exception.NotFoundException;
import org.bonitasoft.web.client.services.policies.OrganizationImportPolicy;
import org.bonitasoft.web.client.services.policies.ProcessImportPolicy;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

public class RestConnectorIT {

    private static final Logger LOGGER = LoggerFactory.getLogger(RestConnectorIT.class);

    @Rule
    public GenericContainer bonita = new GenericContainer(
            DockerImageName.parse("bonita:" + System.getProperty("bonita.version")))
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
    public void testConnectorIntegration() throws Exception {
        var barBuilder = new BusinessArchiveBuilder();

        var processBuilder = new ProcessDefinitionBuilder();
        processBuilder.createNewInstance("myNewProcess", "1.0");
        processBuilder.addActor("system");
        var expBuilder = new ExpressionBuilder();
        var operationBuilder = new OperationBuilder();
        var connectorBuilder = processBuilder.addConnector("connector-under-test", "rest-get", "1.2.0",
                ConnectorEvent.ON_ENTER);
        connectorBuilder.addInput("url", expBuilder.createConstantStringExpression(
                "https://www.toptal.com/developers/postbin/1661262481902-8526414958760?hello=world"));
        //        connectorBuilder.addOutput(operationBuilder.createNewInstance().createSetDataOperation(
        //                String.class.getTypeName(), expBuilder.createConstantStringExpression("RETOUR REST")));

        DesignProcessDefinition process = processBuilder.done();

        barBuilder.createNewBusinessArchive();
        barBuilder.setProcessDefinition(process);

        // Open question:
        // How to retrieve the proper classpath ?
        // It seems smarter to rely on a the project builder than reimplementing another mechanism.

        var connectorJar = new File("").getAbsoluteFile().toPath()
                .resolve("target")
                .resolve("bonita-connector-rest-1.3.0-SNAPSHOT.jar")
                .toFile();
        assertThat(connectorJar).exists();
        List<JarEntry> jarEntries = findJarEntries(connectorJar, entry -> entry.getName().equals("rest-get.impl"));
        assertThat(jarEntries).hasSize(1);
        var implEntry = jarEntries.get(0);

        byte[] content = null;
        try (JarFile jarFile = new JarFile(connectorJar)) {
            InputStream inputStream = jarFile.getInputStream(implEntry);
            content = inputStream.readAllBytes();
        }

        barBuilder.addConnectorImplementation(
                new BarResource("rest-get.impl", content));
        barBuilder.addClasspathResource(
                new BarResource(connectorJar.getName(), Files.readAllBytes(connectorJar.toPath())));
        ActorMapping actorMapping = new ActorMapping();
        var systemActor = new Actor("system");
        systemActor.addRole("member");
        actorMapping.addActor(systemActor);
        barBuilder.setActorMapping(actorMapping);
        var barArchive = barBuilder.done();

        var processFile = new File("process.bar");
        if (processFile.exists()) {
            processFile.delete();
        }

        BusinessArchiveFactory.writeBusinessArchiveToFile(barArchive, processFile);
        client.login("install", "install");
        client.processes().importProcess(processFile, ProcessImportPolicy.REPLACE_DUPLICATES);
        var processId = client.processes().getProcess(process.getName(), process.getVersion()).getId();
        client.processes().getProcessProblem(0, 99, processId);
        var processResponse = client.processes().startProcess(processId, Map.of());

        await()
                .until(pollInstanceState(client, processResponse.getCaseId()), "completed"::equals);

        assertTrue(client.system().isCommunity());
        processFile.delete();
    }

    private Callable<String> pollInstanceState(BonitaClient client, String id){
        return () -> {
            try {
                var instance =  client.get(ProcessInstanceApi.class).getProcessInstanceById(id, (String) null);
                return instance.getState().toLowerCase();
            }catch (NotFoundException e) {
                var archivedInstances = client.get(ArchivedProcessInstanceApi.class)
                            .searchArchivedProcessInstances(new ArchivedProcessInstanceApi.SearchArchivedProcessInstancesQueryParams()
                                    .c(1)
                                    .p(0)
                                    .f(List.of("caller=any","sourceObjectId=" + id)));
                if(!archivedInstances.isEmpty()) {
                    return archivedInstances.get(0).getState().toLowerCase();
                }
                throw e;
            }
        };
    }

    static List<JarEntry> findJarEntries(File file, Predicate<? super JarEntry> entryPredicate)
            throws IOException {
        try (JarFile jarFile = new JarFile(file)) {
            return jarFile.stream()
                    .filter(entryPredicate)
                    .collect(Collectors.toList());
        }
    }

    private InputStream getFileFromResourceAsStream(String fileName) {

        // The class loader that loaded the class
        ClassLoader classLoader = getClass().getClassLoader();
        InputStream inputStream = classLoader.getResourceAsStream(fileName);

        // the stream holding the file content
        if (inputStream == null) {
            throw new IllegalArgumentException("file not found! " + fileName);
        } else {
            return inputStream;
        }

    }

}

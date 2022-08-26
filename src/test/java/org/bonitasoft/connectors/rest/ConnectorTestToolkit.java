package org.bonitasoft.connectors.rest;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;

import org.bonitasoft.engine.bpm.bar.BarResource;
import org.bonitasoft.engine.bpm.bar.BusinessArchive;
import org.bonitasoft.engine.bpm.bar.BusinessArchiveBuilder;
import org.bonitasoft.engine.bpm.bar.BusinessArchiveFactory;
import org.bonitasoft.engine.bpm.bar.actorMapping.Actor;
import org.bonitasoft.engine.bpm.bar.actorMapping.ActorMapping;
import org.bonitasoft.engine.bpm.connector.ConnectorEvent;
import org.bonitasoft.engine.bpm.process.DesignProcessDefinition;
import org.bonitasoft.engine.bpm.process.impl.ProcessDefinitionBuilder;
import org.bonitasoft.engine.expression.ExpressionBuilder;
import org.bonitasoft.engine.expression.InvalidExpressionException;
import org.bonitasoft.engine.operation.OperationBuilder;
import org.bonitasoft.web.client.BonitaClient;
import org.bonitasoft.web.client.model.ProcessInstantiationResponse;
import org.bonitasoft.web.client.services.policies.ProcessImportPolicy;

/**
 * Helper for testing connector in a docker image of Bonita studio.
 * 
 * @author Firstname Lastname
 */
public class ConnectorTestToolkit {

    public static BusinessArchive buildConnectorToTest(String connectorId, String versionId, Map<String, String> inputs,
            Map<String, String> outputs, String locationJar) throws Exception {

        // Building process with connector to setup
        var process = buildConnectorInProcess(connectorId, versionId, inputs, outputs);

        // Building business archive with the process and connector
        return buildBusinessArchive(process, connectorId, locationJar);

    }

    private static BusinessArchive buildBusinessArchive(DesignProcessDefinition process, String connectorId,
            String locationJar) throws Exception {
        var barBuilder = new BusinessArchiveBuilder();
        barBuilder.createNewBusinessArchive();
        barBuilder.setProcessDefinition(process);
        var connectorJar = new File("").getAbsoluteFile().toPath()
                .resolve("target")
                .resolve(locationJar)
                .toFile();
        assertThat(connectorJar).exists();
        List<JarEntry> jarEntries = findJarEntries(connectorJar,
                entry -> entry.getName().equals(connectorId + ".impl"));
        assertThat(jarEntries).hasSize(1);
        var implEntry = jarEntries.get(0);

        byte[] content = null;
        try (JarFile jarFile = new JarFile(connectorJar)) {
            InputStream inputStream = jarFile.getInputStream(implEntry);
            content = inputStream.readAllBytes();
        }

        barBuilder.addConnectorImplementation(
                new BarResource(connectorId + ".impl", content));
        barBuilder.addClasspathResource(
                new BarResource(connectorJar.getName(), Files.readAllBytes(connectorJar.toPath())));
        ActorMapping actorMapping = new ActorMapping();
        var systemActor = new Actor("system");
        systemActor.addRole("member");
        actorMapping.addActor(systemActor);
        barBuilder.setActorMapping(actorMapping);

        return barBuilder.done();
    }

    private static DesignProcessDefinition buildConnectorInProcess(String connectorId, String versionId,
            Map<String, String> inputs, Map<String, String> outputs) throws Exception {
        var processBuilder = new ProcessDefinitionBuilder();
        var expBuilder = new ExpressionBuilder();
        processBuilder.createNewInstance("myProcess", "1.0");
        processBuilder.addActor("system");
        var connectorBuilder = processBuilder.addConnector("connector-under-test", connectorId, versionId,
                ConnectorEvent.ON_ENTER);
        inputs.forEach((name, content) -> {
            try {
                connectorBuilder.addInput(name, expBuilder.createConstantStringExpression(
                        content));
            } catch (InvalidExpressionException e) {
                e.printStackTrace();
            }
        });

        if (outputs != null) {
            outputs.forEach((name, outputName) -> {
                try {
                    processBuilder.addData(name, String.class.getTypeName(), null); //TODO can only work with the string type output
                    connectorBuilder.addOutput(new OperationBuilder().createSetDataOperation(name,
                            new ExpressionBuilder().createConstantStringExpression(outputName)));
                } catch (InvalidExpressionException e) {
                    e.printStackTrace();
                }
            });
        }

        return processBuilder.done();
    }

    public static ProcessInstantiationResponse importAndLaunchProcess(BusinessArchive barArchive, BonitaClient client)
            throws IOException {
        var process = barArchive.getProcessDefinition();
        var processFile = new File("process.bar");
        if (processFile.exists()) {
            processFile.delete();
        }

        BusinessArchiveFactory.writeBusinessArchiveToFile(barArchive, processFile);
        client.login("install", "install");
        client.processes().importProcess(processFile, ProcessImportPolicy.REPLACE_DUPLICATES);
        var processId = client.processes().getProcess(process.getName(), process.getVersion()).getId();
        client.processes().getProcessProblem(0, 99, processId);
        return client.processes().startProcess(processId, Map.of());

    }

    private static List<JarEntry> findJarEntries(File file, Predicate<? super JarEntry> entryPredicate)
            throws IOException {
        try (JarFile jarFile = new JarFile(file)) {
            return jarFile.stream()
                    .filter(entryPredicate)
                    .collect(Collectors.toList());
        }
    }
}

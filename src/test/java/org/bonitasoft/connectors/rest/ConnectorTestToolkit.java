package org.bonitasoft.connectors.rest;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Pattern;
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
import org.bonitasoft.web.client.api.ProcessInstanceVariableApi;
import org.bonitasoft.web.client.model.ProcessInstantiationResponse;
import org.bonitasoft.web.client.services.policies.ProcessImportPolicy;

/**
 * Helper for testing connector in a docker image of Bonita studio.
 */
public class ConnectorTestToolkit {

    /**
     * Build a connector and then install it into a dummy process with input and output process variables.
     * Those variables will help to verify the input and output specified in the implementation of the connector to be tested.
     * 
     * @param connectorId The identifier of the connector specified in the pom.xml and the definition file.
     * @param versionId The version of the connector to be tested.
     * @param inputs A map of variables with a content specified to be tested.
     * @param outputs A map of results variables.
     * @param locationJar The Jar containing the class and dependencies used by the connector.
     * @return A {@link BusinessArchive}
     * @throws Exception
     */
    public static BusinessArchive buildConnectorToTest(String connectorId, String versionId, Map<String, String> inputs,
            Map<String, String> outputs, String locationJar) throws Exception {

        // Building process with connector to setup
        var process = buildConnectorInProcess(connectorId, versionId, inputs, outputs);

        // Building business archive with the process and connector
        return buildBusinessArchive(process, connectorId, locationJar);

    }

    private static BusinessArchive buildBusinessArchive(DesignProcessDefinition process, String connectorId,
            String artifactId) throws Exception {
        var barBuilder = new BusinessArchiveBuilder();
        barBuilder.createNewBusinessArchive();
        barBuilder.setProcessDefinition(process);
        var foundFiles = new File("").getAbsoluteFile().toPath()
                .resolve("target")
                .toFile()
                .listFiles(new FilenameFilter() {

                    @Override
                    public boolean accept(File dir, String name) {
                        return Pattern.matches(artifactId + "-.*.jar", name) && !name.endsWith("-sources.jar")
                                && !name.endsWith("-javadoc.jar");
                    }
                });
        assertThat(foundFiles).hasSize(1);
        var connectorJar = foundFiles[0];
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
                            new ExpressionBuilder().createDataExpression(outputName, String.class.getTypeName())));
                } catch (InvalidExpressionException e) {
                    e.printStackTrace();
                }
            });
        }

        // Add a human task to avoid the process to be already completed as soon as it's launched. 
        processBuilder.addManualTask("waiting task", "system");

        return processBuilder.done();
    }

    /**
     * Import the {@link BusinessArchive} and launch the dummy process containing the connector to be tested.
     * 
     * @param barArchive The file containing the {@link BusinessArchive}
     * @param client A {@link BonitaClient}
     * @return The process started.
     * @throws IOException
     */
    public static ProcessInstantiationResponse importAndLaunchProcess(BusinessArchive barArchive, BonitaClient client)
            throws IOException {
        var process = barArchive.getProcessDefinition();
        File processFile = null;
        try {
            processFile = Files.createTempFile("process", ".bar").toFile();
            processFile.delete();
            BusinessArchiveFactory.writeBusinessArchiveToFile(barArchive, processFile);
            client.login("install", "install");
            client.processes().importProcess(processFile, ProcessImportPolicy.REPLACE_DUPLICATES);
        } finally {
            if (processFile != null) {
                processFile.delete();
            }
        }
        
        var processId = client.processes().getProcess(process.getName(), process.getVersion()).getId();
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

    /**
     * Getting the content value of a specific variable process.
     * 
     * @param client A {@link BonitaClient}
     * @param caseId A process instance id.
     * @param variableProcessName The name of the variable process, it must have been already declared in the output map of the connector before building the
     *        connector to test.
     * @return The content of the variable. Can be null.
     */
    public static Object getProcessVariableValue(BonitaClient client, String caseId, String variableProcessName) {

        return client.get(ProcessInstanceVariableApi.class).getVariableByProcessInstanceId(caseId,
                variableProcessName).getValue();

    }
}

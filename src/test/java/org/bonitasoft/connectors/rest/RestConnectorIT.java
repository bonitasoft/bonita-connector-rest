package org.bonitasoft.connectors.rest;

import static org.junit.Assert.assertTrue;

import java.util.List;

import org.bonitasoft.engine.bpm.bar.BarResource;
import org.bonitasoft.engine.bpm.bar.BusinessArchiveBuilder;
import org.bonitasoft.engine.bpm.bar.actorMapping.Actor;
import org.bonitasoft.engine.bpm.bar.actorMapping.ActorMapping;
import org.bonitasoft.engine.bpm.connector.ConnectorEvent;
import org.bonitasoft.engine.bpm.process.DesignProcessDefinition;
import org.bonitasoft.engine.bpm.process.InvalidProcessDefinitionException;
import org.bonitasoft.engine.bpm.process.impl.ConnectorDefinitionBuilder;
import org.bonitasoft.engine.bpm.process.impl.ProcessDefinitionBuilder;
import org.bonitasoft.web.client.BonitaClient;
import org.bonitasoft.web.client.services.policies.ProcessImportPolicy;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

public class RestConnectorIT {
    
    @Rule
    public GenericContainer bonita = new GenericContainer(DockerImageName.parse("bonita:"+System.getProperty("bonita.version")))
            .withExposedPorts(8080)
            .waitingFor(Wait.forHttp("/bonita"));
    private BonitaClient client;
    
    @Before
    public void setup() {
        client = BonitaClient.builder(String.format("http://%s:%s/bonita", bonita.getHost(), bonita.getFirstMappedPort())).build();
    }
    
    @Test
    public void testConnectorIntegration() throws InvalidProcessDefinitionException {
        var barBuilder = new BusinessArchiveBuilder();
        
        
        var processBuilder =  new ProcessDefinitionBuilder();
        processBuilder.addActor("system");
        var connectorBuilder = processBuilder.addConnector("connector-under-test", "rest-get", "1.2.0",  ConnectorEvent.ON_ENTER);
        connectorBuilder.addInput(null, null);
        connectorBuilder.addOutput(null);
     
        
        DesignProcessDefinition process = processBuilder.done();
        
        
        barBuilder.setProcessDefinition(process);
        
        // Open question:
        // How to retrieve the proper classpath ?
        // It seems smarter to rely on a the project builder than reimplementing another mechanism.
        
        
        barBuilder.addConnectorImplementation(new BarResource(null, null));
       // barBuilder.addClasspathResource(null);
        ActorMapping actorMapping = new ActorMapping();
        var systemActor = new Actor("system");
        systemActor.addRole("member");
        actorMapping.addActor(systemActor);
        barBuilder.setActorMapping(actorMapping);
        
        
        
        client.processes().importProcess(null, ProcessImportPolicy.REPLACE_DUPLICATES);
        
        
        assertTrue(client.system().isCommunity());
    }

}

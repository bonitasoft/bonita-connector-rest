# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Bonita REST Connector is a multi-connector factory that produces 8 separate REST connector implementations (GET, POST, PUT, DELETE, PATCH, HEAD, file-post, file-put) from a single Java codebase for the Bonita BPM platform.

**Current Version:** 1.5.0-SNAPSHOT
**Target:** Bonita 7.14.0
**Java Version:** 11

## Build Commands

```bash
# Build all connectors (default goal: verify)
./mvnw

# Clean build
./mvnw clean verify

# Run unit tests only
./mvnw test

# Run integration tests (includes unit tests)
./mvnw verify

# Skip tests
./mvnw verify -DskipTests

# Run single test class
./mvnw test -Dtest=RESTConnectorTest

# Run single test method
./mvnw test -Dtest=RESTConnectorTest#testExecuteBusinessLogic

# Package connectors without tests
./mvnw package -DskipTests

# Run Sonar analysis
./mvnw sonar:sonar
```

## Architecture

### Inheritance Hierarchy

```
AbstractConnector (Bonita Framework)
    └── AbstractRESTConnectorImpl (733 lines - parameter extraction & validation)
            └── RESTConnector (953 lines - core HTTP client logic)
                    ├── GetConnectorImpl (hasBody=false)
                    ├── DeleteConnectorImpl (hasBody=false)
                    ├── HeadConnectorImpl (hasBody=false)
                    ├── PostConnectorImpl (hasBody=true)
                    ├── PutConnectorImpl (hasBody=true)
                    └── PatchConnectorImpl (hasBody=true)
```

### Key Design Patterns

1. **Template Method Pattern:** `AbstractRESTConnectorImpl` defines the connector framework, `RESTConnector` implements business logic, subclasses specify HTTP method
2. **Single Source, Multiple Artifacts:** One codebase produces 8 connector ZIP packages via Maven assembly plugin
3. **Method-Agnostic Core:** `RESTConnector` doesn't hardcode HTTP method; subclasses override `getMethod()` and pass `hasBody` flag to constructor

### Class Responsibilities

- **AbstractRESTConnectorImpl** (`src/main/java/org/bonitasoft/connectors/rest/AbstractRESTConnectorImpl.java`):
  - Defines 60+ input parameter getters (URL, auth, SSL, proxy, headers, cookies, timeouts, error handling, retry logic)
  - Defines 5 output parameter setters (bodyAsString, bodyAsObject, headers, status_code, status_message)
  - Implements comprehensive validation (40+ validation methods)
  - Abstracts `hasBody()` method

- **RESTConnector** (`src/main/java/org/bonitasoft/connectors/rest/RESTConnector.java`):
  - `executeBusinessLogic()`: Main entry point
  - `buildRequest()`: Constructs Request bean from input parameters
  - `execute()`: Core HTTP execution using Apache HttpClient 4.5+
  - Handles SSL/TLS configuration, proxy setup, authentication (Basic/Digest/OAuth2 Client Credentials)
  - Response parsing (JSON auto-detection via Content-Type)
  - Retry/failure strategies with consumer-based callbacks
  - Sensitive data masking in logs (Authorization, Token, Set-Cookie headers)

- **Concrete Implementations** (6 classes, ~28 lines each):
  - Minimal wrapper classes that specify HTTP method and hasBody flag
  - Example: `GetConnectorImpl` calls `super(false)` and returns `HTTPMethod.GET`

### Build Process

1. **generate-resources:** Groovy script (`src/script/dependencies-as-var.groovy`) generates XML with JAR dependencies, sets `${connector-dependencies}` variable
2. **process-resources:** Maven filters `.impl` template files in `src/main/resources-filtered/`, replacing variables like `${get.impl.id}`, `${get.main-class}`
3. **package:** maven-assembly-plugin creates 8 separate ZIP files using descriptors in `src/assembly/` (e.g., `get-assembly.xml`)

Each ZIP contains:
```
rest-get-impl.zip
  ├── rest-get.impl (connector definition)
  └── classpath/ (JAR files including bonita-connector-rest and dependencies)
```

### Connector Definitions

- **Implementation descriptors:** `src/main/resources-filtered/*.impl` (Maven-filtered XML)
- **UI labels/documentation:** `src/main/resources/*.properties` (localized: EN, FR, ES, JA)
- **Maven properties:** Each connector has properties in `pom.xml` defining:
  - Definition ID and version (stable across releases)
  - Implementation ID and version (tracks project version)
  - Main class name

### Model Classes (DTOs)

Located in `src/main/java/org/bonitasoft/connectors/rest/model/`:
- `Request`: Encapsulates HTTP request data
- `Authorization`, `BasicDigestAuthorization`, `HeaderAuthorization`, `OAuthClientCredentialsAuthorization`: Auth strategies
- `SSL`, `Store`, `TrustCertificateStrategy`, `SSLVerifier`: SSL/TLS configuration
- `Proxy`, `ProxyProtocol`: Proxy configuration
- `HTTPMethod`: Enum (GET, POST, PUT, DELETE, HEAD, PATCH)

## Testing

### Test Infrastructure

- **AcceptanceTestBase** (`src/test/java/org/bonitasoft/connectors/rest/AcceptanceTestBase.java`):
  - Common base class for unit tests
  - Sets up WireMock server on random port
  - Provides Bonita mock objects (EngineExecutionContext, APIAccessor, ProcessAPI)

- **ConnectorTestToolkit** (`src/test/java/org/bonitasoft/connectors/rest/ConnectorTestToolkit.java`):
  - Integration testing with real Bonita container via Testcontainers
  - Methods: `buildConnectorToTest()`, `importAndLaunchProcess()`, `getProcessVariableValue()`

### Test Approach

- **Unit tests:** Use WireMock to mock REST endpoints
- **Integration tests:** Deploy to Bonita in Docker container (TestContainers)
- **Test doubles:** Mockito for Bonita APIs, WireMock for HTTP services
- **Assertions:** AssertJ fluent assertions

### Integration Test Configuration

Integration tests run against multiple Bonita versions (configured in pom.xml):
- `integration-tests-7.13` (Bonita 7.13.0)
- `integration-tests-7.14` (Bonita 7.14.0)

## Adding a New HTTP Method

1. Create `{Method}ConnectorImpl.java` extending `RESTConnector`:
   ```java
   public class OptionsConnectorImpl extends RESTConnector {
       public OptionsConnectorImpl() {
           super(false); // true if method supports body
       }

       @Override
       protected HTTPMethod getMethod() {
           return HTTPMethod.OPTIONS;
       }
   }
   ```

2. Add Maven properties to `pom.xml`:
   ```xml
   <options.def.id>rest-options</options.def.id>
   <options.def.version>1.0.0</options.def.version>
   <options.impl.id>${options.def.id}-impl</options.impl.id>
   <options.impl.version>${project.version}</options.impl.version>
   <options.main-class>org.bonitasoft.connectors.rest.OptionsConnectorImpl</options.main-class>
   ```

3. Create `src/main/resources-filtered/rest-options.impl` (copy and modify existing `.impl` file)

4. Create `src/main/resources/rest-options.properties` and localized variants (`rest-options_fr.properties`, etc.)

5. Create `src/assembly/options-assembly.xml` (copy and modify existing assembly descriptor)

6. Add assembly execution to `pom.xml` build plugins section

7. Add unit test class extending `AcceptanceTestBase`

## Important Notes

### Dependency Constraints

- **Mockito version:** Deliberately kept at 1.10.19 for httpclient4 compatibility (see pom.xml line 104-106)
- **WireMock version:** Limited to 2.35.1 (requires httpclient4, not httpclient5)
- **Bonita dependencies:** Use BOM from `bonita-runtime-bom:7.14.0` for version consistency

### Dependencies with `provided` Scope

These are supplied by Bonita runtime and must not be bundled:
- bonita-common, bonita-server
- commons-logging, commons-codec, commons-io
- httpclient, jackson-core

### Key Features to Understand

1. **Bonita Document Integration:** Connectors can read request body from Bonita process documents via `documentBody` parameter
2. **Sensitive Data Masking:** Authorization/Token/Set-Cookie headers automatically masked in logs
3. **Retry Logic:** Uses consumer-based callbacks with `SRetryableException` for retriable failures
4. **JSON Auto-Detection:** Response parsed as JSON if Content-Type matches, with fallback to string
5. **Flexible SSL/TLS:** Supports trust strategies (DEFAULT, TRUST_SELF_SIGNED, TRUST_ALL) and hostname verification modes
6. **Proxy Resolution:** Manual configuration or automatic JVM system properties resolution
7. **Bonita Context Headers:** Optional injection of process context (activity ID, process ID, etc.) into request headers
8. **OAuth2 Client Credentials:** Supports OAuth2 client credentials flow for authentication with configurable token endpoint, client ID, client secret, and optional scopes

## Release Process

1. Update pom.xml version (remove -SNAPSHOT)
2. Run [release action](https://github.com/bonitasoft/bonita-connector-rest/actions/workflows/release.yml) with version parameter
3. Release published to Maven Central
4. Update master branch with next SNAPSHOT version
5. Update [Bonita marketplace repository](https://github.com/bonitasoft/bonita-marketplace) with new version

## Localization

All connectors support 4 languages via `.properties` files:
- English (default): `rest-{method}.properties`
- French: `rest-{method}_fr.properties`
- Spanish: `rest-{method}_es.properties`
- Japanese: `rest-{method}_ja.properties`

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Bonita REST Connector is a multi-connector factory that produces 9 separate connector implementations from a single Java codebase for the Bonita BPM platform:
- **8 REST connectors:** GET, POST, PUT, DELETE, PATCH, HEAD, file-post, file-put
- **1 OAuth2 connector:** oauth-auth (for OAuth2 token retrieval)

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
    └── AbstractRESTConnectorImpl (818 lines - parameter extraction & validation)
            └── RESTConnector (1199 lines - core HTTP client logic)
                    ├── GetConnectorImpl (hasBody=false)
                    ├── DeleteConnectorImpl (hasBody=false)
                    ├── HeadConnectorImpl (hasBody=false)
                    ├── PostConnectorImpl (hasBody=true)
                    ├── PutConnectorImpl (hasBody=true)
                    ├── PatchConnectorImpl (hasBody=true)
                    └── Oauth2ConnectorImpl (hasBody=true, OAuth2 token retrieval)
```

### Key Design Patterns

1. **Template Method Pattern:** `AbstractRESTConnectorImpl` defines the connector framework, `RESTConnector` implements business logic, subclasses specify HTTP method
2. **Single Source, Multiple Artifacts:** One codebase produces 9 connector ZIP packages via Maven assembly plugin (8 REST + 1 OAuth2)
3. **Method-Agnostic Core:** `RESTConnector` doesn't hardcode HTTP method; subclasses override `getMethod()` and pass `hasBody` flag to constructor
4. **Specialized OAuth2 Connector:** `Oauth2ConnectorImpl` extends `RESTConnector` to provide dedicated OAuth2 token retrieval functionality

### Class Responsibilities

- **AbstractRESTConnectorImpl** (`src/main/java/org/bonitasoft/connectors/rest/AbstractRESTConnectorImpl.java`):
  - Defines 60+ input parameter getters (URL, auth, SSL, proxy, headers, cookies, timeouts, error handling, retry logic)
  - OAuth2 parameters: token endpoint, client ID, client secret, scope, pre-obtained token
  - Defines 5 output parameter setters (bodyAsString, bodyAsObject, headers, status_code, status_message)
  - Implements comprehensive validation (40+ validation methods)
  - Abstracts `hasBody()` method

- **RESTConnector** (`src/main/java/org/bonitasoft/connectors/rest/RESTConnector.java`):
  - `executeBusinessLogic()`: Main entry point
  - `buildRequest()`: Constructs Request bean from input parameters
  - `execute()`: Core HTTP execution using Apache HttpClient 4.5+
  - Handles SSL/TLS configuration, proxy setup, authentication (Basic/Digest/OAuth2 Client Credentials/OAuth2 Bearer)
  - `getOAuth2AccessToken()`: Acquires and caches OAuth2 access tokens using client credentials flow
  - Response parsing (JSON auto-detection via Content-Type)
  - Retry/failure strategies with consumer-based callbacks
  - Sensitive data masking in logs (Authorization, Token, Set-Cookie headers)

- **REST Method Implementations** (6 classes, ~28 lines each):
  - Minimal wrapper classes that specify HTTP method and hasBody flag
  - Example: `GetConnectorImpl` calls `super(false)` and returns `HTTPMethod.GET`
  - Classes: GetConnectorImpl, PostConnectorImpl, PutConnectorImpl, DeleteConnectorImpl, PatchConnectorImpl, HeadConnectorImpl

- **Oauth2ConnectorImpl** (`src/main/java/org/bonitasoft/connectors/rest/Oauth2ConnectorImpl.java`):
  - Dedicated connector for OAuth2 token retrieval (not for making REST API calls)
  - Uses OAuth2 Client Credentials flow to obtain access tokens
  - Outputs token via `OAUTH2_TOKEN_OUTPUT_PARAMETER` for use in subsequent connectors
  - Supports proxy and SSL configuration for token endpoint access
  - ~58 lines of specialized implementation

### Build Process

1. **generate-resources:** Groovy script (`src/script/dependencies-as-var.groovy`) generates XML with JAR dependencies, sets `${connector-dependencies}` variable
2. **process-resources:** Maven filters `.impl` template files in `src/main/resources-filtered/`, replacing variables like `${get.impl.id}`, `${get.main-class}`, `${oauth.impl.id}`
3. **package:** maven-assembly-plugin creates 9 separate ZIP files using descriptors in `src/assembly/` (e.g., `get-assembly.xml`, `oauth-auth-assembly.xml`)

Each ZIP contains:
```
rest-get-impl.zip
  ├── rest-get.impl (connector definition)
  └── classpath/ (JAR files including bonita-connector-rest and dependencies)

oauth-auth-impl.zip
  ├── oauth-auth.impl (OAuth2 connector definition)
  └── classpath/ (JAR files including bonita-connector-rest, nimbus-jose-jwt, and dependencies)
```

### Connector Definitions

- **Implementation descriptors:** `src/main/resources-filtered/*.impl` (Maven-filtered XML)
- **UI labels/documentation:** `src/main/resources/*.properties` (localized: EN, FR, ES, JA)
- **Maven properties:** Each connector has properties in `pom.xml` defining:
  - Definition ID and version (stable across releases)
  - Implementation ID and version (tracks project version)
  - Main class name
  - Example REST connector: `get.def.id=rest-get`, `get.impl.version=${project.version}`, `get.main-class=org.bonitasoft.connectors.rest.GetConnectorImpl`
  - Example OAuth connector: `oauth.def.id=oauth-auth`, `oauth.impl.version=${project.version}`, `oauth.main-class=org.bonitasoft.connectors.rest.Oauth2ConnectorImpl`

### Model Classes (DTOs)

Located in `src/main/java/org/bonitasoft/connectors/rest/model/`:
- `Request`: Encapsulates HTTP request data
- **Authorization strategies:**
  - `Authorization`: Base interface
  - `BasicDigestAuthorization`: Basic/Digest HTTP authentication
  - `HeaderAuthorization`: Custom header-based authentication
  - `OAuth2ClientCredentialsAuthorization`: OAuth2 Client Credentials flow (acquires token from endpoint)
  - `OAuth2BearerAuthorization`: OAuth2 Bearer token (uses pre-obtained token)
- **SSL/TLS configuration:**
  - `SSL`, `Store`, `TrustCertificateStrategy`, `SSLVerifier`
- **Proxy configuration:**
  - `Proxy`, `ProxyProtocol`
- **HTTP methods:**
  - `HTTPMethod`: Enum (GET, POST, PUT, DELETE, HEAD, PATCH)
  - `AuthorizationType`: Enum (NONE, BASIC, DIGEST, OAUTH2_CLIENT_CREDENTIALS, OAUTH2_BEARER)

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

## OAuth2 Authentication Usage

### Using OAuth2 Client Credentials in REST Connectors

REST connectors (GET, POST, PUT, DELETE, PATCH, HEAD) can automatically acquire OAuth2 tokens:

1. Set `auth_type` to `OAUTH2_CLIENT_CREDENTIALS` or `OAUTH2 (Client Credentials)`
2. Configure OAuth2 parameters:
   - `oauth2_token_endpoint`: Token endpoint URL
   - `oauth2_client_id`: Client ID
   - `oauth2_client_secret`: Client secret
   - `oauth2_scope`: Optional space-separated scopes

The connector will automatically:
- Request an access token from the endpoint
- Cache the token in-memory for reuse
- Add `Authorization: Bearer <token>` header to the API request
- Handle token expiration based on JWT claims

### Using OAuth2 Bearer Authentication

For scenarios where you already have a token or want to manage token lifecycle separately:

1. **Option A - Use dedicated oauth-auth connector:**
   - Add `oauth-auth` connector to retrieve token
   - Configure with OAuth2 Client Credentials parameters
   - Capture output parameter `token`
   - Pass token to subsequent REST connector via `oauth2_token` input parameter
   - Set REST connector `auth_type` to `OAUTH2_BEARER` or `OAUTH2 (Bearer)`

2. **Option B - Use externally obtained token:**
   - Obtain token from external source or process variable
   - Set REST connector `auth_type` to `OAUTH2_BEARER`
   - Set `oauth2_token` input parameter to your token value

### OAuth2 Connector Output

The `oauth-auth` connector (`Oauth2ConnectorImpl`) produces:
- **Output parameter:** `token` (String) - The access token retrieved from the OAuth2 provider
- **Use case:** Chain multiple API calls with same token without re-authentication

## Important Notes

### Dependency Constraints

- **Mockito version:** Deliberately kept at 1.10.19 for httpclient4 compatibility (see pom.xml line 111)
- **WireMock version:** Limited to 2.35.1 (requires httpclient4, not httpclient5)
- **Bonita dependencies:** Use BOM from `bonita-runtime-bom:7.14.0` for version consistency
- **nimbus-jose-jwt:** Version 9.37.3 - Required for OAuth2 token parsing and JWT handling

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
8. **OAuth2 Authentication:** Two modes supported:
   - **OAuth2 Client Credentials:** REST connectors can automatically acquire tokens using client credentials flow (token endpoint, client ID, client secret, optional scopes). Tokens are cached in-memory.
   - **OAuth2 Bearer:** REST connectors can use pre-obtained tokens passed as input parameter. Use the dedicated `oauth-auth` connector to retrieve tokens first, then pass to REST connectors.
9. **Dedicated OAuth2 Connector:** The `oauth-auth` connector (`Oauth2ConnectorImpl`) is specialized for token retrieval and outputs the token for use in subsequent API calls

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

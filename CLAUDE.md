# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Bonita REST Connector is a multi-connector factory that produces 9 separate connector implementations from a single Java codebase for the Bonita BPM platform:
- **8 REST connectors:** GET, POST, PUT, DELETE, PATCH, HEAD, file-post, file-put
- **1 OAuth2 connector:** oauth-auth (for OAuth2 token retrieval)

**Target:** Bonita 9.0.0
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
  - OAuth2 parameters: token endpoint, client ID, client secret, scope, authorization code, code verifier (PKCE), redirect URI, pre-obtained token
  - Defines 5 output parameter setters (bodyAsString, bodyAsObject, headers, status_code, status_message)
  - Implements comprehensive validation (40+ validation methods)
  - Abstracts `hasBody()` method

- **RESTConnector** (`src/main/java/org/bonitasoft/connectors/rest/RESTConnector.java`):
  - `executeBusinessLogic()`: Main entry point
  - `buildRequest()`: Constructs Request bean from input parameters
  - `execute()`: Core HTTP execution using Apache HttpClient 4.5+
  - Handles SSL/TLS configuration, proxy setup, authentication (Basic/Digest/OAuth2 Client Credentials/OAuth2 Authorization Code/OAuth2 Bearer)
  - `getOAuth2AccessToken()`: Acquires and caches OAuth2 access tokens using client credentials or authorization code flow
  - Response parsing (JSON auto-detection via Content-Type)
  - Retry/failure strategies with consumer-based callbacks
  - Sensitive data masking in logs (Authorization, Token, Set-Cookie headers)

- **REST Method Implementations** (6 classes, ~28 lines each):
  - Minimal wrapper classes that specify HTTP method and hasBody flag
  - Example: `GetConnectorImpl` calls `super(false)` and returns `HTTPMethod.GET`
  - Classes: GetConnectorImpl, PostConnectorImpl, PutConnectorImpl, DeleteConnectorImpl, PatchConnectorImpl, HeadConnectorImpl

- **Oauth2ConnectorImpl** (`src/main/java/org/bonitasoft/connectors/rest/Oauth2ConnectorImpl.java`):
  - Dedicated connector for OAuth2 token retrieval (not for making REST API calls)
  - Supports both OAuth2 Client Credentials and Authorization Code flows
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
  └── classpath/ (JAR files including bonita-connector-rest and dependencies)
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
  - `OAuth2TokenRequestAuthorization`: Abstract superclass for OAuth2 token request flows (contains tokenEndpoint, clientId, clientSecret)
  - `OAuth2ClientCredentialsAuthorization`: OAuth2 Client Credentials flow (acquires token from endpoint using client credentials)
  - `OAuth2AuthorizationCodeAuthorization`: OAuth2 Authorization Code flow (exchanges authorization code for token, supports PKCE)
  - `OAuth2BearerAuthorization`: OAuth2 Bearer token (uses pre-obtained token)
- **SSL/TLS configuration:**
  - `SSL`, `Store`, `TrustCertificateStrategy`, `SSLVerifier`
- **Proxy configuration:**
  - `Proxy`, `ProxyProtocol`
- **HTTP methods:**
  - `HTTPMethod`: Enum (GET, POST, PUT, DELETE, HEAD, PATCH)
  - `AuthorizationType`: Enum (NONE, BASIC, DIGEST, OAUTH2_CLIENT_CREDENTIALS, OAUTH2_AUTHORIZATION_CODE, OAUTH2_BEARER)

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
- Cache the token in-memory for reuse (LRU cache with 100-token limit)
- Add `Authorization: Bearer <token>` header to the API request
- Handle token expiration with 60-second clock skew (tokens expire 60 seconds before actual expiration)

### Using OAuth2 Authorization Code in REST Connectors

REST connectors (GET, POST, PUT, DELETE, PATCH, HEAD) can exchange authorization codes for access tokens:

1. Set `auth_type` to `OAUTH2_AUTHORIZATION_CODE` or `OAUTH2 (Authorization Code)`
2. Configure OAuth2 parameters:
   - `oauth2_token_endpoint`: Token endpoint URL
   - `oauth2_client_id`: Client ID
   - `oauth2_client_secret`: Client secret
   - `oauth2_code`: Authorization code (obtained from OAuth2 provider)
   - `oauth2_code_verifier`: PKCE code verifier (optional, for PKCE flows)
   - `oauth2_redirect_uri`: Redirect URI (optional, required by some providers)

The connector will automatically:
- Exchange the authorization code for an access token
- Support PKCE (Proof Key for Code Exchange) when code_verifier is provided
- Store the token in the connector instance for retry handling (NOT cached globally)
- Add `Authorization: Bearer <token>` header to the API request
- Handle token expiration with 60-second clock skew (tokens expire 60 seconds before actual expiration)

**Important Notes:**
- The authorization code and code_verifier are INPUT parameters (not retrieved by the connector)
- PKCE support is optional - if `oauth2_code_verifier` is empty, the token request is sent without PKCE
- The `oauth2_redirect_uri` is optional but required by some OAuth2 providers
- Authorization codes are typically single-use - tokens are stored per connector instance for retries, but NOT in the global cache

### Using OAuth2 Bearer Authentication

For scenarios where you already have a token or want to manage token lifecycle separately:

1. **Option A - Use dedicated oauth-auth connector:**
   - Add `oauth-auth` connector to retrieve token
   - Configure with OAuth2 Client Credentials or Authorization Code parameters
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

### OAuth2 Token Caching Details

**Client Credentials Flow Caching:**
- Tokens are cached in a synchronized `LinkedHashMap` with LRU (Least Recently Used) eviction
- **Cache limit:** 100 tokens maximum (`MAX_CACHED_TOKENS` constant in `RESTConnector.java:98`)
- **Cache key format:** `tokenEndpoint#clientId#scope` (scope is optional)
- **Eviction policy:** When cache exceeds 100 entries, the least recently accessed token is automatically removed
- **Clock skew:** Tokens are considered expired 60 seconds before their actual expiration time (`OAUTH2_TOKEN_EXPIRATION_CLOCK_SKEW_SECONDS` constant in `RESTConnector.java:118`)
- **Thread-safety:** Cache operations are synchronized to prevent race conditions in concurrent scenarios
- **Default expiration:** If OAuth2 provider doesn't return `expires_in`, tokens default to 3600 seconds (1 hour)

**Authorization Code Flow Storage:**
- Tokens are NOT stored in the global cache (authorization codes are single-use)
- Token is stored in the `userTokenSavedForRetry` instance variable (`RESTConnector.java:130`)
- Only used for retry handling within the same connector execution
- Each new connector instance requires a fresh token acquisition

### OAuth2 Troubleshooting

**Common OAuth2 Errors:**

1. **"OAuth2 token request failed. Error: invalid_client, Description: Client authentication failed"**
   - **Cause:** Invalid client credentials (client_id or client_secret)
   - **Solution:** Verify client_id and client_secret are correct in OAuth2 provider console
   - **Test location:** `RESTConnectorTest.java:1903` (`oauth2ClientCredentialsWithTokenAcquisitionFailure`)

2. **"OAuth2 token request failed. Error: invalid_grant, Description: The provided authorization grant is invalid, expired, or revoked"**
   - **Cause:** Authorization code has already been used, expired, or is invalid
   - **Solution:** Generate a new authorization code from the OAuth2 provider
   - **Note:** Authorization codes are typically single-use and expire quickly (5-10 minutes)

3. **"Failed to acquire OAuth2 token. Status: 401, Response: ..."**
   - **Cause:** Token endpoint returned 401 but response is not valid JSON or doesn't contain OAuth2 error fields
   - **Solution:** Check token endpoint URL, network connectivity, and OAuth2 provider status
   - **Implementation:** Generic fallback error when JSON parsing fails (`RESTConnector.java:668`)

4. **"Neither access_token nor error in OAuth2 token response"**
   - **Cause:** OAuth2 provider returned 200 status but response doesn't contain `access_token` or `error` fields
   - **Solution:** Check OAuth2 provider API documentation for correct response format
   - **Implementation:** Response validation at `RESTConnector.java:681-682`

5. **Token expires prematurely**
   - **Expected behavior:** Tokens expire 60 seconds before actual expiration (clock skew protection)
   - **Reason:** Prevents race conditions where token expires during request execution
   - **Configuration:** Cannot be changed (hardcoded in `OAUTH2_TOKEN_EXPIRATION_CLOCK_SKEW_SECONDS`)

**Default Token Expiration:**
- If OAuth2 provider does not return `expires_in`, tokens default to **3600 seconds (1 hour)** expiration
- Constant: `DEFAULT_TOKEN_EXPIRES_IN` in `RESTConnector.java:137`
- This default applies to both Client Credentials and Authorization Code flows

6. **Cache not working / Tokens not reused**
   - **Check cache key:** Ensure `tokenEndpoint`, `clientId`, and `scope` are identical across requests
   - **Authorization Code:** This flow intentionally does NOT use the cache (single-use codes)
   - **Cache limit:** If you have >100 unique token configurations, LRU eviction occurs automatically

7. **SSL/TLS errors when connecting to token endpoint**
   - **Solution:** Configure SSL parameters: `ssl_trust_self_signed_certificate`, `truststore_file`, `truststore_password`
   - **Trust strategies:** DEFAULT, TRUST_SELF_SIGNED, TRUST_ALL
   - **Hostname verification:** Can be disabled via `ssl_hostname_verifier` parameter

8. **Proxy issues with token endpoint**
   - **Solution:** Configure proxy parameters: `proxy_protocol`, `proxy_host`, `proxy_port`, `proxy_username`, `proxy_password`
   - **Note:** Proxy configuration applies to both token acquisition and API requests

**Debugging Tips:**

- Enable FINE logging to see OAuth2 token acquisition attempts: `LOGGER.fine()` statements in `RESTConnector.java:518-528`
- Check `getOAuth2AccessToken()` method at `RESTConnector.java:514` for flow-specific logic
- Review `handleErrorResponse()` method at `RESTConnector.java:728` for OAuth2 RFC 6749 Section 5.2 error handling
- Authorization/Token headers are automatically masked in logs for security - look for `[REDACTED]` in log output

## Important Notes

### Dependency Constraints

- **Mockito version:** Deliberately kept at 1.10.19 for httpclient4 compatibility (see pom.xml line 111)
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
8. **OAuth2 Authentication:** Three modes supported:
   - **OAuth2 Client Credentials:** REST connectors can automatically acquire tokens using client credentials flow (token endpoint, client ID, client secret, optional scopes). Tokens are cached in-memory using LRU cache with 100-token limit. Tokens expire 60 seconds before actual expiration (clock skew).
   - **OAuth2 Authorization Code:** REST connectors can exchange authorization codes for tokens (token endpoint, client ID, client secret, authorization code, optional PKCE code verifier, optional redirect URI). Tokens are stored per connector instance for retry handling only (NOT in global cache).
   - **OAuth2 Bearer:** REST connectors can use pre-obtained tokens passed as input parameter. Use the dedicated `oauth-auth` connector to retrieve tokens first, then pass to REST connectors.
9. **Dedicated OAuth2 Connector:** The `oauth-auth` connector (`Oauth2ConnectorImpl`) is specialized for token retrieval using either Client Credentials or Authorization Code flows and outputs the token for use in subsequent API calls

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

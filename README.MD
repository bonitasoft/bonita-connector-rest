# Rest Connector

A multi-connector project for the Bonita BPM platform to execute REST requests from a process.

[![Actions Status](https://github.com/bonitasoft/bonita-connector-rest/workflows/Build/badge.svg)](https://github.com/bonitasoft/bonita-connector-rest/actions?query=workflow%3ABuild)
[![Sonarcloud Status](https://sonarcloud.io/api/project_badges/measure?project=bonitasoft_bonita-connector-rest&metric=alert_status)](https://sonarcloud.io/dashboard?id=bonitasoft_bonita-connector-rest)
[![GitHub release](https://img.shields.io/github/v/release/bonitasoft/bonita-connector-rest?color=blue&label=Release)](https://github.com/bonitasoft/bonita-connector-rest/releases)
[![Maven Central](https://img.shields.io/maven-central/v/org.bonitasoft.connectors/bonita-connector-rest.svg?label=Maven%20Central&color=orange)](https://search.maven.org/search?q=g:%22org.bonitasoft.connectors%22%20AND%20a:%22bonita-connector-rest%22)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-yellow.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)

---

## 📦 Available Connectors

This project builds **9 distinct connector packages** from one unified codebase:

### REST API Connectors (8)

| Connector | Definition ID | Purpose | Has Body |
|-----------|--------------|---------|----------|
| **GET** | `rest-get` | Retrieve resources | ❌ |
| **POST** | `rest-post` | Create resources | ✅ |
| **PUT** | `rest-put` | Update resources | ✅ |
| **DELETE** | `rest-delete` | Delete resources | ❌ |
| **PATCH** | `rest-patch` | Partial updates | ✅ |
| **HEAD** | `rest-head` | Check resource existence | ❌ |
| **File POST** | `rest-file-post` | Upload files via POST | ✅ |
| **File PUT** | `rest-file-put` | Upload files via PUT | ✅ |

### OAuth2 Token Connector (1)

| Connector | Definition ID | Purpose | Output |
|-----------|--------------|---------|--------|
| **OAuth2 Auth** | `oauth-auth` | Retrieve OAuth2 access tokens | `token` |

## ✨ Features

### Authentication
- ✅ **None** - No authentication
- ✅ **Basic Auth** - Username/password authentication
- ✅ **Digest Auth** - Challenge-response authentication
- ✅ **Custom Header** - API key or custom token authentication
- ✅ **OAuth2 Client Credentials** - Automated token acquisition for service-to-service
- ✅ **OAuth2 Authorization Code** - User authentication with PKCE support
- ✅ **OAuth2 Bearer** - Pre-obtained token usage

### Security & SSL/TLS
- ✅ Trust strategies: DEFAULT, TRUST_SELF_SIGNED, TRUST_ALL
- ✅ Custom keystores and truststores
- ✅ Hostname verification modes
- ✅ Client certificate authentication

### Networking
- ✅ **Proxy support** - HTTP/HTTPS/SOCKS with authentication
- ✅ **Timeout configuration** - Connection, socket, and request timeouts
- ✅ **Retry logic** - Configurable retry strategies for transient failures

### Request Configuration
- ✅ **Custom headers** - Multiple headers with expression support
- ✅ **Cookies** - Cookie management and injection
- ✅ **Content negotiation** - JSON/XML/form-urlencoded/multipart
- ✅ **File uploads** - Multipart form data with binary file support
- ✅ **Bonita document integration** - Read request body from process documents

### Response Handling
- ✅ **JSON auto-detection** - Automatic parsing based on Content-Type
- ✅ **Status code extraction** - HTTP status code and message capture
- ✅ **Header extraction** - Response header access
- ✅ **Body capture** - Raw string or parsed object output

### Advanced
- ✅ **Bonita context injection** - Process/activity metadata in headers
- ✅ **Sensitive data masking** - Automatic log sanitization for tokens/passwords
- ✅ **Token caching** - In-memory OAuth2 token reuse with expiration management
- ✅ **Multi-language support** - EN, FR, ES, JA localization

## 🔧 Build

### Requirements
- **Java:** 11+
- **Maven:** 3.6+ (wrapper included)
- **Target Bonita:** 7.14.0

#### Clone or fork this repository
`git clone https://github.com/bonitasoft/bonita-connector-rest.git`

#### Build all connectors (runs unit + integration tests)
`./mvnw`

#### Clean build and package (with tests)
`./mvnw clean verify`

#### Run unit tests only
`./mvnw test`

#### Build and package only (skiping tests)
`./mvnw package -DskipTests`

#### Run specific test class
`./mvnw test -Dtest=RESTConnectorTest`

#### Run specific test method
`./mvnw test -Dtest=RESTConnectorTest#testExecuteBusinessLogic`

#### Sonar analysis
`./mvnw sonar:sonar`

Build Output

The build produces 9 ZIP packages in target/

Each ZIP contains:
- {connector-name}.impl - Connector implementation descriptor
- classpath/ - All required JAR dependencies

## 📋 Versioning Strategy

This project uses a dual-versioning approach to maintain backward compatibility:

Definition Version ({connector}.def.version)

- Purpose: Stable version for connector definition (UI contract)
- Stability: Only incremented when input/output parameters change
- Scope: Bonita Studio connector configuration compatibility
- Example: get.def.version=1.4.0 (stable)

Implementation Version ({connector}.impl.version)

- Purpose: Tracks project version and implementation changes
- Value: Always set to ${project.version} from POM
- Scope: Internal logic, bug fixes, feature enhancements, New featues
- Example: get.impl.version=1.5.0-SNAPSHOT (tracks POM version)

Versioning Rules

Increment definition version when:
- ✅ Adding new parameters
- ✅ Removing parameters
- ✅ Changing parameter types
- ✅ Changing output parameter schema

Do NOT increment definition version for:
- ❌ Internal logic improvements
- ❌ Bug fixes
- ❌ Performance optimizations

Always increment implementation version (via project version) for:
- ✅ Any code change
- ✅ Bug fixes
- ✅ New features
- ✅ Dependency updates

## Release

In order to create a new release:
- On the release branch, make sure to update the pom version (remove the -SNAPSHOT)
- Run the [release](https://github.com/bonitasoft/bonita-connector-rest/actions/workflows/release.yml) action, set the version to release as parameter. The release will be published to [Maven Central](https://central.sonatype.com/artifact/org.bonitasoft.connectors/bonita-connector-uipath).
- Update the `master` branch with the next SNAPSHOT version.

Once this is done, update the [Bonita marketplace repository](https://github.com/bonitasoft/bonita-marketplace) with the new version of the connector.

## Contributing

We would love you to contribute, pull requests are welcome! Please see the [CONTRIBUTING.md](CONTRIBUTING.md) for more information.

## License

The sources and documentation in this project are released under the [GPLv2 License](LICENSE)

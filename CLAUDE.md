# CLAUDE.md

## Project Overview

**secret-service** is a Java library for storing secrets in a keyring over D-Bus, implementing the [freedesktop.org Secret Service API 0.2](https://specifications.freedesktop.org/secret-service/0.2/). It is the Java equivalent of the `libsecret` C library, compatible with GNOME Linux systems (gnome-keyring, KeePassXC).

- **Group/Artifact:** `de.swiesend:secret-service`
- **Version:** 2.0.1-alpha
- **License:** MIT
- **JDK:** Compiles to Java 9 bytecode; requires JDK 17+ to build

## Build Commands

```bash
mvn clean compile          # Compile
mvn test                   # Run tests (requires D-Bus session + gnome-keyring)
mvn package                # Build JAR
mvn clean -Pcoverage test  # Run tests with JaCoCo coverage
```

Maven 3.6.0+ is enforced. No Gradle support.

## Project Structure

```
src/main/java/
  module-info.java                              # JPMS module: de.swiesend.secretservice
  de/swiesend/secretservice/
    simple/
      SimpleCollection.java                     # HIGH-LEVEL API (recommended entry point)
      interfaces/SimpleCollection.java          # Abstract base for SimpleCollection
    interfaces/                                 # D-Bus interface definitions
      Service.java, Collection.java, Item.java, Session.java, Prompt.java
    handlers/
      MessageHandler.java, SignalHandler.java, Messaging.java
    errors/
      IsLocked.java, NoSession.java, NoSuchObject.java
    gnome/keyring/                              # GNOME-specific non-standard interfaces
      InternalUnsupportedGuiltRiddenInterface.java
    Service.java, Collection.java, Item.java    # Low-level API implementations
    Session.java, Prompt.java, Secret.java
    TransportEncryption.java                    # DH key exchange + AES-128-CBC
    Static.java                                 # Constants, conversion utilities
    Pair.java                                   # Generic tuple

src/test/java/
  de/swiesend/secretservice/integration/       # ALL tests are integration tests
    simple/SimpleCollectionTest.java            # High-level API tests
    ServiceTest.java, CollectionTest.java, ...  # Low-level API tests
    IntegrationTest.java                        # Transport encryption end-to-end
    RegressionTests.java                        # Issue-specific regression tests
    test/Context.java                           # Shared test fixture helper

src/test/resources/
    *.xml                                       # D-Bus interface XML definitions
    simplelogger.properties                     # SLF4J test logging config
```

## Architecture

Two API layers:

1. **High-level API** (`SimpleCollection`) - Recommended. Manages D-Bus connections, sessions, encryption, and prompts internally. Use `try-with-resources` or call `disconnect()`.
2. **Low-level API** (`Service`, `Collection`, `Item`, `Session`, `Prompt`) - Direct D-Bus wrappers for fine-grained control.

Key components:
- **`TransportEncryption`** - Implements DH (RFC 2409 Second Oakley Group) + AES-128-CBC for encrypted sessions
- **`Secret`** (a D-Bus Struct) - Wraps secret values with session, parameters, content type. Implements `AutoCloseable` for secure cleanup
- **`Static`** - Central constants (D-Bus paths, algorithm identifiers) and conversion utilities
- **`MessageHandler`** - Handles D-Bus message sending with error recovery
- **`InternalUnsupportedGuiltRiddenInterface`** - GNOME-specific non-standard API for unlocking without user prompts (used in tests)

## Key Dependencies

| Dependency | Version | Purpose |
|---|---|---|
| `dbus-java-core` | 4.3.0 | D-Bus communication |
| `dbus-java-transport-native-unixsocket` | 4.3.0 | Unix socket transport |
| `hkdf` (at.favre.lib) | 2.0.0 | HMAC-based key derivation |
| `slf4j-api` | 2.0.9 | Logging |
| `junit-jupiter` | 5.10.0 | Testing (test scope) |

## Testing

All tests are **integration tests** that require a running D-Bus session bus and a secret service provider (gnome-keyring or KeePassXC). They cannot run in headless CI environments without a D-Bus mock.

- Framework: JUnit Jupiter 5
- Test fixture helper: `Context.java` provides `ensureService()`, `ensureSession()`, `ensureCollection()`, `ensureItem()`, and `after()` for setup/teardown
- Tests cover both encrypted (DH+AES) and plain-text sessions
- Some tests are `@Disabled` (e.g., deleting the default collection) because they are destructive

## Code Conventions

- **Logging:** SLF4J via `LoggerFactory.getLogger(getClass())` per class
- **Resource cleanup:** Use `AutoCloseable` / try-with-resources. Sensitive byte arrays cleared with `Arrays.fill(bytes, (byte) 0)`
- **Naming:** Standard Java conventions (PascalCase classes, camelCase methods, `get`/`set`/`is` prefixes)
- **Javadoc:** HTML tags in Javadoc (`<p>`, `<code>`, `<b>`). Extensive on public interfaces
- **Error handling:** Custom exceptions in `errors/` package. D-Bus exceptions caught and logged via `MessageHandler`
- **No code formatting tools** (no checkstyle, spotbugs, or editorconfig configured)

## JPMS Module

The project uses the Java Platform Module System:

```java
module de.swiesend.secretservice {
    requires transitive org.freedesktop.dbus;
    requires at.favre.lib.hkdf;
    requires org.slf4j;
    opens de.swiesend.secretservice to org.freedesktop.dbus;
    exports de.swiesend.secretservice;
    exports de.swiesend.secretservice.simple;
    exports de.swiesend.secretservice.interfaces;
    exports de.swiesend.secretservice.gnome.keyring.interfaces;
}
```

## Versioning

Semantic versioning with format: `{MAJOR}.{MINOR}.{PATCH}[-{SNAPSHOT|alpha|beta|rc}.?{INC}?]`

The current release is `2.0.1-alpha`. The 2.0.0 line introduced JPMS (`module-info.java`), updated major dependencies (dbus-java 4.x, hkdf 2.x, slf4j 2.x), and moved interfaces into the `de.swiesend.secretservice` package hierarchy. Earlier 1.x releases (e.g., `1.8.1-jdk17`) predate modularization.

## Git Conventions

- Commit messages: capitalized, descriptive subject line. Reference issues with `Resolves: #N` or link format
- Branches:
  - **`main`** - Production branch; holds the current released/alpha code (2.0.1-alpha)
  - **`develop-2.x.x`** - Long-lived development branch for the 2.x.x interface design. New 2.x features and API changes are developed here before merging to `main`. Check this branch for in-progress work on the next 2.x release
  - **Feature branches** - Slash notation (e.g., `claude/feature-name`, `purejava/modularize`)

## Security Considerations

- Transport encryption uses DH key exchange + AES-128-CBC (not optional for production use)
- Secrets are wrapped in `AutoCloseable` types that clear sensitive data on close
- Byte arrays holding secrets are zeroed after use
- The library addresses CVE-2018-19358 (gnome-keyring prompt bypass)

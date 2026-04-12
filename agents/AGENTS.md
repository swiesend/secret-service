# Agent Instructions

This is the unified instruction file for all AI agents (Claude Code, GitHub Copilot, etc.) working on the `secret-service` codebase. For the full design roadmap and historical context, see [`docs/vision.md`](../docs/vision.md).

## Project Overview

**secret-service** is a Java library for storing secrets in a keyring over D-Bus, implementing the [freedesktop.org Secret Service API 0.2](https://specifications.freedesktop.org/secret-service/0.2/). It is the Java equivalent of the `libsecret` C library, compatible with GNOME Linux systems (gnome-keyring, KeePassXC).

- **Group/Artifact:** `de.swiesend:secret-service`
- **License:** MIT
- **JDK:** Requires JDK 17+ to build

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
    functional/                                 # NEW FUNCTIONAL API (recommended)
      SecretService.java, Session.java, Collection.java, System.java
      interfaces/
        ServiceInterface.java, SessionInterface.java, CollectionInterface.java, SystemInterface.java
    simple/
      SimpleCollection.java                     # LEGACY API (backward-compatible adapter)
      interfaces/SimpleCollection.java
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

src/test/java/
  de/swiesend/secretservice/
    functional/                                 # Functional API tests
      SecretServiceTest.java, CollectionTest.java, SystemTest.java
      integration/Example.java
    integration/                                # Low-level API integration tests
      simple/SimpleCollectionTest.java
      ServiceTest.java, CollectionTest.java, ...
      test/Context.java                         # Shared test fixture helper
```

## Key Architecture Decisions

### Two API Layers

- **Functional API** (`de.swiesend.secretservice.functional`) — Recommended. Instance-scoped connections, `Optional` returns, `AutoCloseable` lifecycle. Entry point: `SecretService.create()`.
- **SimpleCollection** (`de.swiesend.secretservice.simple`) — Legacy backward-compatible adapter. Static shared D-Bus connection with JVM shutdown hook. Delegates internally to the functional API.

### Connection Ownership Model

- `System.connect()` creates an **owned** connection — `close()` disconnects it.
- `System.wrap(DBusConnection)` wraps an **existing** connection without ownership — `close()` is a no-op. Used by `SimpleCollection` to share its static connection with the functional layer.
- `SimpleCollection` wraps its static connection via `System.wrap()` so both layers share one D-Bus connection. The static `disconnect()` / shutdown hook owns the lifecycle.

### Secure Secret Cleanup

- `Secret` implements `AutoCloseable` — `close()` zeroes the `byte[] value` via `Arrays.fill`.
- The functional API never exposes `Secret` objects to callers. `getSecret()` returns `Optional<char[]>` after closing the `Secret` internally via try-with-resources.
- **`withSecret()` / `withSecrets()` callbacks** are the recommended API: the library decrypts, passes `char[]` to the callback, zeroes in `finally`. Callers never manage cleanup. The map passed to `withSecrets()` is unmodifiable, and values are snapshotted before the callback to prevent leak via map mutation.
- Avoid creating `new String(secret)` from `char[]` inside callbacks — `String` is immutable and cannot be cleared.

### D-Bus Message Handling

- `MessageHandler` constructs `MethodCall` messages directly using dbus-java's public constructor API.
- dbus-java 4.x is pinned at 4.3.1. The 5.x upgrade is deferred because 5.2.0 made all `MethodCall` constructors protected with no public alternative, requiring reflection + `--add-opens` which is not acceptable for library consumers on strict JPMS.
- Error responses are checked via `instanceof org.freedesktop.dbus.errors.Error` (4.x package location; moved to `messages.Error` in 5.x).

### JPMS Module

```java
module de.swiesend.secretservice {
    requires transitive org.freedesktop.dbus;
    requires at.favre.lib.hkdf;
    requires org.slf4j;
    opens de.swiesend.secretservice to org.freedesktop.dbus;
    exports de.swiesend.secretservice;
    exports de.swiesend.secretservice.simple;
    exports de.swiesend.secretservice.interfaces;
    exports de.swiesend.secretservice.functional;
    exports de.swiesend.secretservice.functional.interfaces;
    exports de.swiesend.secretservice.gnome.keyring.interfaces;
}
```

### Key Dependencies

| Dependency | Version | Purpose |
|---|---|---|
| `dbus-java-core` | 4.3.1 | D-Bus communication |
| `dbus-java-transport-native-unixsocket` | 4.3.1 | Unix socket transport |
| `hkdf` (at.favre.lib) | 2.0.0 | HMAC-based key derivation |
| `slf4j-api` | 2.0.17 | Logging |
| `junit-jupiter` | 5.10.5 | Testing (test scope) |

### Null Safety

All public API boundary methods validate parameters:
- `Objects.requireNonNull` for `Optional` parameters and callbacks
- `IllegalArgumentException` for null/blank labels
- `IllegalStateException` for disconnected connections in `System.wrap()`
- `Static.Utils.isNullOrEmpty()` for String/path parameters

### Exception Strategy

- **Functional API**: Returns `Optional.empty()` on failure, logs errors via SLF4J. No checked exceptions.
- **SimpleCollection** (legacy): Throws `IOException`, `SecurityException`, `IllegalArgumentException` to match the 1.x contract.
- `InterruptedException`: Always restore interrupt flag via `Thread.currentThread().interrupt()` before logging/returning.

## Code Conventions

- **Logging:** SLF4J via `LoggerFactory.getLogger(getClass())` per class
- **Resource cleanup:** Use `AutoCloseable` / try-with-resources. Sensitive byte arrays cleared with `Arrays.fill(bytes, (byte) 0)`
- **Naming:** Standard Java conventions (PascalCase classes, camelCase methods, `get`/`set`/`is` prefixes)
- **Error handling:** Custom exceptions in `errors/` package. D-Bus exceptions caught and logged via `MessageHandler`
- **No code formatting tools** (no checkstyle, spotbugs, or editorconfig configured)

## Testing

All tests are **integration tests** requiring a running D-Bus session bus and gnome-keyring. CI runs in a Docker container (`.github/dbus-mock/`) with a mock D-Bus + gnome-keyring-daemon.

```bash
docker build -f .github/dbus-mock/Dockerfile -t secret-service-test .
docker run --rm -v "$(pwd)":/workspace secret-service-test
```

- `DBusConnection.isConnected()` is **unreliable after `close()`** in dbus-java 4.x — do not assert on post-close connection state.
- Use `Thread.sleep()` (not `Thread.currentThread().sleep()`) for D-Bus signal waits.
- `@Disabled` tests require interactive prompts or affect global state — the reason is in the annotation string.

## Security Considerations

- Transport encryption uses DH key exchange + AES-128-CBC (not optional for production use)
- Secrets are wrapped in `AutoCloseable` types that clear sensitive data on close
- Byte arrays holding secrets are zeroed after use
- The library addresses CVE-2018-19358 (gnome-keyring prompt bypass)
- `withSecret()` callback API guarantees zeroing even on exception paths

## Git Conventions

- Commit messages: capitalized, descriptive subject line. Reference issues with `Resolves: #N` or link format
- Branches:
  - **`main`** — Production branch
  - **`develop-2.x.x`** — Long-lived development branch for the next release
  - **Feature branches** — Slash notation (e.g., `claude/feature-name`)

## Versioning

Semantic versioning: `{MAJOR}.{MINOR}.{PATCH}[-{SNAPSHOT|alpha|beta|rc}.?{INC}?]`

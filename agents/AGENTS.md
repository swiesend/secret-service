# Agent Instructions

This is the unified instruction file for all AI agents (Claude Code, GitHub Copilot, etc.) working on the `secret-service` codebase. For the full design roadmap and historical context, see [`docs/vision.md`](../docs/vision.md).

## Project Overview

**secret-service** is a Java library for storing secrets in a keyring over D-Bus, implementing the [freedesktop.org Secret Service API 0.2](https://specifications.freedesktop.org/secret-service/0.2/). It is the Java equivalent of the `libsecret` C library, tested against gnome-keyring, KeePassXC, KWallet 5 and 6, and oo7.

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

Maven 3.6.3+ is enforced, by `maven-enforcer-plugin` in `core/pom.xml`. No Gradle support.

## Project Structure

```
pom.xml                                         # build aggregator only; never published
core/pom.xml                                    # the library: de.swiesend:secret-service
core/src/main/java/
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

core/src/test/java/
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

- `System.connect()` takes a share of dbus-java's **shared** connection, which every `System.connect()` in the JVM gets — `close()` gives up this System's share, once, and the last share closes the connection.
- `System.wrap(DBusConnection)` wraps an **existing** connection without ownership — `close()` is a no-op. Used by `SimpleCollection` to share its static connection with the functional layer.
- `SimpleCollection` wraps its static connection via `System.wrap()` so both layers share one D-Bus connection. The static `disconnect()` / shutdown hook owns the lifecycle.

### Secure Secret Cleanup

- `Secret` implements `AutoCloseable` — `close()` zeroes the `byte[] value` via `Arrays.fill`.
- The functional API never exposes `Secret` objects to callers. `getSecret()` returns `Optional<char[]>` after closing the `Secret` internally via try-with-resources.
- **`withSecret()` / `withSecrets()` callbacks** are the recommended API: the library decrypts, passes `char[]` to the callback, zeroes in `finally`. Callers never manage cleanup. The map passed to `withSecrets()` is unmodifiable, and values are snapshotted before the callback to prevent leak via map mutation.
- Avoid creating `new String(secret)` from `char[]` inside callbacks — `String` is immutable and cannot be cleared.

### D-Bus Message Handling

- `MessageHandler` constructs `MethodCall` messages via `connection.getMessageFactory().createMethodCall(...)`. The direct `new MethodCall(...)` constructor was made non-public in dbus-java 5.x; `MessageFactory` is the supported public alternative and works without reflection or `--add-opens`.
- dbus-java is pinned at 5.2.0. This resolves classpath collisions (e.g. issue #51) when other libraries on the classpath ship a newer dbus-java that no longer provides the 4.x public `MethodCall` constructor.
- Error responses are checked via `instanceof org.freedesktop.dbus.messages.Error` (the class moved from `org.freedesktop.dbus.errors.Error` in 4.x).
- D-Bus byte arrays (signature `ay`) may be unmarshalled as either `byte[]` or `List<Byte>` in dbus-java 5.1.0+. `Static.Utils.toByteArray(Object)` normalizes both representations to `byte[]`.

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
    exports de.swiesend.secretservice.gnome.keyring;
    exports de.swiesend.secretservice.handlers;
    exports de.swiesend.secretservice.simple.interfaces;
}
```

An exported class may extend, implement or return only exported types; `ModuleExportsTest` checks
it, as `javac -Xlint:exports` would.

### Key Dependencies

| Dependency | Version | Purpose |
|---|---|---|
| `dbus-java-core` | 5.2.0 | D-Bus communication |
| `dbus-java-transport-native-unixsocket` | 5.2.0 | Unix socket transport |
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

- **Logging:** SLF4J via `LoggerFactory.getLogger(<DeclaringClass>.class)` per class — not `getClass()`, which names the runtime subclass, so that a consumer's configured logger name fails to match. No label or secret in a log message: a label often describes the secret it guards.
- **Resource cleanup:** Use `AutoCloseable` / try-with-resources. Sensitive byte arrays cleared with `Arrays.fill(bytes, (byte) 0)`
- **Naming:** Standard Java conventions (PascalCase classes, camelCase methods, `get`/`set`/`is` prefixes)
- **Error handling:** Custom exceptions in `errors/` package. D-Bus exceptions caught and logged via `MessageHandler`
- **No code formatting tools** (no checkstyle, spotbugs, or editorconfig configured)

## Testing

All tests are **integration tests** requiring a running D-Bus session bus and a Secret Service
provider. CI runs in per-provider Docker containers under `.github/providers/` (each starts a
path-based D-Bus via the shared `dbus-up.sh`, then its provider daemon).

```bash
# Default regression run (gnome-keyring), mirrors regression-tests.yml
docker build -f .github/providers/gnome-keyring/Dockerfile -t secret-service-test .
docker run --rm -v "$(pwd)":/workspace secret-service-test
```

- Tests tagged `@Tag("system-test")` are excluded from the default `mvn test` and run via the
  `system-test` profile (`mvn test -Psystem-test`). `ProviderSystemTest` is provider-agnostic and
  runs against whichever provider serves `org.freedesktop.secrets` (gnome-keyring, KeePassXC,
  KWallet, oo7), skipping cleanly (`Assumptions`) when a provider/collection is absent, or
  failing instead with `-Dsecret-service.system-test.required=true`, which every CI leg passes. The
  `system-tests.yml` workflow runs it against gnome-keyring, KWallet 5 and 6, KeePassXC as it
  comes and with per-item confirmation (`keepassxc-confirm`), oo7, and gnome-keyring with its
  dialogs shown and answered through xdotool (`gnome-keyring-dialogs`); only the gnome-keyring
  leg is required.
- The standalone developer GUI lives in the separate `tools/gui` project (not in the test suite or
  the core jar). Launch it with `mvn -DskipTests -Dgpg.skip=true install` then
  `mvn -f tools/gui/pom.xml exec:java`.
- `DBusConnection.isConnected()` was **unreliable after `close()`** in dbus-java 4.x, and `System.connect()`'s shared connection stays open while another holder has a share — do not assert on post-close connection state.
- Use `Thread.sleep()` (not `Thread.currentThread().sleep()`) for D-Bus signal waits.
- A test that needs a user to answer a dialog runs only with `-Dsecret-service.system-test.dialogs-answered=true`, and one that also locks or writes into the default collection only with `-Dsecret-service.system-test.default-collection=throwaway` as well: `@EnabledIfSystemProperty` on the flags of `integration.test.Dialogs`, with its reason as `disabledReason`. The `gnome-keyring-dialogs` CI leg sets both; never set the second where the default collection is a user's. Its container also exports `SECRET_SERVICE_DIALOG_CONTROL`, through which a test holds the dialog answerer back, as a user who is away (`Dialogs.hold()`, `release()`), and has it cancel the dialog on the screen (`Dialogs.cancelTheDialog()`); such a test runs only there (`@EnabledIfEnvironmentVariable`).
- The other `@Disabled` tests touch the user's own keyring, need a dialog that the CI leg does not answer, or depend on timing or on the rest of the run; the annotation string says which. Give every new one its reason.
- A provider's bug has its entry in `ProviderBug`, next to `FakeSecretService`: what the provider does, the versions known to have it, its report upstream or that it is not reported, and what the library does about it. The fake follows the specification unless a test turns a bug on with `FakeSecretService.reproduce(...)`, and a test of a workaround turns on the bug that it works around. Give a newly found bug its entry.

## Security Considerations

- Transport encryption uses DH key exchange + AES-128-CBC (not optional for production use)
- Secrets are wrapped in `AutoCloseable` types that clear sensitive data on close
- Byte arrays holding secrets are zeroed after use
- The library mitigates CVE-2018-19358 (gnome-keyring hands an unlocked keyring to every client) for reading all secrets and deleting items: `unlockWithUserPermission()` locks the collection, then unlocks it through the provider's dialog, or on gnome-keyring with the password that the collection was opened with. Reading a single secret is not gated, and KeePassXC, which locks only through a prompt, confirms access itself
- `withSecret()` callback API guarantees zeroing even on exception paths

## Git Conventions

- Commit messages: capitalized, descriptive subject line. Reference issues with `Resolves: #N` or link format
- Branches:
  - **`main`** — Production branch
  - **`develop-2.x.x`** — The 2.x line
  - **`develop-3.x.x`** — The 3.x line, for fixes to 3.x once 4.0 is on `main`; the workflows run on it too
  - **Feature branches** — Slash notation (e.g., `claude/feature-name`)

## Versioning

Semantic versioning: `{MAJOR}.{MINOR}.{PATCH}[-{SNAPSHOT|alpha|beta|rc}.?{INC}?]`

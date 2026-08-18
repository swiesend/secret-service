# Agent Instructions

This is the unified instruction file for all AI agents (Claude Code, GitHub Copilot, etc.) working on the `secret-service` codebase. For the full design roadmap and historical context, see [`docs/roadmap.md`](../docs/roadmap.md).

## Project Overview

**secret-service** is a Java library for storing secrets in a keyring over D-Bus, implementing the [freedesktop.org Secret Service API 0.2](https://specifications.freedesktop.org/secret-service/0.2/). It is the Java equivalent of the `libsecret` C library, compatible with GNOME Linux systems (gnome-keyring, KeePassXC).

- **Group/Artifact:** `de.swiesend:secret-service`
- **License:** MIT
- **JDK:** Requires JDK 25 to build

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

- `MessageHandler` constructs `MethodCall` messages via `connection.getMessageFactory().createMethodCall(...)`. The direct `new MethodCall(...)` constructor was made non-public in dbus-java 5.x; `MessageFactory` is the supported public alternative and works without reflection or `--add-opens`.
- dbus-java is pinned at 5.2.0. This resolves classpath collisions (e.g. issue #51) when other libraries on the classpath ship a newer dbus-java that no longer provides the 4.x public `MethodCall` constructor.
- Error responses are checked via `instanceof org.freedesktop.dbus.messages.Error` (the class moved from `org.freedesktop.dbus.errors.Error` in 4.x).
- D-Bus byte arrays (signature `ay`) may be unmarshalled as either `byte[]` or `List<Byte>` in dbus-java 5.1.0+. `Static.Utils.toByteArray(Object)` normalizes both representations to `byte[]`.

### JPMS Module

```java
module de.swiesend.secretservice {
    requires transitive org.freedesktop.dbus;
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
| `dbus-java-core` | 5.2.0 | D-Bus communication |
| `dbus-java-transport-native-unixsocket` | 5.2.0 | Unix socket transport |
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

## Working Conventions

**Edit files with the Edit/Write tools, not with `sed -i` or `python3 - <<PY` heredocs.** The
maintainer reads the session transcript to follow what changed: an `Edit` call renders as a
reviewable diff, a heredoc renders as an opaque blob whose effect has to be reconstructed
afterwards. On a security-sensitive repository that difference is the review.

Reserve scripted edits for genuinely repetitive bulk work across many files — and say what the
script will do before running it.

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
  KWallet), skipping cleanly (`Assumptions`) when a provider/collection is absent. The
  `system-tests.yml` workflow runs it across all three providers (KWallet/KeePassXC legs are
  non-blocking).
- The standalone developer GUI lives in the separate `tools/gui` project (not in the test suite or
  the core jar). Launch it with `mvn -DskipTests -Dgpg.skip=true install` then
  `mvn -f tools/gui/pom.xml exec:java`.
- `DBusConnection.isConnected()` is **unreliable after `close()`** in dbus-java 4.x — do not assert on post-close connection state.
- Use `Thread.sleep()` (not `Thread.currentThread().sleep()`) for D-Bus signal waits.
- `@Disabled` tests require interactive prompts or affect global state — the reason is in the annotation string.

## Security Considerations

- Transport encryption uses DH key exchange + AES-128-CBC (not optional for production use)
- Secrets are wrapped in `AutoCloseable` types that clear sensitive data on close
- Byte arrays holding secrets are zeroed after use
- The library addresses CVE-2018-19358 (gnome-keyring prompt bypass)
- `withSecret()` callback API guarantees zeroing even on exception paths

## Documentation Conventions

`docs/` is written **for humans** — consumers of the library and operators deploying it. Editorial
rules, maintenance notes and reminders to yourself belong here in `AGENTS.md`, never on a page a
reader is trying to learn from.

### Every Java snippet in `docs/` must compile

`.github/scripts/check_doc_snippets.py` extracts every ` ```java ` fence, wraps it, and compiles it
against the built artifacts. It runs in `docs.yml` and fails the build on any error.

```bash
mvn -q -B -pl core,hardened,hardened-tpm2 -am install -DskipTests -Dgpg.skip=true
mvn -q -B -pl core,hardened,hardened-tpm2 -am dependency:build-classpath \
    -Dmdep.outputFile="$PWD/target/docs-cp.txt" -Dmdep.regenerateFile=true
python3 .github/scripts/check_doc_snippets.py
```

- The workflow triggers on `*/src/main/**` as well as `docs/**`: prose breaks when the **API** moves,
  not when the prose does. Keep it that way.
- **Never stub a library symbol** in the script's `STUBS` block — that is exactly what the check
  verifies. Only the reader's own symbols (`httpClient`, `grantAccess()`) or a variable carried over
  from an earlier fence on the same page.
- Opt out of one fence with `<!-- docs-compile: skip <reason> -->`. Currently used once.
- `de.swiesend.secretservice.functional` is imported class-by-class in the harness, never by
  wildcard: it contains a class named `System`, which a wildcard makes ambiguous with
  `java.lang.System`.

**Why it exists:** a scan that only asked "does this symbol appear anywhere in the sources" passed a
**private** `unlock()` and left a non-compiling example on all three usage pages for months. Verify
against the *declared type's public surface*, or better, just compile it.

### One canonical home per threat-coverage verdict

A verdict copied into two tables is a verdict that will eventually disagree with itself — that
happened here, and the copies had already drifted before anyone noticed.

| Verdict about… | Canonical home |
|---|---|
| a hardening mechanism (SELinux, seccomp, systemd, …) | its entry in `docs/security/defense-mechanisms.md` |
| LUKS / full-disk encryption | `docs/security/full-disk-encryption.md` |
| a distribution format (tar.gz, jpackage, Snap, OCI, …) | the format-vs-class table in `docs/security/sample-configurations.md` |
| a backend (gnome-keyring, KeePassXC, stacking) | the class-by-class table in `docs/security/backend-choice.md` |

Adding a verdict: put it in its home and link. Finding one stated twice: delete the copy, and check
first whether the two had already diverged.

### Style

- Warnings and asides use a **bold lead-in** (`**Pitfalls.**`), not MkDocs admonitions — `admonition`
  is enabled but nothing uses it, so introducing one is a style fork.
- Never put markdown links inside a fenced code block; they render as literal text. Put them in prose
  beneath the fence.
- Explain *why*, not only *what* — the algorithm rationale lives in
  `docs/architecture/index.md#why-these-primitives`, and much of it was promoted from Javadoc that
  readers of the site never saw.
- `mkdocs build --strict` fails on broken links and anchors; moving a heading changes its slug, so
  update every inbound link in the same commit.

## Git Conventions

- Commit messages: capitalized, descriptive subject line. Reference issues with `Resolves: #N` or link format
- Branches:
  - **`main`** — Production branch
  - **`develop-2.x.x`** — Long-lived development branch for the next release
  - **Feature branches** — Slash notation (e.g., `claude/feature-name`)

## Versioning

Semantic versioning: `{MAJOR}.{MINOR}.{PATCH}[-{SNAPSHOT|alpha|beta|rc}.?{INC}?]`

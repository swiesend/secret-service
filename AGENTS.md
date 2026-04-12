# AGENTS.md

## Overview

This file provides guidance for AI agents working on the `secret-service` codebase. For the full design roadmap and historical context, see [`docs/vision.md`](docs/vision.md).

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

```
module de.swiesend.secretservice {
    requires transitive org.freedesktop.dbus;
    exports de.swiesend.secretservice;
    exports de.swiesend.secretservice.simple;
    exports de.swiesend.secretservice.interfaces;
    exports de.swiesend.secretservice.functional;
    exports de.swiesend.secretservice.functional.interfaces;
    exports de.swiesend.secretservice.gnome.keyring.interfaces;
}
```

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

## Testing

All tests are **integration tests** requiring a running D-Bus session bus and gnome-keyring. CI runs in a Docker container (`.github/dbus-mock/`) with a mock D-Bus + gnome-keyring-daemon.

```bash
docker build -f .github/dbus-mock/Dockerfile -t secret-service-test .
docker run --rm -v "$(pwd)":/workspace secret-service-test
```

- `DBusConnection.isConnected()` is **unreliable after `close()`** in dbus-java 4.x — do not assert on post-close connection state.
- Use `Thread.sleep()` (not `Thread.currentThread().sleep()`) for D-Bus signal waits.
- `@Disabled` tests require interactive prompts or affect global state — the reason is in the annotation string.

## Build

```bash
mvn clean compile    # Compile (requires JDK 17+)
mvn test             # Run tests (requires D-Bus mock container)
```

Maven 3.6.0+ enforced. dbus-java pinned at 4.3.1. See `pom.xml` for all dependency versions.

# Vision for develop-2.x.x

This document captures the design goals, known issues, and planned direction for the 2.x.x line of `secret-service`.

## Background

The 1.x API shipped a single high-level entry point (`SimpleCollection`) backed by a static D-Bus connection. While this made basic usage straightforward, the design created several fundamental problems that surfaced as the library gained adoption in projects like [Cryptomator](https://github.com/cryptomator/integrations-linux) and [KeePassXC](https://keepassxc.org/) integrations.

The 2.0.0-alpha (August 2023) addressed the most pressing structural issue -- Java module system (JPMS) compatibility -- but the broader API redesign remains in progress on the [`develop-2.x.x`](https://github.com/swiesend/secret-service/tree/develop-2.x.x) branch.

## What shipped in 2.0.x-alpha

- **JPMS modularization** ([#38](https://github.com/swiesend/secret-service/issues/38), [#40](https://github.com/swiesend/secret-service/pull/40)): Packages moved from `org.freedesktop.*` / `org.gnome.*` to `de.swiesend.secretservice.*` to eliminate split packages. A `module-info.java` was added.
- **Dependency upgrades**: dbus-java 3.x to 4.3.0, hkdf 1.x to 2.0.0, slf4j 1.x to 2.x.
- **Native unix sockets** ([#36](https://github.com/swiesend/secret-service/pull/36)): Replaced JNR-based transport with JDK-native unix sockets (requires JDK 17+).
- **Non-gnome compatibility** ([#34](https://github.com/swiesend/secret-service/issues/34), [#35](https://github.com/swiesend/secret-service/pull/35)): Deferred loading of gnome-keyring-specific interfaces so the library does not crash with non-gnome secret service providers.

## Design goals for 2.x

### 1. Separate service lifetime from session lifetime

**Problem:** `SimpleCollection` owns both the D-Bus connection (static, long-lived) and the encryption session (instance-scoped). This creates issues when multiple `SimpleCollection` instances are used sequentially -- closing one can break the shared connection ([#30](https://github.com/swiesend/secret-service/issues/30)), and the static lifetime makes it impossible to properly scope connection lifecycle ([#7](https://github.com/swiesend/secret-service/issues/7)).

**Direction:** A new functional-style API ([PR #32](https://github.com/swiesend/secret-service/pull/32)) introduces `SecretService.create()` as the entry point under `de.swiesend.secretservice.functional`. The design separates:
- A **service** object (owns the D-Bus connection, long-lived)
- A **session** object (owns the encryption context, short-lived, scoped to operations)

This allows callers to hold a single service and open/close sessions as needed, avoiding the static connection pitfalls.

### 2. Functional-programming-friendly API

**Problem:** The current API uses mutable state, null returns, and checked exceptions extensively, making it difficult to compose operations safely.

**Direction:** The 2.x API aims to use `Optional` returns and a more composable style. An open design challenge is the interplay between `Optional` and `AutoCloseable` -- resources wrapped in `Optional` do not integrate naturally with try-with-resources ([PR #32](https://github.com/swiesend/secret-service/pull/32) discussion).

### 3. Broader secret service provider compatibility

**Problem:** The library was originally designed for gnome-keyring. Other providers that implement the freedesktop Secret Service spec (KeePassXC, KWallet) have stricter or different behaviors:
- KeePassXC requires per-item unlocking before retrieval ([#45](https://github.com/swiesend/secret-service/issues/45))
- Non-gnome providers do not expose `org.gnome.keyring` on D-Bus ([#34](https://github.com/swiesend/secret-service/issues/34))

**Direction:** The 2.x API should treat gnome-specific functionality (e.g., `InternalUnsupportedGuiltRiddenInterface`) as strictly optional and support the per-item unlock flow required by KeePassXC ([PR #46](https://github.com/swiesend/secret-service/pull/46)).

### 4. Updated dbus-java

**Problem:** The current 2.0.1-alpha pins dbus-java at 4.3.0. Projects that also depend on dbus-java (e.g., `kdewallet`) may pull in 5.x, causing `NoSuchMethodError` at runtime ([#51](https://github.com/swiesend/secret-service/issues/51)).

**Direction:** Upgrade to dbus-java 5.x ([PR #48](https://github.com/swiesend/secret-service/pull/48), [PR #50](https://github.com/swiesend/secret-service/pull/50)) to align with the broader ecosystem.

### 5. CI and automated testing

**Problem:** All tests are integration tests requiring a running D-Bus session bus and a secret service provider. There is no CI pipeline ([PR #43](https://github.com/swiesend/secret-service/pull/43) is a draft attempt). D-Bus `abstract` socket handling creates challenges for JDK native sockets in CI environments.

**Direction:** Establish GitHub Actions CI with a D-Bus session bus mock or containerized gnome-keyring. This would catch regressions and enable confident merging of dependency upgrades.

## Open pull requests relevant to 2.x

| PR | Title | Status | Impact |
|----|-------|--------|--------|
| [#32](https://github.com/swiesend/secret-service/pull/32) | Draft: Develop 2.x.x | Draft | Core functional API redesign |
| [#50](https://github.com/swiesend/secret-service/pull/50) | Update dbus-java 4.3.1 > 5.1.0 | Open | Dependency alignment |
| [#48](https://github.com/swiesend/secret-service/pull/48) | dbus-java 5.0.0 | Open | Dependency alignment |
| [#46](https://github.com/swiesend/secret-service/pull/46) | Unlock items before retrieval | Open | KeePassXC compatibility |
| [#43](https://github.com/swiesend/secret-service/pull/43) | [WIP] Add initial CI | Draft | Infrastructure |

## Known design tensions

- **`Optional` vs `AutoCloseable`:** The functional API wants to return `Optional<Secret>`, but `Secret` implements `AutoCloseable` for secure cleanup. `Optional` has no built-in resource management, so callers must manually handle the lifecycle of the contained value. This remains an open design question.
- **Static connection vs instance connection:** The 1.x `SimpleCollection` uses a static `DBusConnection` shared across all instances with a JVM shutdown hook. The 2.x API needs to move to instance-scoped connections without breaking the simple "just works" experience for basic usage.
- **Backward compatibility:** The 2.0.0-alpha already broke package names (necessary for JPMS). The functional API will be a new package (`functional`), so the existing `SimpleCollection` can coexist during a transition period.

## Version history context

| Version | Date | Milestone |
|---------|------|-----------|
| 1.0.0 | May 2020 | Initial stable release |
| 1.8.0-jdk17 | Dec 2022 | JDK 17 requirement, dbus-java 4.x, native sockets |
| 2.0.0-alpha | Aug 2023 | JPMS module, package rename, hkdf 2.x |
| 2.0.1-alpha | Jan 2024 | Bugfix (`DBusExecutionException` at startup) |
| 2.x (next) | TBD | Functional API, dbus-java 5.x, KeePassXC support |

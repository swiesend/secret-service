# Roadmap

Design goals, current state, and direction of `secret-service`. The current line is **3.0.0-alpha** — a Maven reactor of three artifacts released in lockstep. For the release-by-release record see the [changelog](changelog.md).

## Where the project stands (3.0.0-alpha)

Everything the 2.x plan set out to do has shipped:

- **Functional API** (`de.swiesend.secretservice.functional`) — instance-scoped connections, `Optional` returns, `AutoCloseable` lifecycle, and the callback-based `withSecret`/`withSecrets` access that guarantees plaintext zeroing (resolving the `Optional`-vs-`AutoCloseable` cleanup tension the 2.x design identified). `SimpleCollection` remains as a backward-compatible adapter delegating to the functional layer.
- **dbus-java 5.2.0** — resolves classpath collisions with consumers that ship their own dbus-java ([#51](https://github.com/swiesend/secret-service/issues/51)); messages built via the public `MessageFactory` (no reflection, no `--add-opens`).
- **JDK 25 baseline** — all modules target `--release 25`; post-quantum ML-KEM-768 comes natively from SunJCE (JEP 496), so no third-party crypto provider is needed for the KEM.
- **Provider breadth** — gnome-keyring, KeePassXC, and KWallet (ksecretd) are exercised by a provider-agnostic system-test suite in CI; gnome-specific interfaces are deferred-loaded ([#34](https://github.com/swiesend/secret-service/issues/34)).
- **CI** — regression tests, per-provider system tests, and a TPM system test against the ms-tpm-20-ref simulator run on every push/PR.
- **Opt-in hardening** — `secret-service-hardened` (AES-256-GCM envelopes, `KeyMaterialProvider` SPI, hybrid X25519 + ML-KEM-768 with epoch rotation and forward secrecy) and `secret-service-hardened-tpm2` (TPM-sealed pepper, NV-counter anti-rollback anchor). See the [architecture diagrams](architecture/index.md) and the [security guide](security/index.md).
- **Honest security posture** — a [security audit](audits/2026-07-security-audit-hardened.md) drove envelope v2 (full-header AEAD), the anti-rollback fix, binary-safe TPM sealing, and ultimately the **removal of TOTP time-binding** (always security theater in the shipped configurations; see audit finding F-5).

## Open items toward 3.0.0 stable

- **Release engineering** — publish the three-artifact reactor (`secret-service`, `secret-service-hardened`, `secret-service-hardened-tpm2`) to Maven Central; establish the release cadence off `main`.
- **Provider-leg stabilization** — the KWallet and KeePassXC system-test legs are non-blocking (headless bring-up is fragile); make them reliable enough to gate merges.
- **Per-item unlock flow** — KeePassXC requires unlocking items before retrieval ([#45](https://github.com/swiesend/secret-service/issues/45), [PR #46](https://github.com/swiesend/secret-service/pull/46)); fold this into the functional API rather than a provider-specific workaround.
- **Connection robustness** — `EOFException` on send after connection loss ([#52](https://github.com/swiesend/secret-service/issues/52)); the functional API should surface a reconnect story instead of a dead session.
- **Containerized consumers** — document/detect the "no Secret Service on the bus" case cleanly ([#41](https://github.com/swiesend/secret-service/issues/41)); the [CI deployment guide](security/ci-deployment.md) covers the patterns, but the library error path can be friendlier.
- **Possession-based factors, if ever, done honestly** — TOTP was removed because a seed-holding process gains nothing from time-binding. A real second factor would need an *oracle-shaped* SPI (e.g. `getCode(step)` served by an off-machine device) rather than `getTotpSeed()`. Explicitly out of scope until there is a design that does not co-locate the factor with the pepper.

## Design invariants (unchanged)

These carried over from the 2.x design work and still bind every change:

- **No API shape may make it easy to leak secret bytes in memory.** Plaintext crosses the API boundary only inside zero-after-use callbacks; `String` never carries a secret.
- **Non-destructive by default.** The hardened layer never reads, overwrites, or deletes items it did not write; migration of foreign items is dual-gated (builder flag + env var).
- **Honest threat coverage.** Every `KeyMaterialProvider` declares what it actually defends against; theater-rated providers are refused in production builds unless explicitly acknowledged.

## 2.x history (condensed)

The 2.x line was the bridge from the static 1.x `SimpleCollection` design to the functional API:

- **2.0.0-alpha (Aug 2023)** — JPMS modularization: packages moved from `org.freedesktop.*`/`org.gnome.*` to `de.swiesend.secretservice.*` to eliminate split packages ([#38](https://github.com/swiesend/secret-service/issues/38)); dbus-java 3.x→4.3, JDK-native unix sockets ([#36](https://github.com/swiesend/secret-service/pull/36)).
- **2.0.1-alpha (Jan 2024)** — startup `DBusExecutionException` bugfix.
- The remaining 2.x goals (service/session lifetime split [#7](https://github.com/swiesend/secret-service/issues/7)/[#30](https://github.com/swiesend/secret-service/issues/30), functional API [PR #32](https://github.com/swiesend/secret-service/pull/32), dbus-java 5, CI) shipped in 3.0.0-alpha.

| Version | Date | Milestone |
|---------|------|-----------|
| 1.0.0 | May 2020 | Initial stable release |
| 1.8.0-jdk17 | Dec 2022 | JDK 17, dbus-java 4.x, native unix sockets |
| 2.0.0-alpha | Aug 2023 | JPMS module, package rename, hkdf 2.x |
| 2.0.1-alpha | Jan 2024 | Startup bugfix |
| 3.0.0-alpha | Jun 2026 | Functional API, dbus-java 5.2, JDK 25, reactor split, hardened + tpm2 |

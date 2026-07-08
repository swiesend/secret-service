# Changelog

The [secret-service](https://github.com/swiesend/secret-service) library implements the [Secret Service API 0.2](https://specifications.freedesktop.org/secret-service/0.2/).

## Unreleased

Landed on `main` after the `v3.0.0-alpha` tag; not part of a published release.

- `Added`:
  - Standalone developer **GUI** extracted to a separate `tools/gui` module (not part of the library jar).
  - Provider-agnostic system tests: `ProviderSystemTest` (`@Tag("system-test")`, run via `-Psystem-test`) exercised in CI across gnome-keyring, KeePassXC, and KWallet; plus `ProviderDetectorTest` and `SecretCleanupTest`.
  - `CollectionLockLogicTest`: daemon-free unit tests covering the `lock()` decision helpers (`containsPath`, `requiresPrompt`, `awaitUntil`).
- `Changed`:
  - **Build/runtime baseline raised to JDK 25** — all modules (`core`, `hardened`, `hardened-tpm2`) now target `--release 25`. **Breaking** for consumers of the core `secret-service` artifact, which previously targeted JDK 17. As a result, post-quantum ML-KEM-768 uses the stock SunJCE provider natively (JEP 496, JDK 24+), so **BouncyCastle is no longer needed for the KEM** — the removed reflective provider-registration/parameter-spec code is gone, and BouncyCastle remains only as an optional `provided` dependency of `Argon2KeyMaterialProvider` (Argon2id has no JDK-native implementation). CI provider images (gnome-keyring/KeePassXC/KWallet) build on JDK 25.
  - `Collection.lock()` is now response-aware: it branches on the Secret Service `Lock` response `(locked, prompt)`, returning promptly instead of waiting out the timeout when the collection cannot be locked (a lock requiring a prompt, or a non-lockable collection). `lock()` and collection creation also poll the expected state up to `Static.DBus.MAX_DELAY_MILLIS` instead of a single fixed `Thread.sleep(DEFAULT_DELAY_MILLIS)`, so under load `lock()` no longer spuriously returns `false` and a freshly created collection is no longer reported as "not created".
  - `CollectionTest.deleteWithALockedService` is `@Disabled`: `lockService()` locks the whole service including the user's login keyring (nothing re-unlocks it), popping an interactive unlock prompt during an otherwise headless run, and its gnome-keyring-specific setup cannot even open a session under `-Psystem-test` on KWallet/KeePassXC. `deleteALockedCollection` covers the locked-item case; remove `@Disabled` locally to run it against a throwaway gnome-keyring.
- `Fixed`:
  - Tolerate gnome-keyring's asynchronously-injected `xdg:schema` attribute in the functional attribute tests: `createItemWithAttribute` compares by containment, and `getAttributes` compares only user-defined keys — the latter's strict assertion previously raced and flaked (~1 run in 10) [#68](https://github.com/swiesend/secret-service/pull/68).

### Hardened application-layer encryption — opt-in, not yet released

New `secret-service-hardened` and `secret-service-hardened-tpm2` artifacts plus a Maven reactor split. Core consumers upgrade by changing only the version (no API change for `secret-service`); consumers who want application-layer encryption opt into the new artefacts.

- `Added` — architecture:
  - **Maven reactor split into three artifacts** at one version: `de.swiesend:secret-service` (JDK 17 classical client; only the build moved into a `core/` submodule — GAV unchanged), `de.swiesend:secret-service-hardened` (JDK 21; opt-in AES-256-GCM envelopes with HKDF-derived per-item DEKs, a pluggable `KeyMaterialProvider` SPI, optional Argon2id pepper-stretching, optional hybrid X25519 + ML-KEM-768 with persisted-and-destroyable epoch keypairs for forward secrecy), and `de.swiesend:secret-service-hardened-tpm2` (JDK 21; optional `Tpm2KeyMaterialProvider` + `Tpm2Provisioner` CLI for TPM-sealed peppers, classpath-only). Parent pom is a BOM pinning all three at one version.
- `Added` — hardened layer:
  - `HardenedCollection` decorator (`createItem` / `withSecret` / `withSecrets` / `matchesSecret` / `rotateEpoch` / `migrateNonHardenedToHardened`).
  - `KeyMaterialProvider` SPI (`getPepper`, `getTotpSeed`, `mode`, `threatCoverage`, `close()`); providers `EnvVarKeyMaterialProvider` (CI/dev only, loud warning), `FileKeyMaterialProvider`, `NoTotpKeyMaterialProvider`, and `Argon2KeyMaterialProvider` (Argon2id over the pepper; EMBEDDED/INTERACTIVE/SENSITIVE profiles per RFC 9106).
  - `HybridKem` (X25519 + ML-KEM-768): `enablePostQuantum(true)` writes `kem_id=0x01` envelopes whose AEAD key derives from HKDF including the ML-KEM shared secret; `EpochKeystore` persists per-epoch keypairs as an encrypted item and `rotateEpoch` destroys the previous epoch's key for forward secrecy.
  - `HardenedHealthCheck` (structured /healthz-style diagnostic, `toMap` for JSON), `ThreatCoverage` (per-class A/B/C/D `Level` ratings), `HardenedStatus` (epoch, time-binding mode, algorithms), and a one-line startup posture log.
  - `migrateNonHardenedToHardened(Predicate)` — dual-gated (Builder flag + `SECRET_SERVICE_HARDENED_ALLOW_MIGRATION=1`), per-item `MigrationReport`, create-then-delete ordering so crashes never lose data.
- `Added` — hardened-tpm2 layer:
  - `Tpm2KeyMaterialProvider.forPlatformTpm(...)` / `forSimulator(...)`; `Tpm2Provisioner` CLI with `--password-{stdin,env,fd,prompt}` and `--pepper-{stdin,env,fd}` sources (stdin conflict refused; no plaintext `--password`); versioned `Tpm2SealedBlob` (stable wire bytes, atomic mode-0600 write, group/other read refused); `Tpm2Availability.isAvailable()` preflight; TPM dictionary-attack lockout on the sealed object.
- `Added` — documentation:
  - `docs/threat_models_and_mitigation.md` (deployment threat-model guide) and `docs/usage_examples.md` (worked core/hardened/TPM examples).
- `Removed`:
  - **TOTP support removed entirely** (follow-through on audit F-5). `STORED_STEP` was security theater in every configuration — the step travelled beside the ciphertext and the SPI co-located the seed with the pepper, so any attacker holding the key material recomputed the factor — and `LIVE_CODE` was only a liveness window, never a possession factor, because the SPI exposed the raw seed to the process. Gone: `Totp`, `NoTotpKeyMaterialProvider`, `KeyMaterialProvider.Mode`/`getTotpSeed()`/`currentStep()`, the `hardened.totp.*` attributes, the `SECRET_SERVICE_TOTP_SEED`/`SECRET_SERVICE_TOTP_MODE` env vars, and `HardenedStatus.totpMode`/`timeBindingLabel()`. The envelope v2 byte layout is preserved (the ex-TOTP header bytes are reserved-zero) and the DEK IKM keeps its zero-length third slot, so **envelopes written without TOTP keep decrypting unchanged**; envelopes written *with* a TOTP mode are rejected at parse with a clear re-write hint.
  - `Tpm2Provisioner` no longer accepts `--password <plaintext>` (leaked into `/proc/<pid>/cmdline`); use the `--password-*` sources.
- `Security` — hardening from the security audit (`docs/audits/2026-07-security-audit-hardened.md`):
  - **Envelope format v2 (breaking, alpha only)**: the AES-256-GCM associated data now authenticates the entire envelope header, and the item id plus TOTP mode/step are embedded as authenticated envelope fields instead of being read from mutable D-Bus attributes — tampering a header field or relocating a ciphertext under another item's attributes now fails authentication. The per-item DEK KDF feeds every secret input (pepper, KEM shared secret, TOTP code) through the HKDF input keying material rather than the Expand `info`. v1 envelopes are no longer read [F-3, F-4].
  - **TPM NV generation-anchor fixed**: `Tpm2GenerationAnchor` / `Tpm2Provisioner.defineGenerationCounter` built the NV handle with `TPM_HANDLE.NV(fullHandle)`, which double-applied the NV base so every counter operation failed `TPM_RC_VALUE` — the anti-rollback anchor never actually functioned (masked because its tests skip without a TPM simulator). Now constructs the handle with `new TPM_HANDLE(...)` [F-8].
  - **Binary-safe TPM pepper**: `Tpm2Provisioner.seal` base64-encodes the pepper before sealing so any pepper round-trips losslessly through the text pepper SPI; sealed blobs bumped to v2 and old v1 blobs are rejected with a re-provision hint [F-9].
  - **Health check**: a provider whose `sameUid` threat coverage is `NONE` is now a hard `FAIL`, so a weak-but-decrypting deployment reports UNHEALTHY rather than HEALTHY [F-7].
  - **Provider hygiene**: `EnvVar`/`File`/`Interactive` providers scrub cached pepper/seed on `close()` (and fail closed afterwards); `NoTotpKeyMaterialProvider` now propagates `close()` and forwards `currentStep()`; `FileKeyMaterialProvider` degrades its `ThreatCoverage` to all-`NONE` when the POSIX 0600/owner check cannot run (non-POSIX filesystem) instead of asserting `crossUid=REAL` on trust [F-6].
  - **Honest warnings and docs**: loud warnings when forward secrecy is relied on without a `GenerationAnchor` (F-1) and when the TOTP mode is `STORED_STEP` (F-5); forward-secrecy Javadoc scoped to the store's delete semantics and backup-retention discipline (F-2); README hardened section leads with the honest threat scoping — no same-UID (class-A) defense, with the real value concentrated in the TPM path plus measured boot + a MAC policy + backup rotation (P-1, P-2).
- `Security` / `Changed` — hardening & simplification round 2:
  - **Envelope format v3** (breaking, alpha only): the AEAD and KDF are now agile like the KEM already was — authenticated `aead_id` and `kdf_id` selector bytes let a new cipher/KDF land without a format bump. **ChaCha20-Poly1305** ships as a second AEAD alongside AES-256-GCM, selectable via `HardenedCollection.Builder.aead(AeadId)`. `fromBytes` accepts only v3 (v1/v2 rejected). The dead `KEM_ID_NONE` write path was removed.
  - **TOTP removed entirely**: in every provider the TOTP seed was co-located with the pepper, so it was never an independent factor (`STORED_STEP` was self-admitted theater). Deleted `Totp`, the `Mode`/`getTotpSeed`/`currentStep` SPI surface, the `NoTotpKeyMaterialProvider` decorator, the envelope TOTP fields, and all provider seed handling.
  - **Process memory locking**: `HardenedStatus.memoryLocked` was advertised but never implemented; `Builder.lockMemory(true)` now calls `mlockall` via the JDK 25 Foreign Function & Memory API (opt-in; needs `--enable-native-access=de.swiesend.secretservice.hardened` and an adequate `RLIMIT_MEMLOCK`), and the status reports the real result.
  - **One fewer dependency**: the third-party `at.favre.lib:hkdf` is gone; HKDF-SHA256 now uses the native `javax.crypto.KDF` API (JEP 510, final in JDK 25) in both `core` and `hardened`. Byte-identical (RFC 5869 KATs).
  - **Testing**: `hardened-tpm2` tests now run against a software TPM (ibmswtpm2) in a new CI workflow (previously always skipped); coverage-guided **Jazzer** fuzzing of the envelope parser; RFC 5869 / AEAD known-answer tests; a manual throughput benchmark.
  - **Performance**: shared `SecureRandom` (was 3–5 fresh instances per write) and a dropped redundant buffer in the UTF-8 path.

## [3.0.0-alpha] - 2026-06-11

Major release introducing a new functional API and an upgrade to dbus-java 5. Requires **JDK 17**. Delivered on the `develop-2.x.x` line (now merged to `main`).

- `Added`:
  - New **functional API** (`de.swiesend.secretservice.functional`): `SecretService`, `Session`, `Collection`, `System`, backed by `functional.interfaces` (`ServiceInterface`, `SessionInterface`, `CollectionInterface`, `SystemInterface`, `Activatable`, `AvailableServices`). Instance-scoped connections, `Optional` returns instead of checked exceptions, and `AutoCloseable` lifecycle. Entry point: `SecretService.create()`.
  - Secure secret access on the functional API: `getSecret(...)` returns `Optional<char[]>` (never `String`), and `withSecret(path, Function<char[],R>)` / `withSecrets(Function<Map<String,char[]>,R>)` decrypt, hand the caller a `char[]`, and zero it in a `finally` block so plaintext does not linger on the heap.
  - **Search API**: `Collection.search(query, SearchMode)` with substring and fuzzy (Levenshtein) matching; `SearchMode` = `BY_NAME`, `BY_OBJECT_ID`, `BY_OBJECT_PATH`, `BY_ATTRIBUTE_KEY`, `BY_ATTRIBUTE_VALUE`.
  - **Provider detection**: `ProviderDetector` and `getProvider()` identify the backing Secret Service implementation (gnome-keyring, KeePassXC, KWallet served via ksecretd).
  - `collectionById` / `openById` lookups and label↔id mapping on the functional API.
  - New JPMS exports: `de.swiesend.secretservice.functional`, `functional.interfaces`, and `gnome.keyring.interfaces`.
- `Changed`:
  - Upgrade **dbus-java** from 4.x to **5.2.0**: construct `MethodCall` via the public `MessageFactory` (`connection.getMessageFactory().createMethodCall(...)`) — no reflection and no `--add-opens`. Migrate `ObjectPath` → `DBusPath` across the codebase, and normalize `ay` byte arrays (which 5.1.0+ may unmarshal as `byte[]` or `List<Byte>`) via `Static.Utils.toByteArray`.
  - Path-scoped signal registration (fixes `InvalidBusNameException`); suppress stack traces for known D-Bus error responses in `MessageHandler`; verify lock/unlock post-conditions by returning the actual daemon state.
  - Address the CVE-2018-19358 silent-read exposure: the functional API never returns `String` secrets, forces a user-permission prompt before unlocking (all collections, not just the default), and zeroes secret buffers after use.
  - Update dependencies: `hkdf` 2.0.0, `slf4j` 2.0.17, JUnit Jupiter 5.10.5.
- `Deprecated`:
  - `SimpleCollection` and its base interface are marked `@Deprecated(since = "3.0", forRemoval = true)`. They remain as a backward-compatible adapter that delegates to the functional API, scheduled for removal in 4.0.

## [2.0.1-alpha] - 2024-01-21

- `Fixed`:
  - Avoid `AddressResolvingException` at startup by catching `DBusExecutionException`s at static initialization [#47](https://github.com/swiesend/secret-service/issues/47).

## [2.0.0-alpha] - 2023-08-06

- `Added`
  - Introduce java modules `module-info.java`
- `Changed`
  - Update `hkdf` from `1.1.0` to `2.0.0`
  - Update `slf4j` from `2.0.6` to `2.0.7`
  - Update Maven dependencies

## [1.8.1-jdk17] - 2023-01-17

- `Fixed`:
  - Actually use `dbus-java-transport-native-unixsocket` instead of `dbus-java-transport-jnr-unixsocket`.
- `Changed`:
  - Update `slf4j-api` from `2.0.5` to `2.0.6`.
  - Update test and plugin libraries.

## [1.8.0-jdk17] - 2022-12-12

- `Changed`:
  - Make dbus service `org.gnome.keyring` an optional requirement. The `org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface` is not part of the original specification. In order to unlock the `SimpleCollection` with a primary password, the dbus service `org.gnome.keyring` needs to be present. There is the new static method `SimpleCollection.isGnomeKeyringAvailable()` in order to check the Gnome keyring availability separately.
  - Require **JDK 17** for `dbus-java` upgrade.
  - Update `dbus-java` from `3.3.0` to `4.2.1`. Using the new split library `dbus-java-core` together with `dbus-java-transport-native-unixsocket`.
  - Update `slf4j-api` from `1.7.30` to `2.0.4`.

## [1.7.0] - 2021-10-18

- `Fixed`
  - Fix [#30](https://github.com/swiesend/secret-service/issues/30) by removing the auto-close disconnect of `SimpleCollection` instances, which were introduced for [#26](https://github.com/swiesend/secret-service/issues/26). One has to call `SimpleCollection.disconnect()` manually in order to close the D-Bus connection or wait for the shutdown hook of `SimpleCollection`, which eventually will close the D-Bus connection. The shutdown hook is always set-up with the static lifetime of `SimpleCollection`.
  - Fix dead-lock of [cryptomator/integrations-linux#12]https://github.com/cryptomator/integrations-linux/issues/12 with the new `SimpleCollection.disconnect()` method. Waits only for 2 seconds to close the connection properly and logs otherwise.
- `Changed`
  - Removes the `ReentrantLock` from `SimpleCollection.disconnect` and changes the method signature to `synchronized`.
- `Added`
  - Add a regression test for [#30](https://github.com/swiesend/secret-service/issues/30) that checks if multiple instances of the `SimpleCollection` can be used one after the other.
  - Add `SimpleCollection.isConnected()` to the public interface as static method.
  - Add `SimpleCollection.disconnect()` to the public interface as static method.

## [1.6.2] - 2021-04-22

- `Fixed`
  - `Hotfix`: Check for all necessary services on the system:
    - `org.freedesktop.DBus`,
    - `org.freedesktop.secrets`,
    - `org.gnome.keyring`

## [1.6.1] - 2021-04-16

- `Fixed`
  - `Hotfix`: 'SimpleCollection()' is not public in 'org.freedesktop.secret.simple.SimpleCollection'. Could not be accessed from outside package.

## [1.6.0] - 2021-04-16

- `Fixed`
  - Fix [cryptomator/integrations-linux/issues/5](https://github.com/cryptomator/integrations-linux/issues/5) by using `dbus-java` `3.3.0`, which solves [dbus-java/issues/128](https://github.com/hypfvieh/dbus-java/issues/128).
  - Fix [#26](https://github.com/swiesend/secret-service/issues/26) by closing `DBusConnection` on the auto close of the `SimpleCollection`. The D-Bus connection closes now immediately on calling `SimpleCollection.close()` or at the end of the lifetime of the static scope from `SimpleCollection`.  
  - Handle `org.gnome.keyring.Error.Denied` as `info` log message (`MessageHandler`). E.g. if the password of a collection is wrong.
  - Handle `org.freedesktop.dbus.exceptions.NotConnected` as `debug` log message (`MessageHandler`).

## [1.5.0] - 2021-02-18

- `Fixed`
  - Fix the static `isAvailable()` method by also checking if the D-Bus service `org.freedesktop.DBus` is provided by the system and can open a session.
  - Handle `org.freedesktop.DBus.Error.ServiceUnknown` D-Bus errors.
- `Changed`
  - Change the low-level `TransportEncryption.openSession()` return type from `void` to `boolean`.
  - Handle `org.freedesktop.DBus.Error.*` as `debug` log message (`MessageHandler`).
  - Handle `org.freedesktop.Secret.Error.*` as `warn` or `info` log message (`MessageHandler`).

## [1.4.0] - 2021-01-19

- `Fixed`
  - Fix the static `isAvailable()` method by checking if the secret service is actually provided by the D-Bus and supports the expected transport encryption algorithm. 

## [1.3.1] - 2021-01-19

- `Changed`
  - Warn with a short message instead of logging the whole stack trace, when there is a problem with the D-Bus connection.
- `Fixed`
  - Fix a `NullPointerException` for the static `isAvailable()` method, when there is no D-Bus connection available. This happened, when [`dbus-java`](https://github.com/hypfvieh/dbus-java) raises a `RuntimeException: Cannot Resolve Session Bus Address` and the connection kept being uninitialized, which was not checked by the `isAvailable()` method. 

## [1.3.0] - 2021-01-05
- `Added`
  - Add `isLocked()` method to the `SimpleCollection` interface.
- `Fixed`
  - Fix [`#21`](https://github.com/swiesend/secret-service/issues/21), which lead to a race condition when closing the connection like 1/25 times.
    The problem was very kindly investigated by [@infeo](https://github.com/infeo) and fixed by [@hypfvieh](https://github.com/hypfvieh) in [`dbus-java`](https://github.com/hypfvieh/dbus-java/issues/123) in version [`3.2.4`](https://github.com/hypfvieh/dbus-java/tree/dbus-java-parent-3.2.4).
  - Fix problems of [integrations-linux/pull/1](https://github.com/cryptomator/integrations-linux/pull/1), thanks goes to [@purejava](https://github.com/purejava) for pointing out the issues:
    - Make main thread interruptible for better signal handling and ui integrations
    - Handle `org.freedesktop.DBus.Error.UnknownMethod` for better prompt handling and warn only.
    - Warn on `org.freedesktop.Secret.Error.NoSession`, `org.freedesktop.Secret.Error.NoSuchObject`, `org.freedesktop.Secret.Error.IsLocked` with a short message, instead of writing a whole stacktrace.
  - Fix a `ClassCastException` for locked keyrings for the SimpleCollection interface.
  - Fix problems of [integrations-linux/pull/4](https://github.com/cryptomator/integrations-linux/pull/4), thanks to [@Liboicl](https://github.com/Liboicl) for reporting and PRs:
    - Handle unexpected `RuntimeException` if no D-Bus session can be initiated.

## [1.2.3] - 2020-11-09

- `Added`
  - Add possible `RuntimeException`s: `AccessControlException`, `IllegalArgumentException` to the SimpleCollection example.
  - Add an interface `org.freedesktop.secret.simple.interfaces.SimpleCollection` for the high-level api. 
- `Fixed`
  - Overhaul of the disconnect logic for the signal handlers and the D-Bus connection.
    One has to disconnect the signal handlers manually using the low-level api.
    The new introduced changes should avoid race conditions during the `disconnect()` phase and thus hopefully:
    - Fix [`#20`](https://github.com/swiesend/secret-service/issues/20)

## [1.2.2] - 2020-11-06

- `Fixed`
  - [`#24`](https://github.com/swiesend/secret-service/issues/24) Provide better log messages and log root exceptions instead of causes only.
  - [`#25`](https://github.com/swiesend/secret-service/issues/25) Avoid possible `NullPointerException`s during logging of empty D-Bus responses. 

## [1.2.1] - 2020-10-17

- `Fixed`
  - `#23` Already created non default collections with a master password will use the master password to unlock the collection silently.
          Before the user was prompted for already created collections.

## [1.2.0] - 2020-09-17

- `Added`
  - add `SimpleCollection.isAvailable()`, which checks if `org.freedesktop.secrets` is provided as D-Bus service.
    - NOTE: might lead to a `RejectedExecutionException` or a `DBusExecutionException` in 1/25 cases on 
            `DBusConnection.disconnect()`, but should be handled all time.
      See:
      - https://github.com/swiesend/secret-service/issues/20
      - https://github.com/swiesend/secret-service/issues/21
- `Changed`
  - the `SimpleCollection` constructor checks the availability of the secret service by using `SimpleCollection.isAvailable()`.
  - ask only once for user permission per session. This avoids multiple unlock prompts right after another.
  - synchronize the access to the handled signals for `SignalHandler.handle()`.
- `Fix`
  - make `SimpleCollection.lock()` and `SimpleCollection.unlockWithUserPermission()` actually public, instead of protected.
  - do not exit early on unexpected signals for `SignalHandler.await()`.

## [1.1.0] - 2020-08-14

- `Added`
  - add `SimpleCollection.setTimeout()`. In order to set a timeout for awaiting prompts.
  - add `SimpleCollection.lock()`. In order to lock a given collection at any time.
- `Changed`
  - improve signal handling by closing open prompts automatically after the timeout.
  - change the default timeout from 300 to 120 seconds and make it configurable.
  - make `SimpleCollection.unlockWithUserPermission()` ~~public~~ protected.

## [1.0.1] - 2020-08-14

- `Changed`
  - update `dbus-java` to `3.2.3` to fix #13.

## [1.0.0] - 2020-05-07

- `Changed`
  - The signal handlers have now a default timeout of 300 seconds instead of 60.
  - The signal handling timeout can now be set in the low-level API.
  - Update dependencies up to the same patch level
    - Clarify ambiguous call `HKDF.fromHmacSha256().extract()` by explicit type casting.
- `Fixed`
  - `#4`, `#10`: Fix RejectedExecutionException by closing the session 
  - `#9`: Fix module problem for `org.freedesktop.dbus` which is also used by `dbus-java`
  - `#11`: Fix JDK8 support by using the `release` flag for the `maven-compiler-plugin`.

## [1.0.0-RC.3] - 2019-05-07

- `Changed`
  - update dependencies

## [1.0.0-RC.2] - 2019-03-19

- `Added`
  - add `slf4j-api` dependency
- `Fixed`
  - use `slf4j-simple` only in test scope 

## [1.0.0-RC.1] - 2019-03-12

- implement the [Secret Service API 0.2](https://specifications.freedesktop.org/secret-service/) 

[2.0.1-alpha]:  https://github.com/swiesend/secret-service/compare/v2.0.0-alpha...v2.0.1-alpha
[2.0.0-alpha]:  https://github.com/swiesend/secret-service/compare/v1.8.1-jdk17...v2.0.0-alpha
[1.8.1-jdk17]:  https://github.com/swiesend/secret-service/compare/v1.8.0-jdk17...v1.8.1-jdk17
[1.8.0-jdk17]:  https://github.com/swiesend/secret-service/compare/v1.7.0...v1.8.0-jdk17
[1.7.0]:  https://github.com/swiesend/secret-service/compare/v1.6.2...v1.7.0
[1.6.2]:  https://github.com/swiesend/secret-service/compare/v1.6.1...v1.6.2
[1.6.1]:  https://github.com/swiesend/secret-service/compare/v1.6.0...v1.6.1
[1.6.0]:  https://github.com/swiesend/secret-service/compare/v1.5.0...v1.6.0
[1.5.0]:  https://github.com/swiesend/secret-service/compare/v1.4.0...v1.5.0
[1.4.0]:  https://github.com/swiesend/secret-service/compare/v1.3.1...v1.4.0
[1.3.1]:  https://github.com/swiesend/secret-service/compare/v1.3.0...v1.3.1
[1.3.0]:  https://github.com/swiesend/secret-service/compare/v1.2.3...v1.3.0
[1.2.3]:  https://github.com/swiesend/secret-service/compare/v1.2.2...v1.2.3
[1.2.2]:  https://github.com/swiesend/secret-service/compare/v1.2.1...v1.2.2
[1.2.1]:  https://github.com/swiesend/secret-service/compare/v1.2.0...v1.2.1
[1.2.0]:  https://github.com/swiesend/secret-service/compare/v1.1.0...v1.2.0
[1.1.0]:  https://github.com/swiesend/secret-service/compare/v1.0.1...v1.1.0
[1.0.1]:  https://github.com/swiesend/secret-service/compare/v1.0.0...v1.0.1
[1.0.0]:  https://github.com/swiesend/secret-service/compare/v1.0.0-RC.3...v1.0.0
[1.0.0-RC.3]:  https://github.com/swiesend/secret-service/compare/v1.0.0-RC.2...v1.0.0-RC.3
[1.0.0-RC.2]:  https://github.com/swiesend/secret-service/compare/v1.0.0-RC.1...v1.0.0-RC.2
[1.0.0-RC.1]:  https://github.com/swiesend/secret-service/releases/tag/v1.0.0-RC.1

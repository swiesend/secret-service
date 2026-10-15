# Changelog

The [secret-service](https://github.com/swiesend/secret-service) library implements the [Secret Service API 0.2](https://specifications.freedesktop.org/secret-service/0.2/).

## Unreleased

Landed on `main` after the `v3.0.0-alpha` tag; not part of a published release.

- `Added`:
  - Standalone developer **GUI** extracted to a separate `tools/gui` module (not part of the library jar).
  - Provider-agnostic system tests: `ProviderSystemTest` (`@Tag("system-test")`, run via `-Psystem-test`) exercised in CI against gnome-keyring and KeePassXC, with a KWallet leg that does not run yet (see below); plus `ProviderDetectorTest` and `SecretCleanupTest`.
  - `CollectionLockLogicTest`: daemon-free unit tests covering the `lock()` decision helpers (`containsPath`, `requiresPrompt`, `awaitUntil`).
  - `Collection.lockedState()` on the low-level API: the `Locked` property, or empty when it could not be read. `isLocked()` answers `false` in that case, as if the collection were unlocked [#73](https://github.com/swiesend/secret-service/pull/73).
- `Changed`:
  - `Collection.lock()` is now response-aware: it branches on the Secret Service `Lock` response `(locked, prompt)`, returning promptly instead of waiting out the timeout when the collection cannot be locked (a lock requiring a prompt, or a non-lockable collection). `lock()` and collection creation also poll the expected state up to `Static.DBus.MAX_DELAY_MILLIS` instead of a single fixed `Thread.sleep(DEFAULT_DELAY_MILLIS)`, so under load `lock()` no longer spuriously returns `false` and a freshly created collection is no longer reported as "not created".
  - `CollectionTest.deleteWithALockedService` is `@Disabled`: `lockService()` locks the whole service including the user's login keyring (nothing re-unlocks it), popping an interactive unlock prompt during an otherwise headless run, and its gnome-keyring-specific setup cannot even open a session under `-Psystem-test` on KWallet/KeePassXC. `deleteALockedCollection` covers the locked-item case; remove `@Disabled` locally to run it against a throwaway gnome-keyring.
  - The published POM's `scm` links point to the `main` branch, over HTTPS. They pointed to the stale `master` branch, which holds 2.0.0-alpha, through the `git://` protocol that GitHub turned off in 2022, and the SSH address was malformed. The description names every provider, not only gnome-keyring.
  - `IntegrationTest`, which the README links as its example of transport encryption, no longer logs the decrypted secret at INFO or turns it into a `String`. It compares the chars and erases them.
  - **`ProviderSystemTest` uses only the collection `test`**, unless `-Dsecret-service.system-test.collection` names another. On KeePassXC and KWallet it fell back to the first collection it found, which on a developer's desktop is their real database or wallet, and its tests write and delete items there; KeePassXC moves deleted entries to the user's recycle bin. The CI legs name their containers' throwaway collections. The two `Example` classes, which an IDE runs although surefire does not, use the collection `test` with a password: `integration.Example` deleted "My Collection", the README's example label, and `functional.integration.Example` created "täst" without a password, which gnome-keyring does only through its dialog.
  - **The KWallet CI leg no longer passes with every test skipped.** Its image lacked the QCA OpenSSL plugin, so kwalletd5 refused the encrypted session (`createDLGroup failed`), the service counted as unavailable, and all tests skipped behind a green check. The image installs `libqca-qt5-2-plugins` now, and the entrypoint fails when KWallet exposes no collection, as the KeePassXC one does. It exposes none yet: headless, kwalletd5 creates no wallet, because opening one brings up a dialog nobody answers. The leg is non-blocking and now fails visibly instead.
  - Tests that could not fail assert what they are named for. `ItemTest.modified` read the creation time and compared an unsigned value with zero. Four `SecretServiceTest` methods were empty, and its close tests checked only that nothing threw. Calls that report failure by their result, `unlockWithMasterPassword` and `Session.close`, were wrapped in `assertDoesNotThrow`; `SimpleCollectionTest.close`, whose method catches everything, is gone, as `closeKeepsStaticConnection` covers it.
  - Every `@Disabled` test names its reason, as the agent instructions said they did: 14 had none. They need a user to answer a dialog, touch the user's own keyring, or depend on timing or on the rest of the run.
  - The README links the specification's "Transfer of Secrets" chapter at its current address, in version 0.2; the old address gave a 404.
  - The README's dependency snippet keeps `slf4j-api`. It excluded it for everyone, and a project that followed it without an `slf4j-api` of its own failed with `NoClassDefFoundError`. The exclusion is shown separately, for a project whose own `slf4j-api` conflicts.
  - The GUI's build instructions, in `tools/gui/pom.xml` and `SecretServiceGui`, skip the release signing with `-Dgpg.skip=true`, as the README's do. `mvn install` signs the artifacts, which fails without the maintainer's key.
  - `docs/vision.md`, the 2.x roadmap, says that its goals shipped, and gives the pull requests it listed as open, which were merged or closed, their real state. It still said there was no CI.
  - **The KWallet CI leg tests KWallet.** Its container starts kwalletd as pam_kwallet starts it at a Plasma login, with the hash of an empty login password: kwalletd creates its wallet and opens it, and later unlocks it without a dialog as well. The container opened the wallet over D-Bus, which brought up the "new wallet" dialog that nobody answered, so there was no collection and the leg failed. It needs no X server now.
  - A KWallet CI leg that fails keeps kwalletd's log. The container wrote it to `/tmp`, which dies with the container; it writes it under the mounted workspace now, as the KeePassXC container does, and the job's diagnostics artifact collects it.
  - The system tests run against KWallet 6 too. A second KWallet leg, `kwallet6`, runs KDE Frameworks 6.24's `ksecretd` on Ubuntu 26.04, as Kubuntu 26.04 ships it, beside KWallet 5 (KDE Frameworks 5.115) on Ubuntu 24.04.
  - The KWallet legs let the system tests lock their wallet, which unlocks again without a dialog: they pass `-Dsecret-service.system-test.lockable=true`. The other legs leave it unset; KeePassXC's database would need the user to unlock it, and the gnome-keyring collection is the tests' own.
  - The workflows pin each action to the commit of a release, run with a read-only token, and keep the token out of the checkout. A tag such as `actions/checkout@v4` can be moved to other code, and the tests that run after the checkout could read the token in `.git/config`. Taken from the CI of the Rust crate [secret-service-rs](https://github.com/open-source-cooperative/secret-service-rs), which pins its actions since [#111](https://github.com/open-source-cooperative/secret-service-rs/pull/111) and runs with a read-only token.
  - Dependabot keeps the pinned actions current: once a week, in one pull request, for releases at least seven days old. It proposes no Maven updates, as the library pins dbus-java at 5.2.0 on purpose; security advisories for the Maven dependencies come from Dependabot alerts, a setting of the repository. Taken from the Rust crate [secret-service-rs](https://github.com/open-source-cooperative/secret-service-rs), which keeps its actions current in the same way ([#106](https://github.com/open-source-cooperative/secret-service-rs/pull/106)).
  - A third workflow audits the workflows with [zizmor](https://github.com/zizmorcore/zizmor) whenever a push or a pull request changes `.github/`, and fails on any finding: an action on a tag that can be moved, a token with more rights than its job needs, a credential left in the checkout, an expression that a pull request controls inside a shell command. On the workflows before the pins above, it reports nine: five unpinned actions, two workflows without a permissions block, two checkouts that keep the token. Taken from the Rust crate [secret-service-rs](https://github.com/open-source-cooperative/secret-service-rs) ([#111](https://github.com/open-source-cooperative/secret-service-rs/pull/111)).
  - The regression suite runs on JDK 25 too, in a job of its own beside the JDK 17 one, against the same gnome-keyring. The library targets JDK 17, and applications run it on newer ones. The JDK 17 job keeps its name, `regression-tests`, which `main`'s ruleset requires.
  - A fourth workflow compares the library's public API with that of its last release, 3.0.0-alpha, with [japicmp](https://github.com/siom79/japicmp). It fails on a change that breaks a compiled application, binary incompatible, and lists one that breaks only its compilation, source incompatible, in the job summary. Locally: `mvn -Papi-check -DskipTests -Dgpg.skip=true verify`, with Maven 3.8.1 or later; the baseline is `core/pom.xml`'s `api-check.baseline`. Taken from the Rust crate [secret-service-rs](https://github.com/open-source-cooperative/secret-service-rs), which checks its API against its last release with cargo-semver-checks ([#107](https://github.com/open-source-cooperative/secret-service-rs/pull/107)).
  - The workflows run on pushes to `develop-3.x.x` too, the branch for fixes to 3.x once 4.0 is on `main`. They ran on `main` and `develop-2.x.x` only, so a fix pushed to a 3.x branch was tested only through its pull request.
  - **The system tests run against oo7**, GNOME's provider in Rust, which replaces gnome-keyring as the default from Fedora 45 on: a non-blocking leg in a Fedora 45 container with oo7 0.7.0 beta. Its daemon unlocks the login keyring with a password that it reads from stdin, and `.github/providers/oo7/prompter.py`, which serves oo7's CLI prompter, answers the password prompts of the unlocks that follow a lock, so the leg locks its collection too. The container needs `--cap-add IPC_LOCK`: oo7-daemon keeps that capability, to lock its memory, and exits where it cannot keep it.
  - **The system tests run against KeePassXC as it is set up by default**, where it asks the user before it gives a client access to an item. The KeePassXC leg runs with `ConfirmAccessItem=false`, the setting that hides those per-client locks; a second, non-blocking leg, `keepassxc-confirm`, turns it on and answers each Access Request dialog through xdotool, as a user who allows the request. It passes `-Dsecret-service.system-test.dialogs-answered=true`, for the system tests that need someone to answer a provider's dialog. The setting came to light through the Rust crate [secret-service-rs](https://github.com/open-source-cooperative/secret-service-rs), whose `unlock_all` exists for its dialogs ([#73](https://github.com/open-source-cooperative/secret-service-rs/pull/73)).
- `Fixed`:
  - **Per-item unlock.** A provider may lock items individually — the spec says a client "should act as if it must unlock each item individually", and KeePassXC does exactly that with its per-item access confirmation. The library only ever unlocked the *collection*, so reading a locked item failed. `getSecret`/`withSecret` now unlock the item first when the provider reports it locked, and return empty if the unlock is refused rather than falling through to a read that cannot succeed. Reported and first fixed by @SvenMarquardt5772 [#45](https://github.com/swiesend/secret-service/issues/45), [#46](https://github.com/swiesend/secret-service/pull/46).
    - The unlock is attempted **only when the collection is already unlocked**, which is the genuine per-item condition. gnome-keyring reports every item as locked while its collection is locked, so without that guard a failed collection unlock — a dismissed prompt, a wrong stored password, `disablePrompt()` — would raise a *second* prompt for the keyring the user just refused. Verified against a live daemon and covered by `aLockedCollectionDoesNotTriggerASecondUnlockOfTheItem`.
    - Costs one extra `Locked` property read per `getSecret`/`withSecret`: the item's own. A second read, of the collection's, happens only when the item reports locked — so on a provider that does not lock items individually the check ends after the first. `getSecrets`/`withSecrets` are unaffected: they iterate the whole collection and never attempt a per-item unlock, because one prompt per item is not a reasonable thing to do to a user.
    - `unlockItem` now checks the prompt result. It previously ignored dismissal and could throw a `NullPointerException` out of a `boolean` method when the prompt timed out.
    - Covered by `PerItemUnlockTest`, which drives a fake Secret Service that locks one item — no provider in CI reproduces the condition otherwise.
  - Tolerate gnome-keyring's asynchronously-injected `xdg:schema` attribute in the functional attribute tests: `createItemWithAttribute` compares by containment, and `getAttributes` compares only user-defined keys — the latter's strict assertion previously raced and flaked (~1 run in 10) [#69](https://github.com/swiesend/secret-service/pull/69).

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
  - **Breaking:** `SimpleCollection` throws `SecurityException` where 1.x and 2.x threw its subclass `AccessControlException`, which the JDK deprecates for removal. A `catch (AccessControlException e)` still compiles and no longer catches anything; catch `SecurityException`.
  - **Breaking:** `SimpleCollection.delete()`, `deleteItem()` and `deleteItems()` throw `SecurityException` when the deletion fails, also when the user dismisses the prompt. 1.x and 2.x threw only for a default collection or an unspecified item, and otherwise returned without a word.
  - `SimpleCollection.isAvailable()` and `AvailableServices` count a provider that D-Bus can start as available, not only a running one, and the check of `isAvailable()` starts it. An installed provider that was not running counted as unavailable before.
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

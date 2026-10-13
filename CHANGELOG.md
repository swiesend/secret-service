# Changelog

The [secret-service](https://github.com/swiesend/secret-service) library implements the [Secret Service API 0.2](https://specifications.freedesktop.org/secret-service/0.2/).

## Unreleased

Landed on `main` after the `v3.0.0-alpha` tag; not part of a published release.

- `Added`:
  - Standalone developer **GUI** extracted to a separate `tools/gui` module (not part of the library jar).
  - Provider-agnostic system tests: `ProviderSystemTest` (`@Tag("system-test")`, run via `-Psystem-test`) exercised in CI across gnome-keyring, KeePassXC, and KWallet; plus `ProviderDetectorTest` and `SecretCleanupTest`.
  - `CollectionLockLogicTest`: daemon-free unit tests covering the `lock()` decision helpers (`containsPath`, `requiresPrompt`, `awaitUntil`).
- `Changed`:
  - `Collection.lock()` is now response-aware: it branches on the Secret Service `Lock` response `(locked, prompt)`, returning promptly instead of waiting out the timeout when the collection cannot be locked (a lock requiring a prompt, or a non-lockable collection). `lock()` and collection creation also poll the expected state up to `Static.DBus.MAX_DELAY_MILLIS` instead of a single fixed `Thread.sleep(DEFAULT_DELAY_MILLIS)`, so under load `lock()` no longer spuriously returns `false` and a freshly created collection is no longer reported as "not created".
  - `CollectionTest.deleteWithALockedService` is `@Disabled`: `lockService()` locks the whole service including the user's login keyring (nothing re-unlocks it), popping an interactive unlock prompt during an otherwise headless run, and its gnome-keyring-specific setup cannot even open a session under `-Psystem-test` on KWallet/KeePassXC. `deleteALockedCollection` covers the locked-item case; remove `@Disabled` locally to run it against a throwaway gnome-keyring.
- `Fixed`:
  - **Per-item unlock.** A provider may lock items individually — the spec says a client "should act as if it must unlock each item individually", and KeePassXC does exactly that with its per-item access confirmation. The library only ever unlocked the *collection*, so reading a locked item failed. `getSecret`/`withSecret` now unlock the item first when the provider reports it locked, and return empty if the unlock is refused rather than falling through to a read that cannot succeed. Reported and first fixed by @SvenMarquardt5772 [#45](https://github.com/swiesend/secret-service/issues/45), [#46](https://github.com/swiesend/secret-service/pull/46).
    - The unlock is attempted **only when the collection is already unlocked**, which is the genuine per-item condition. gnome-keyring reports every item as locked while its collection is locked, so without that guard a failed collection unlock — a dismissed prompt, a wrong stored password, `disablePrompt()` — would raise a *second* prompt for the keyring the user just refused. Verified against a live daemon and covered by `aLockedCollectionDoesNotTriggerASecondUnlockOfTheItem`.
    - Costs one extra `Locked` property read per `getSecret`/`withSecret`: the item's own. A second read, of the collection's, happens only when the item reports locked — so on a provider that does not lock items individually the check ends after the first. `getSecrets`/`withSecrets` are unaffected: they iterate the whole collection and never attempt a per-item unlock, because one prompt per item is not a reasonable thing to do to a user.
    - `unlockItem` now checks the prompt result. It previously ignored dismissal and could throw a `NullPointerException` out of a `boolean` method when the prompt timed out.
    - Covered by `PerItemUnlockTest`, which drives a fake Secret Service that locks one item — no provider in CI reproduces the condition otherwise.
  - **`disablePrompt()` no longer stops locking, and a refused prompt is dismissed** ([#79](https://github.com/swiesend/secret-service/pull/79)). `lockItem()` returned `false` after `disablePrompt()` without asking the provider, although locking normally needs no prompt: gnome-keyring locks at once and answers with a `/` prompt path. Now only the branch that would show a dialog is suppressed. A prompt that the library refuses to show is dismissed instead of abandoned; before, the provider kept one Prompt object per call registered until the connection closed (`lockItem`, `deleteItem`, `delete`, collection creation and the unlock path).
  - The javadoc of `ProviderDetector` builds without an error. Its first heading was `<h3>`, where a class comment needs `<h2>`; `failOnError=false` had hidden the error.
  - **The library's copy of the transport session key is erased when the session closes.** `TransportEncryption.clear()` tried to destroy its keys, but the JDK's `SecretKeySpec` and DH private key cannot be destroyed, and the fallback zeroed copies: the AES session key stayed usable in memory until garbage collection. The key the library holds now lives in a type whose `destroy()` erases its bytes, and the library's copies of the DH shared secret and of both HKDF stages are zeroed as soon as the key exists. The copies that the JDK's cipher and the HKDF library make for one operation are out of the library's reach. `functional.Session.close()` erases the key too; it used to close only the D-Bus session. A cleared session refuses to encrypt or decrypt, also when it is cleared during an operation on another thread, which then fails instead of encrypting under a partly erased key. The DH private key cannot be erased by Java code, so its references are dropped.
  - `deleteItem` reports a deletion that the provider carried out without a prompt as done, on every provider. The provider then answers `"/"`, and the library accepted that answer only from gnome-keyring: on any other provider that gives it, `deleteItem` and `deleteItems` returned `false` although the items were gone. Nothing is deleted from a collection that stayed locked, though: KWallet answers `"/"` there too, and deletes nothing.
  - `ServiceTest.openSessionWithTransportEncryption` no longer fails about one run in 256. It required the provider's DH public value to be exactly 128 bytes, but a value whose top byte is zero arrives as 127.
  - Tolerate gnome-keyring's asynchronously-injected `xdg:schema` attribute in the functional attribute tests: `createItemWithAttribute` compares by containment, and `getAttributes` compares only user-defined keys — the latter's strict assertion previously raced and flaked (~1 run in 10) [#68](https://github.com/swiesend/secret-service/pull/68).
  - **`SimpleCollection.getItems` returns `null` again when no item matches**, as in 1.x and 2.x. Since 3.0.0-alpha it returned an empty list, and code that tests the result for `null` before it creates an item or reads `items.get(0)` failed with an `IndexOutOfBoundsException`. `deleteItems` with an empty list does nothing again; it threw a `SecurityException`.
  - **A collection opened with a password is no longer bound to a different collection.** When the password could not be used, `Collection.open(label, password)` and `Session.collection(label, password)` took the path of the newest `CollectionCreated` signal the service had seen, whichever collection that was. It could be an earlier collection of the same client or one that any other client on the bus created. That collection then received the new collection's items, and `delete()` deleted it. This happened on every provider other than gnome-keyring, which has no interface for the password, and on gnome-keyring when `CreateWithMasterPassword` failed or its reply timed out. Now the other providers create and unlock such a collection through their prompt, as 2.0.0-alpha did, and after a failed gnome-keyring call the collection is looked up by its label.
  - **`isGnomeKeyringAvailable()` is true only when gnome-keyring serves `org.freedesktop.secrets`.** It was true wherever gnome-keyring was installed, because the `org.gnome.keyring` name is activatable there, also on a desktop where KeePassXC or KWallet serves the secrets. The library then sent gnome-keyring's own calls to that provider: a collection opened with a password was never unlocked, and could not be created.
  - **On KeePassXC, `lock()` locks, and reading all secrets works.** KeePassXC answers `Lock` with a prompt and locks only once that prompt is called, which the library never did. So `lock()` never locked a KeePassXC collection, and `unlockWithUserPermission()`, which locks the collection before it unlocks it through the provider's dialog, always failed. `getSecrets()` and `withSecrets()` returned nothing, and `SimpleCollection.getSecrets()`, `deleteItems()` and `unlockWithUserPermission()` threw a `SecurityException`; 1.8.1 had ignored the failed lock. Now `lock()` carries out the prompt, for which KeePassXC shows no dialog, and after `disablePrompt()` it dismisses it. `unlockWithUserPermission()` locks and unlocks where the provider locks without a prompt, as gnome-keyring does. On KeePassXC it uses the collection as it is: the cycle would lock the database in KeePassXC's own window just to bring up its unlock dialog, and KeePassXC confirms access to its secrets itself.
  - **With prompting disabled, `unlockWithUserPermission()` no longer locks a collection it cannot unlock again.** It locked the collection and then had to dismiss the unlock dialog, so on gnome-keyring the collection stayed locked: for every application on the desktop, and for the login keyring all of them started to prompt. `getSecrets()`, `withSecrets()`, `deleteItem()` and `deleteItems()` call it, and a deletion that needs no dialog failed with it. Now it refuses without locking, unless a stored password can unlock the collection again. Reading all secrets is refused as before; a deletion goes ahead.
  - **`createItem` respects `disablePrompt()` and the configured timeout, and asks only once.** KeePassXC answers every `CreateItem` with a prompt. `createItem` called it even after `disablePrompt()`, and waited for it for the default 120 seconds instead of `getTimeout()`. When the user had just refused to unlock the collection, it went on to `CreateItem`, whose prompt asked to unlock it a second time. Now a collection that stays locked ends the call, and a prompt the caller opted out of is dismissed.

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
  - Address the CVE-2018-19358 silent-read exposure: the functional API never returns `String` secrets, makes the user confirm access before it reads all secrets or deletes items (`getSecrets`, `withSecrets`, `deleteItem(s)`, on all collections, not just the default; reading a single secret is not gated), and zeroes secret buffers after use.
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

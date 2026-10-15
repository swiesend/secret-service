# Changelog

The [secret-service](https://github.com/swiesend/secret-service) library implements the [Secret Service API 0.2](https://specifications.freedesktop.org/secret-service/0.2/).

## Unreleased

Landed on `main` after the `v3.0.0-alpha` tag; not part of a published release.

- `Added`:
  - Standalone developer **GUI** extracted to a separate `tools/gui` module (not part of the library jar).
  - Provider-agnostic system tests: `ProviderSystemTest` (`@Tag("system-test")`, run via `-Psystem-test`) exercised in CI across gnome-keyring, KeePassXC, and KWallet; plus `ProviderDetectorTest` and `SecretCleanupTest`.
  - `CollectionLockLogicTest`: daemon-free unit tests covering the `lock()` decision helpers (`containsPath`, `requiresPrompt`, `awaitUntil`).
  - `ProviderSystemTest` locks the collection and unlocks it again, and checks that an item of a collection that stays locked has no secret and keeps its secret when `updateItem` gives it a new one. It locks a collection that it did not create only with `-Dsecret-service.system-test.lockable=true`, which says that the collection unlocks again without a dialog.
- `Changed`:
  - `Collection.lock()` is now response-aware: it branches on the Secret Service `Lock` response `(locked, prompt)`, returning promptly instead of waiting out the timeout when the collection cannot be locked (a lock requiring a prompt, or a non-lockable collection). `lock()` and collection creation also poll the expected state up to `Static.DBus.MAX_DELAY_MILLIS` instead of a single fixed `Thread.sleep(DEFAULT_DELAY_MILLIS)`, so under load `lock()` no longer spuriously returns `false` and a freshly created collection is no longer reported as "not created".
  - `CollectionTest.deleteWithALockedService` is `@Disabled`: `lockService()` locks the whole service including the user's login keyring (nothing re-unlocks it), popping an interactive unlock prompt during an otherwise headless run, and its gnome-keyring-specific setup cannot even open a session under `-Psystem-test` on KWallet/KeePassXC. `deleteALockedCollection` covers the locked-item case; remove `@Disabled` locally to run it against a throwaway gnome-keyring.
  - The README names KeePassXC and KWallet as providers of the Secret Service API besides gnome-keyring; KWallet serves it since KDE Frameworks 5.97.0 (August 2022). Under "Related" it links Ralph Plawetzki's ([@purejava](https://github.com/purejava)) [secret-service](https://github.com/purejava/secret-service) library, from whose README the KWallet version comes, in place of his archived `kdewallet` library, which it succeeds.
  - A prompt is shown with an empty window id. The `window_id` of `Prompt` names the caller's window, over which the provider places its dialog: KeePassXC reads it as an X11 window, oo7 as `x11:` or `wayland:` and a handle. `Prompt.prompt(DBusPath)` sent the prompt's own id, the last segment of its path, which names no window; the library knows none of the caller's, and sends an empty id, as libsecret and the Rust crate [secret-service-rs](https://github.com/open-source-cooperative/secret-service-rs) do.
  - `openDefault()` and `defaultCollection()` log a warning when the provider names no default collection, which it says by answering `ReadAlias("default")` with `/`: on a fresh account where nothing has created the login keyring yet, on a phone or under WSL. Every later read or `createItem` in that collection failed, and nothing said why. Found through the issue tracker of the Rust crate [secret-service-rs](https://github.com/open-source-cooperative/secret-service-rs), where the unclear errors of a missing default collection come back again and again ([#8](https://github.com/open-source-cooperative/secret-service-rs/issues/8), [#29](https://github.com/open-source-cooperative/secret-service-rs/issues/29), [#69](https://github.com/open-source-cooperative/secret-service-rs/issues/69)).
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
  - **After the user refuses to unlock the collection, `search()` and `deleteItems()` stop asking.** `search()` by name or attribute asked once more for every item it read, through `getItemLabel()` and `getAttributes()`. `deleteItems()` asked once more for every item through `deleteItem()`. If nobody answered, each dialog waited for the timeout. Now each call asks once, and `deleteItems()` stops when the collection stayed locked, as `deleteItem()` does.
  - **Checking a secret for emptiness no longer copies it into a `String`.** `createItem`, `updateItem` and `SimpleCollection` checked the secret with `toString().trim()`. For a secret passed as a `CharSequence` that is not a `String`, for example a `CharBuffer` over a `char[]` that the caller erases afterwards, that made a copy nothing can erase. The check now reads the chars one by one; a blank secret still counts as empty.
  - **Encoding a secret leaves no unerased copy of it.** `Secret.toBytes`, which every encryption of a `char[]` or `CharSequence` goes through, used `Charset.encode`. That starts with a buffer of 1.1 bytes per char, and for a secret with enough non-ASCII chars it copies into a larger buffer and drops the first one without erasing it, so a partial copy of the secret stayed on the heap. The encoder now writes into one buffer sized for the worst case, which is erased afterwards. The README's example that hashes a secret uses `Secret.toBytes` for the same reason.
  - **Signal handlers are released when their owner closes.** `SecretService`, the functional `Collection` and `TransportEncryption` registered signal handlers on the connection and never released them. The connection mostly outlives them: `SimpleCollection`'s lasts as long as the JVM, and a session can open many collections. Each handler kept up to 1024 received signals and logged every Secret Service signal on the bus, and a `SimpleCollection` opened and closed per operation added 13 of them every time. A failed open now also closes the service and session it had opened, in `Collection.open` and `openById` and in the `SimpleCollection` constructors, and `TransportEncryption()` closes the connection it opened itself.
  - **Without a usable session bus, the functional API reports the service as unavailable instead of throwing.** Over ssh, from cron or in a container there is often no session bus address to resolve, and dbus-java then throws the unchecked `AddressResolvingException`; for a malformed address, `InvalidBusAddressException`. `System.connect()` caught only `DBusException`, so `SecretService.create()`, `Collection.openDefault()` and `Collection.open()` threw where they promise an empty `Optional`. A `ListNames` call that fails, which dbus-java also reports unchecked, now makes `SimpleCollection.isAvailable()` and `isGnomeKeyringAvailable()` return `false`, as documented. A malformed address no longer breaks the loading of `SimpleCollection` for the rest of the JVM's life.
  - **Closing a `System` twice no longer disconnects other users of the connection.** Every `System.connect()` in the JVM gets dbus-java's shared connection, which counts its holders and disconnects when the last one lets go. `close()` gave up a share on every call, so a second call gave up another holder's. That happened easily: `SecretService.close()` closes the system it was created with, and a try-with-resources over both closed it again. `close()` now acts once. The javadoc of `SecretService.create(Optional)` says that the service takes the system over.
  - **The low-level `Service.getSecrets()` returns `Secret` values, and `openSession()` a `byte[]` output.** dbus-java decodes the reply without type information: each secret struct as an `Object[]`, and a byte array possibly as `List<Byte>`. The declared types only cast the reply, so the first read of a value threw a `ClassCastException`. Both now convert the reply, as `Item.getSecret()` already did; a plain session's output stays the empty string it is.
  - **A D-Bus call that gets no reply in time is logged.** `MessageHandler` waits two seconds for a reply. When none came, the call returned empty without a word, so a slow provider looked like a refusing one, although it can still carry the call out after the wait. It now logs a warning that names the call.
  - The javadoc of `SimpleCollection` shows migration examples that compile and close what they open. The full example put the `Optional` from `System.connect()` into a try-with-resources, and the simple one never closed its collection, which leaks the connection the collection opened. It also says that the class goes in 4.0, not 3.0, and that `clear()` clears the collection's passphrase; the transport keys are erased on `close()`.
  - `SimpleCollection.disconnect()` keeps the thread's interrupt flag when it is interrupted while it waits for the connection to close. It dropped the flag, so the caller, often a shutdown in progress, did not learn of the interruption.
  - Javadoc that contradicted the code. `Service.changeLock` and `InternalUnsupportedGuiltRiddenInterface.changeWithPrompt` "toggled the lock" and returned the collection's path; both open gnome-keyring's change-password dialog, and return the prompt that shows it. `SimpleCollection.isAvailable()` listed `org.gnome.keyring` as required, which it does not check for. `Secret` linked a page of the specification that no longer exists.
  - **The module exports `handlers` and `simple.interfaces`.** The low-level `Service`, `Session`, `Collection`, `Item` and `Prompt` extend `handlers.Messaging`, whose `getSignalHandler()` and `getMessageHandler()` return handler types, and `SimpleCollection` extends `simple.interfaces.SimpleCollection`. On the module path, an application could call those methods but not use what they returned, nor name the supertype. On the class path nothing changes.
  - `search()` returns an unmodifiable list for an empty query too, as its javadoc promises. The empty query matches every item, and that list could be changed by the caller.
  - `updateItem` reports a refused label or attribute change. It returned whether the secret was set and ignored the other two, so a caller could not tell that the provider had kept the old label.
  - **`updateItem` without a new secret changes the label and the attributes again**, as in 1.x and 2.x: a `null` password keeps the secret, as a `null` label or attributes map keeps those. Since 3.0.0-alpha it refused the whole call, and `SimpleCollection.updateItem`, which reports nothing, silently left the item unchanged. An empty password is still refused.
  - **The default collection is recognised on every provider.** It is the collection that the provider's `default` alias points to; the library knew only gnome-keyring's ids for it, `login` and `session`. So `delete()` deleted KWallet's default wallet, or the database KeePassXC names as its default, where it refuses to delete gnome-keyring's. `openDefault()` opens the collection the alias points to rather than the alias, so `getId()` names that collection instead of answering `default`.
  - `SimpleCollection.delete()` says why it did not delete. It reported every failure as "Default collections may not be deleted", also a dismissed prompt for any other collection. The new `CollectionInterface.isDefault()` tells the two apart: it answers whether `delete()` refuses the collection as a default one. **Breaking** for another implementation of `CollectionInterface`, which must add the method.
  - The low-level `Prompt.await` answers `null` for the path "/", which names no prompt. It returned the newest `Completed` signal its handler had seen, the result of another prompt, perhaps another application's: a caller that reads a result that is not dismissed as the user's consent got the consent of someone else's dialog. The functional API never awaits "/".
  - **A prompt's result is taken only from a signal that arrives while the library waits for it.** `SignalHandler.await` searched its whole history, up to 1024 signals, once any new one arrived. An older `Completed` signal for the same prompt path, as a provider that restarted reuses its paths, could stand in for the answer: a refusal for a consent, or the reverse. `createItem`'s wait for the `ItemCreated` signal could likewise return an item created earlier.
  - **A prompt that the library stops waiting for is dismissed, and only that prompt.** An interrupted wait left its dialog open, with nobody to collect the answer, and with two threads waiting through one `Prompt`, a timed-out wait dismissed the prompt the other thread had shown last. `Prompt.dismiss(DBusPath)` dismisses a given prompt; `prompt(DBusPath)` addresses the given path rather than the object's last one.
  - **A secret whose content type names a charset the JVM does not know is read.** The application that stored it chooses the content type. `getSecret`, `withSecret` and `getSecrets` threw `UnsupportedCharsetException` or `IllegalCharsetNameException` for such a secret, and under a Turkish default locale for `charset=iso-8859-1` too, as the name was upper-cased in the default locale.
  - **A secret is decoded in the charset that its content type names**, and in UTF-8, the specification's default, where it names none or one the JVM does not know. It was always decoded as UTF-8, so a secret that another application had stored as ISO-8859-1 came back with replacement characters for its non-ASCII ones. The decoding uses one buffer, erased afterwards, as the encoding does.
  - **Reading a secret that throws reports no secret.** An unexpected exception while one secret was read, an `IllegalArgumentException` from a content type as the one above, escaped `getSecret` and `withSecret`, where the functional API reports a failure as an empty result. From `getSecrets` and `withSecrets` it also dropped the secrets decrypted until then, unerased; the item is left out now, as one that cannot be read.
  - **No code in the JVM can change the transport encryption's Diffie-Hellman group.** The key exchange read it from `Static.RFC_2409.SecondOakleyGroup.PRIME` and `GENERATOR`, public arrays that any code could change, weakening every session opened afterwards. It uses a private copy now; the public arrays remain, as copies whose change has no effect.
  - `Static.Utils.isNullOrEmpty(byte[])` is true for an empty array. It tested the array's `toString()`, `[B@...`, which is never empty. `TransportEncryption`'s guard that called it checks for `null` now, so an empty secret is still encrypted, as in every release.
  - **A closed session or collection is let go.** `SecretService` kept every session it had opened until it closed itself, and a `Session` every collection opened through it, also after their owner had closed them. A long-lived service that opens a session per operation grew without bound. Each now removes itself when it closes.
  - **No secret is read from a locked item.** The specification says that the secrets of locked items cannot be accessed, and gnome-keyring and KeePassXC refuse such a read, but KWallet answers it with an empty secret ([KDE bug 524650](https://bugs.kde.org/show_bug.cgi?id=524650)). After an unlock that the user refused, `getSecret` returned that empty secret as the item's, `withSecret` passed it to the callback, and `SimpleCollection.getSecret` returned an empty password instead of `null`; 1.x read the item in the same way. A locked item now has no secret, and `getSecrets` and `withSecrets` leave it out; they read each item's `Locked` property first. On gnome-keyring and KeePassXC the results are the same as before, without the read that fails. Found and reported by Ralph Plawetzki ([@purejava](https://github.com/purejava)), whose [secret-service](https://github.com/purejava/secret-service) library works around it as well.
  - **Opening a session on KWallet no longer fails about once in 512.** The library sent its Diffie-Hellman public key as `BigInteger.toByteArray()` gives it, as short as the value allows, and KWallet refuses a key of fewer than 128 bytes: a session whose key had its top 9 bits clear failed with "Client public key size is invalid". The key is padded with zero bytes to the prime's 128 bytes, which leaves it the same unsigned integer, as the specification transfers it; gnome-keyring accepted the shorter key. A key whose top bit is set keeps its sign byte, as before, because KWallet reads the key as a signed number.
  - **Storing or reading a secret on KWallet no longer fails in about one session in 256.** Both sides of a session derive its AES key from the Diffie-Hellman shared secret, and when the secret's top byte was zero, they derived two different keys: gnome-keyring and KeePassXC hash all of the secret's 128 bytes, as the library and libsecret do, but KWallet hashes it without its leading zero bytes. In such a session, KWallet refused every secret with "Can't find session", and the library could not decrypt the secrets that KWallet sent, or, rarely, decrypted them to something else. The library now replaces such a session with a new one before it uses it, on every provider: none tells how it hashes.
  - **`updateItem` no longer reports a new secret for a locked item as set.** The specification says that locked items cannot be modified. gnome-keyring refuses such a secret, but KWallet reports it set and throws it away: after an unlock that the user refused, `updateItem` returned `true`, and the item kept its old secret. A new secret is not sent to a locked item now, and `updateItem` returns `false`.
  - **A secret is stored as `text/plain`, the content type under which libsecret reads a password.** The library stored a secret, always in UTF-8, as `text/plain; charset=utf-8`. oo7 0.6 refuses that content type, and libsecret's password functions read a password only under `text/plain`: from KWallet, which hands back the content type it was given, an application that looks a password up through libsecret read none from an item that the library had stored, and nor did `secret-tool` before libsecret 0.21.8. gnome-keyring and KeePassXC hand back `text/plain` either way. `Secret.createContentType(UTF_8)` and a `Secret` made without a content type give `text/plain` now; another charset is still named, as in `text/plain; charset=iso-8859-1`. Reading does not change: `text/plain` and `text/plain; charset=utf-8` are both read as UTF-8. The issue trackers of the Rust crates showed the way: a secret stored on KWallet under `text/plain; charset=utf8` came back as an empty password ([secret-service-rs #104](https://github.com/open-source-cooperative/secret-service-rs/issues/104)), and KeePassXC saves a password sent as `application/octet-stream` as an attachment ([zbus-secret-service-keyring-store #25](https://github.com/open-source-cooperative/zbus-secret-service-keyring-store/issues/25)), so the library does not send that.
  - **An item without attributes is created with an empty map of them.** `createItem(label, secret)`, and `SimpleCollection.createItem` without attributes, sent `CreateItem` without an `Attributes` property. oo7, Fedora 45's provider, takes every item to have attributes: without the property its `CreateItem` fails and sends no answer, so the library waited out its two-second reply timeout and created nothing. `Item.createProperties(label, null)` gives an empty map of attributes now, which gnome-keyring, KeePassXC and KWallet take as none.
  - **`updateItem` unlocks a locked item first, and changes nothing of an item that stays locked.** The specification says that locked items cannot be modified, and providers differ in what they take from one. KeePassXC keeps an item locked for a client until the user confirms that client's access, which it asks by default, and takes a new label and attributes for such an item but refuses its secret: `updateItem` changed the label, kept the old secret and returned `false`. KWallet keeps a new label for an item of a closed wallet. `updateItem` now unlocks a locked item as `getSecret` does, which brings up KeePassXC's dialog, and leaves an item that stays locked as it is. On gnome-keyring, which locks collections only, an update does what it did. On KeePassXC, a new label for an item whose access this client has not been granted asks the user now.
  - **`getSecrets` and `withSecrets` read the items that KeePassXC keeps locked, after one dialog.** KeePassXC keeps an item locked for a client until the user confirms that client's access, which it asks by default. The bulk readers skipped every locked item, so a client that the user had not allowed yet read no secret at all, and nothing asked. They now unlock the locked items with one `Unlock` call, for which KeePassXC shows one dialog, and read the items that the user allowed. The prompt is carried out whenever the provider gives one, also when some items came back unlocked at once; an item that stays locked is still left out, and with prompting disabled nothing is asked. On gnome-keyring and KWallet, which lock no single item, a bulk read does what it did. Taken from the Rust crate [secret-service-rs](https://github.com/open-source-cooperative/secret-service-rs), whose `unlock_all` unlocks several items through one KeePassXC dialog ([#73](https://github.com/open-source-cooperative/secret-service-rs/pull/73)); it carries out the prompt only when no item came back unlocked, which the library does not copy.

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

# Why a call failed

The functional API answers `Optional.empty()` or `false` when a call fails, and logs why. Code that acts on the answer needs the reason itself, to decide whether to fall back to another store, try again, ask the user, or create what is missing. A `Failure` carries that reason, and a `Result` holds either a value or the `Failure` that says why there is none.

## Reasons

| Reason | Means | A caller can |
|---|---|---|
| `NO_PROVIDER` | There is no session bus, or nothing on it provides `org.freedesktop.secrets`. | Fall back to another store, or ask the user to start a keyring: gnome-keyring, KeePassXC, KWallet or oo7. |
| `NO_DEFAULT_COLLECTION` | The provider names no default collection: its alias `default` points to none, as on an account where nothing has created the login keyring yet. | Open a collection by its label, or set the provider's default. |
| `DISCONNECTED` | The connection closed, or the provider quit or forgot the session, before it answered. | Create a new service. |
| `TIMED_OUT` | No reply came within the reply timeout, or no answer to a prompt within its timeout. | Try again, or wait longer: `setReplyTimeout`, `setTimeout`. |
| `NOT_FOUND` | The item or the collection does not exist. | Create it. |
| `LOCKED` | It stays locked: prompting is disabled, or the provider kept it locked. | Enable prompting and try again. |
| `DISMISSED` | The user dismissed the provider's dialog. | Not ask again at once. |
| `DENIED` | Access was refused, by the consent policy or by the provider. | Tell the user. |
| `INVALID_ARGUMENT` | The library refused the call before it sent anything: an empty path, say. | Fix the call. |
| `OTHER` | An error that says nothing more, or an answer the library cannot use. | Report it, with the error name and the cause. |

A later release may add reasons, so a `switch` over them needs a `default` branch.

## Methods

| Method | Answers with | In place of |
|---|---|---|
| `SecretService.createChecked()`, `createChecked(system)` | the service; `NO_PROVIDER`, or the failure of the session that the availability check opens | `create()`, `create(system)` |
| `CollectionInterface.withSecretChecked(path, callback)` | the callback's result; `INVALID_ARGUMENT`, `DENIED`, `LOCKED`, `DISMISSED`, `TIMED_OUT`, `NOT_FOUND`, or the failure of the read | `withSecret(path, callback)` |
| `SessionInterface.defaultCollectionChecked()`, `Collection.openDefaultChecked(session)` | the default collection; `NO_DEFAULT_COLLECTION`, or the failure of reading the alias | `defaultCollection()`, `openDefault(session)`, which answer a collection on the alias's path, where every read fails |

On the low-level API: `System.connectChecked()`, `ServiceInterface.isAvailableChecked(system, available)`, `Service.openSessionChecked(algorithm, input)`, `Service.unlockChecked(objects)`, `Service.readAliasChecked(name)`, `TransportEncryption.InitializedSession.openSessionChecked()` and `Item.getSecretChecked(session)`.

`withSecretChecked` and `defaultCollectionChecked` have a default body, for another implementation of their interface: it answers `OTHER` for every failure of the plain method, as it cannot say why.

## `Result` and `Failure`

A `Result` holds a value or a `Failure`: `isOk()`, `value()` and `failure()` say which.

```java
import de.swiesend.secretservice.Failure;
import de.swiesend.secretservice.Result;

Result<ServiceInterface> created = SecretService.createChecked();
if (created.isOk()) {
    try (ServiceInterface service = created.value().orElseThrow()) {
        // ...
    }
} else {
    Failure failure = created.failure().orElseThrow();
    switch (failure.reason()) {
        case NO_PROVIDER -> useAnotherStore();
        case TIMED_OUT, DISCONNECTED -> tryAgainLater();
        default -> log.warn("No Secret Service: {}", failure);
    }
}
```

`value()` answers what the plain method answers: empty for a failure, and also for a success without a value. `reason()` is a shortcut for the failure's reason. `map` and `flatMap` pass a failure on unchanged. A `Result` prints whether the call succeeded and its failure, never its value, which can be a secret.

A `Failure` is a record of four parts:

- `reason()`, one of the reasons above.
- `message()`, the library's own description. It holds no label and no secret.
- `errorName()`, the name of the D-Bus error that the provider or the bus answered with, or null.
- `cause()`, the exception that ended the call, or null. For a call without a reply within the reply timeout, it is a `java.util.concurrent.TimeoutException`.

The text of a D-Bus error is written by the provider. It is logged where the error arrives, and the `Failure` does not keep it.

## From a D-Bus reply

On the low-level API, `MessageHandler.sendChecked` and `getPropertyChecked` answer with a `MessageHandler.Reply`. `Failure.from(reply, message)` gives the failure that a reply without a value stands for, as the functional API reports it.

| The reply | Reason |
|---|---|
| `org.freedesktop.Secret.Error.NoSuchObject`, `org.freedesktop.DBus.Error.UnknownObject` (`org.freedesktop.dbus.errors.UnknownObject` from a peer on dbus-java), and gnome-keyring's `UnknownMethod` for any call to a path that does not exist (the outcome `ABSENT`) | `NOT_FOUND` |
| `org.freedesktop.Secret.Error.IsLocked` | `LOCKED` |
| `org.gnome.keyring.Error.Denied`, `org.freedesktop.DBus.Error.AccessDenied` | `DENIED` |
| `org.freedesktop.DBus.Error.ServiceUnknown`, `org.freedesktop.DBus.Error.NameHasNoOwner`, and the bus's `org.freedesktop.DBus.Error.Spawn.*` for a provider that a service file names but that did not start | `NO_PROVIDER` |
| `org.freedesktop.DBus.Local.Disconnected`, `org.freedesktop.DBus.Error.Disconnected`, `org.freedesktop.Secret.Error.NoSession`, and `java.io.IOException`, the error that dbus-java answers a call with when its connection closes; dbus-java's `NotConnected` and `FatalDBusException` | `DISCONNECTED` |
| The bus's `org.freedesktop.DBus.Error.NoReply` | `DISCONNECTED` when its text says that the provider disconnected, otherwise `TIMED_OUT` |
| No reply within the reply timeout; `org.freedesktop.DBus.Error.Timeout`, `org.freedesktop.DBus.Error.TimedOut` | `TIMED_OUT` |
| Any other error, or an exception of another kind | `OTHER` |

## Design

- **Additive.** The `Optional` and `boolean` methods stay. They answer what they answered and log what they logged. A method that reports a `Failure` gets a counterpart named `...Checked`, and the plain method delegates to it, so the two cannot drift apart.
- **A `...Checked` counterpart where the failure decides what a caller does next.** A caller needs to tell a missing provider from a slow one, and a locked item from one that is gone. A call whose failures all lead to the same next step keeps only its plain form.
- **No exceptions.** The functional API throws none for a failed call. An exception that a caller forgets to catch ends a thread, where a forgotten `Optional` ends a branch.
- **No last-error accessor.** It would answer for whichever call ran last, on any thread.
- **The failure keeps the D-Bus error name and the exception that ended the call.** The Rust crate [secret-service-rs](https://github.com/open-source-cooperative/secret-service-rs) reports a missing provider as a bare `Unavailable`, and its [issue 95](https://github.com/open-source-cooperative/secret-service-rs/issues/95) asks to keep the error behind it.
- **The reasons are what a caller can act on.** They are not the D-Bus error names. Providers raise different errors for the same condition, and the mapping above is where those differences end.

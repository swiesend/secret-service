# Changelog

The secret-service library implements the [Secret Service API 0.2](https://specifications.freedesktop.org/secret-service/0.2/).

## Unreleased

## [1.6.1] - 2021-04-16

- `Fixed`
  - Fix 'SimpleCollection()' is not public in 'org.freedesktop.secret.simple.SimpleCollection'. Could not be accessed from outside package.

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

# Changelog

The secret-service library implements the [Secret Service API 0.2](https://specifications.freedesktop.org/secret-service/0.2/).

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

[1.2.1]:  https://github.com/swiesend/secret-service/compare/v1.2.0...v1.2.1
[1.2.0]:  https://github.com/swiesend/secret-service/compare/v1.1.0...v1.2.0
[1.1.0]:  https://github.com/swiesend/secret-service/compare/v1.0.1...v1.1.0
[1.0.1]:  https://github.com/swiesend/secret-service/compare/v1.0.0...v1.0.1
[1.0.0]:  https://github.com/swiesend/secret-service/compare/v1.0.0-RC.3...v1.0.0
[1.0.0-RC.3]:  https://github.com/swiesend/secret-service/compare/v1.0.0-RC.2...v1.0.0-RC.3
[1.0.0-RC.2]:  https://github.com/swiesend/secret-service/compare/v1.0.0-RC.1...v1.0.0-RC.2
[1.0.0-RC.1]:  https://github.com/swiesend/secret-service/releases/tag/v1.0.0-RC.1

# Changelog

The secret-service library implements the [Secret Service API 0.2](https://specifications.freedesktop.org/secret-service/0.2/).


## [1.2.0] - 2020-09-06

- `Added`
  - add `SimpleCollection.isAvailable()`, which checks if `org.freedesktop.secrets` is provided as D-Bus service.
- `Changed`
  - The `SimpleCollection` constructor checks the availability of the secret service by asking for the 
    mere availability of the service rather than actually unlocking it.
- `Fix`
  - actually make `SimpleCollection.lock()` and `SimpleCollection.unlockWithUserPermission()` public, 
    instead of protected.

## [1.1.0] - 2020-08-14

- `Added`
  - add `SimpleCollection.setTimeout()`.
  - add `SimpleCollection.lock()`.
- `Changed`
  - improve signal handling by closing open prompts automatically after the timeout.
  - change the default timeout from 300 to 120 seconds and make it configurable.
  - makes `SimpleCollection.unlockWithUserPermission()` public. 

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

[1.0.0]:  https://github.com/swiesend/secret-service/compare/v1.0.0-RC.3...v1.0.0
[1.0.0-RC.3]:  https://github.com/swiesend/secret-service/compare/v1.0.0-RC.2...v1.0.0-RC.3
[1.0.0-RC.2]:  https://github.com/swiesend/secret-service/compare/v1.0.0-RC.1...v1.0.0-RC.2
[1.0.0-RC.1]:  https://github.com/swiesend/secret-service/releases/tag/v1.0.0-RC.1

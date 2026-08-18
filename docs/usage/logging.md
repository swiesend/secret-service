# Logging

The library logs through SLF4J and brings no backend of its own, so levels, formats, appenders and
per-logger filtering are entirely yours. One thing your backend cannot decide after the fact is
whether a value was put into a message in the first place — that is what this page is about.

## What is never logged

Secrets, peppers, derived keys and envelope plaintext are not logged at any level, and there is no
setting that enables them. If you ever see one in your logs, that is a bug worth reporting.

## Item labels and collection names

**Off by default.** A label is the one part of an item a person writes themselves, and it usually
describes the secret it guards — `Bank — savings login`, `prod DB root`, `ex-employer VPN`. Logs
travel further than keyrings do: journald, a CI job's output, a support bundle attached to a ticket.
So the library keeps labels out of messages and logs the item's D-Bus object path instead:

```
WARN  Prompt was dismissed or timed out for item /org/freedesktop/secrets/collection/login/42.
```

The path identifies the item to an operator and resolves back to it, without naming what it is.
Where no path exists yet — an item whose creation failed — the message reads `<label hidden>`.

### Turning labels on

While reproducing a problem, any one of these:

```sh
# system property
java -Dde.swiesend.secretservice.log.labels=true -jar yourapp.jar

# environment variable — for containers and systemd units
SECRET_SERVICE_LOG_LABELS=true ./yourapp
```

```java
// or at runtime, to wrap a narrow window without a restart
LogPolicy.setLabelsLogged(true);
try {
    // ... reproduce the problem here ...
} finally {
    LogPolicy.setLabelsLogged(false);
}
```

`setLabelsLogged` overrides the property and the variable; `LogPolicy.resetToConfiguredSetting()`
discards the override and re-reads them. The switch is consulted each time a message is emitted, so
it takes effect immediately and costs nothing while labels are off — a suppressed label is never
assembled.

**Leave it off in steady state.** Turning it on is a debugging step, not a configuration default.

## Choosing what you see

Logger names are the fully-qualified class names, so an SLF4J backend can address any part of the
library. With Logback, for example:

```xml
<!-- quieten the library, keep your own app at INFO -->
<logger name="de.swiesend.secretservice" level="WARN"/>

<!-- ...but trace a keyring problem in detail -->
<logger name="de.swiesend.secretservice.hardened.EpochKeystore" level="DEBUG"/>
```

Two messages are worth knowing about because they are deliberately loud:

| Message | Logger | Why |
|---|---|---|
| `same-UID exposure accepted` | `…hardened.HardenedCollection` | You passed `acknowledgeSameUidExposure(true)`; the warning states what that gives up. Silence it with `suppressSameUidExposureWarning(true)` on the builder, or with an SLF4J filter — the two are equivalent. |
| `no GenerationAnchor configured` | `…hardened.HardenedCollection` | `rotateEpoch()` destroys keys, and without an anchor that destruction can be rolled back. See [Anti-rollback anchor](../architecture/anti-rollback-anchor.md). |

Prefer silencing a specific logger over raising the level of the whole library: the messages this
layer emits at `WARN` mostly report that it **failed closed**, which is the class of event you want
to keep hearing about.

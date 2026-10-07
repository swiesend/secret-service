# secret-service

A **Java client library for the [freedesktop.org Secret Service API 0.2](https://specifications.freedesktop.org/secret-service/0.2/)** — store and retrieve secrets in a keyring over D-Bus, compatible with gnome-keyring, KeePassXC, and KWallet. The functional equivalent of the [`libsecret`](https://wiki.gnome.org/Projects/Libsecret) C client library, MIT-licensed.

Since `3.0.0-alpha` the project ships **three artifacts, released in lockstep**:

| Artifact | Adds |
|---|---|
| `de.swiesend:secret-service` | The classical Secret Service client + transport encryption — **most consumers need only this** |
| `de.swiesend:secret-service-hardened` | Opt-in application-layer AES-256-GCM envelopes with a pluggable key-material SPI and hybrid X25519 + ML-KEM-768 |
| `de.swiesend:secret-service-hardened-tpm2` | TPM 2.0-sealed pepper and NV-counter anti-rollback anchor |

```java
try (ServiceInterface service = SecretService.create().orElseThrow()) {
    CollectionInterface collection = service.openSession()
            .flatMap(session -> session.collection("My Collection", Optional.empty()))
            .orElseThrow();

    String item = collection.createItem("My Item", "secret").orElseThrow();

    // The char[] is zeroed automatically after the callback returns.
    collection.withSecret(item, secret -> Arrays.equals(secret, "secret".toCharArray()));
}
```

## Where to go

- **[Getting started](getting-started.md)** — Maven coordinates, JDK requirements, first secret.
- **[Usage guides](usage/core.md)** — worked examples for [core](usage/core.md), [hardened](usage/hardened.md), and [TPM 2.0](usage/tpm2.md).
- **[Security & deployment guide](security/index.md)** — the threat model, what each layer actually defends against, and copy-paste deployment recipes. Start with [Do I need this?](security/index.md#do-i-need-this)
- **[Architecture](architecture/index.md)** — diagrams of the envelope encryption, hybrid KEM, epoch keystore, and anti-rollback anchor, each mapped to the tests that prove it.
- **[Roadmap](roadmap.md)** and **[Changelog](changelog.md)**.
- **[Security audits](audits/index.md)** — dated, immutable review records.

## Honest scope, up front

The Secret Service API [was never designed with a secure retrieval mechanism](security/threat-catalogue.md) — any process running as your user can read an unlocked keyring (CVE-2018-19358; a Linux desktop design issue, not a bug in one daemon). This library gives you transport encryption by default, and the optional hardened layer makes the *stored bytes* ciphertext — but **no in-process encryption can defend against a same-UID attacker**. The [security guide](security/index.md) is explicit about which threat classes each mechanism does and does not cover.

## Related

- [`kdewallet`](https://github.com/purejava/kdewallet) — KDE client library by [@purejava](https://github.com/purejava)
- Source, issues, and releases: [github.com/swiesend/secret-service](https://github.com/swiesend/secret-service)

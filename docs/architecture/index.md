# Hardened architecture — diagrams

Visual documentation of how the **`secret-service-hardened`** application-layer encryption works, and — via the test suite — evidence that each mechanism behaves correctly.

Every diagram maps to real code and to the tests that pin the behaviour. "Correctness (proven by)" lists the JUnit methods that would fail if the property broke; run them with:

```bash
mvn test -pl hardened -am            # crypto + keystore + anchor (daemon-free)
mvn test -pl hardened-tpm2 -am -Psystem-test   # TPM paths (needs a TPM/simulator)
```

## Index

| Doc | Mechanism | Key property shown |
|-----|-----------|--------------------|
| [envelope-encryption.md](envelope-encryption.md) | Per-item AEAD envelope (AES-256-GCM or ChaCha20-Poly1305), HKDF-derived DEK | Round-trips; fails closed on wrong key material or tampering |
| [hybrid-kem.md](hybrid-kem.md) | X25519 (+ optional ML-KEM-768) KEM | Encapsulate/decapsulate agree; hybrid is honest |
| [epoch-keystore-and-forward-secrecy.md](epoch-keystore-and-forward-secrecy.md) | Per-epoch keypairs, create-then-delete persistence, `rotateEpoch` | No data loss on crash; destroyed epochs are unreadable |
| [anti-rollback-anchor.md](anti-rollback-anchor.md) | `GenerationAnchor` + TPM NV monotonic counter | A rolled-back keystore is refused (fail-closed) |
| [key-material-providers.md](key-material-providers.md) | Provider SPI, Argon2 stretching, TPM sealing | Pepper never at rest in cleartext; wrong password fails |

## Component overview

```mermaid
flowchart TB
    app["Application"]
    subgraph hardened["secret-service-hardened (opt-in)"]
        hc["HardenedCollection<br/>(decorator)"]
        kem["HybridKem<br/>X25519 (+ ML-KEM-768)"]
        eks["EpochKeystore<br/>per-epoch keypairs"]
        kmp["KeyMaterialProvider (SPI)<br/>pepper"]
        anchor["GenerationAnchor (SPI)<br/>anti-rollback floor"]
    end
    subgraph tpm2["secret-service-hardened-tpm2 (optional)"]
        tprov["Tpm2KeyMaterialProvider<br/>TPM-sealed pepper"]
        tanchor["Tpm2GenerationAnchor<br/>NV monotonic counter"]
    end
    subgraph core["secret-service (core)"]
        ci["CollectionInterface"]
    end
    daemon["Secret Service daemon<br/>(gnome-keyring / KeePassXC / KWallet)"]

    app -->|"createItem / withSecret"| hc
    hc -->|"derive DEK, seal/open"| kem
    hc -->|"epoch keypairs"| eks
    hc -->|"getPepper"| kmp
    eks -->|"generation floor"| anchor
    kmp -.implemented by.-> tprov
    anchor -.implemented by.-> tanchor
    hc -->|"stores base64 envelope as the secret body"| ci
    eks -->|"stores encrypted keystore item"| ci
    ci --> daemon
```

The daemon only ever sees a base64 **envelope** (ciphertext + metadata), never the plaintext. The pepper — the root of the wrapping keys — lives only in the `KeyMaterialProvider` (an env var, a mode-0600 file, or TPM-sealed), never in the daemon.

## Threat-class mapping

See the [threat catalogue](../security/threat-catalogue.md) for the full catalogue.

```mermaid
flowchart LR
    A["Class A<br/>same-UID live process"]:::no
    B["Class B<br/>cross-UID on host"]:::yes
    C["Class C<br/>offline disk / backup"]:::yes
    D["Class D<br/>harvest-now-decrypt-later"]:::yes

    A -->|"NOT defended by the wrapper<br/>(needs OS isolation)"| osiso["MAC / systemd / namespaces"]
    B -->|"envelope opacity"| env["AEAD body encryption<br/>(AES-256-GCM / ChaCha20-Poly1305)"]
    C -->|"pepper not on disk (or TPM-sealed)<br/>+ envelope opacity"| pep["KeyMaterialProvider / TPM"]
    D -->|"enablePostQuantum(true)<br/>+ rotateEpoch() forward secrecy"| pq["HybridKem + EpochKeystore"]

    classDef yes fill:#173,stroke:#2b6,color:#efe;
    classDef no fill:#611,stroke:#b33,color:#fee;
```

# Key material providers

The **pepper** is the root of every wrapping key. A `KeyMaterialProvider` supplies it and honestly declares its `ThreatCoverage`. Providers **compose** as decorators, so you stack a source with optional stretching. The pepper is handed out as a fresh `char[]` the caller zeroes; providers holding state scrub themselves on `close()`.

Source: `KeyMaterialProvider` (SPI) and `providers/*`; `Tpm2KeyMaterialProvider`, `Tpm2Provisioner`, `Tpm2SealedBlob` (tpm2).

## Provider composition

```mermaid
flowchart LR
    subgraph sources["Pepper sources"]
      env["EnvVarKeyMaterialProvider<br/>(CI/dev only — same-UID = NONE, loud warning)"]:::weak
      file["FileKeyMaterialProvider<br/>(mode-0600 file)"]
      tpm["Tpm2KeyMaterialProvider<br/>(TPM-sealed; same-UID = PARTIAL)"]:::strong
    end
    subgraph decorators["Optional decorators"]
      argon["Argon2KeyMaterialProvider<br/>Argon2id stretch (EMBEDDED/INTERACTIVE/SENSITIVE)"]
    end
    hc["HardenedCollection"]

    env --> argon
    file --> argon
    argon --> hc
    tpm --> hc
    classDef weak fill:#611,stroke:#b33,color:#fee;
    classDef strong fill:#173,stroke:#2b6,color:#efe;
```

The builder **refuses** a provider whose `ThreatCoverage` rates same-UID as `NONE` (e.g. `EnvVarKeyMaterialProvider`) unless the caller explicitly calls `acknowledgeSameUidExposure(true)` — so a weak dev provider can never be shipped to production silently.

## TPM sealing — provision once, unseal at runtime

```mermaid
sequenceDiagram
    autonumber
    participant Op as Operator (Tpm2Provisioner CLI)
    participant TPM as TPM 2.0
    participant Disk as pepper.tpm2blob (mode 0600)
    participant App as Tpm2KeyMaterialProvider (runtime)
    participant HC as HardenedCollection

    Note over Op,Disk: provisioning (one-shot)
    Op->>TPM: CreatePrimary (SRK) under owner hierarchy
    Op->>TPM: Create sealed keyed-hash object<br/>(authValue = password, sensitive = pepper, DA lockout on)
    TPM-->>Op: outPublic, outPrivate
    Op->>Disk: write Tpm2SealedBlob (atomic, mode 0600)
    Note over Op: zero pepper + password buffers

    Note over App,HC: runtime
    App->>Disk: readFrom (refuses group/other-readable file)
    App->>TPM: CreatePrimary (same SRK), then Load(outPublic, outPrivate)
    App->>TPM: Unseal (handle.authValue = password)
    alt correct password
        TPM-->>App: pepper bytes → cached as char[]
        App-->>HC: getPepper() returns a clone
    else wrong password (repeatedly)
        TPM-->>App: auth failure → TPM DA lockout rate-limits brute force
    end
```

At rest the disk holds only TPM-wrapped material — no plaintext pepper, no env var. Recovering it needs *both* the specific TPM and the policy secret (password). See [anti-rollback-anchor.md](anti-rollback-anchor.md) for the sibling `Tpm2GenerationAnchor` NV counter.

## Correctness (proven by)

Core providers (daemon-free):

| Property | Test |
|----------|------|
| The builder refuses a same-UID=`NONE` provider without acknowledgement | `HardenedCollectionTest.refusesWeakProviderWithoutAcknowledgement`, `builderRequiresKeyMaterialAtCompileTime` |
| `close()` propagates to the provider only when owned (`ownsProvider` / `ownsInner`) | `HardenedCollectionTest.ownershipFlagsOptBackIntoClosing` |
| Argon2id stretching is wired and profiled | `Argon2KeyMaterialProviderTest.*` |
| Health check flags a weak provider and round-trips a canary | `HardenedHealthCheckTest.healthCheckFlagsWeakProviderAsWarn`, `healthCheckRoundTripsACanary` |

TPM (tpm2 module; blob tests run anywhere, unseal is simulator-gated):

| Property | Test |
|----------|------|
| Seal → unseal round-trips the pepper via the (simulated) TPM | `Tpm2KeyMaterialProviderTest.sealUnsealRoundTripViaSimulator` |
| A wrong password fails to unseal | `Tpm2KeyMaterialProviderTest.wrongPasswordFailsToUnseal` |
| The sealed-blob file is mode-0600 and rejects over-permissive files | `Tpm2SealedBlobTest.fileRoundTripSetsMode0600`, `readFromRejectsOverPermissiveFile` |
| The blob format round-trips and rejects bad magic / unknown policy | `Tpm2SealedBlobTest.binaryRoundTripPreservesAllFields`, `rejectsBadMagic`, `rejectsUnknownPolicyKind` |
| The provisioner CLI refuses unsafe argument combinations | `Tpm2ProvisionerArgsTest.*` (e.g. `parseRejectsBothPasswordAndPepperOnStdin`) |
| `Tpm2Availability.isAvailable()` reflects TSS.Java on the classpath without forcing init | `Tpm2AvailabilityTest.isAvailableReflectsTssJavaOnTheClasspath` |

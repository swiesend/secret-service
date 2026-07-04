# Envelope encryption (write / read)

Each secret body is sealed in an **AES-256-GCM envelope** under a per-item data-encryption key (DEK). The DEK is derived fresh per item with HKDF-SHA256 from: the application **pepper**, an optional **TOTP code**, a per-item random **salt**, the **epoch id**, the **item id**, and the **KEM shared secret**. No key is stored; the DEK is recomputed on read from the same inputs.

Source: `HardenedCollection.createItem` / `decryptToChars` / `deriveDek`, `Envelope`.

## Wire format (the item body, base64-encoded)

```mermaid
flowchart LR
    subgraph env["Envelope bytes (then base64 → item secret body)"]
      direction LR
      magic["magic<br/>'SSv1' (4)"] --> ver["version<br/>(1)"] --> flags["flags<br/>(1)"] --> kid["kem_id<br/>(1)"] --> salt["salt<br/>(16)"] --> epoch["epoch_len(1)+epoch_id"] --> kemct["kem_ct_len(2)+kem_ct<br/>(0 iff kem_id=NONE)"] --> nonce["nonce<br/>(12)"] --> ct["aead_ct<br/>(GCM tag included)"]
    end
```

Alongside the body, non-secret attributes travel as item metadata: `hardened.version`, `hardened.epoch`, `hardened.totp.mode` (+ `hardened.totp.step` for `STORED_STEP`), `hardened.kem`, `hardened.kem.id`, `hardened.item.id`. The `kem_id == NONE  ⇔  kem_ct is empty` invariant is enforced by the `Envelope` constructor.

## Write — `createItem`

```mermaid
sequenceDiagram
    autonumber
    participant App
    participant HC as HardenedCollection
    participant KMP as KeyMaterialProvider
    participant KEM as HybridKem + EpochKeystore
    participant Col as CollectionInterface (daemon)

    App->>HC: createItem(label, secret, attrs)
    HC->>KMP: getPepper() / getTotpSeed()
    Note over HC: totpStep captured once (STORED_STEP write race fix)
    HC->>KEM: encapsulateForWrite(epochId)
    KEM-->>HC: (kem_ct, kem_shared_secret)
    Note over HC: DEK = HKDF-SHA256(<br/>salt=pepper-salt, ikm=pepper,<br/>info = TAG || totpCode || epoch || itemId || kemSecret)
    HC->>HC: aead_ct = AES-256-GCM(DEK, nonce, plaintext,<br/>AAD = salt||epoch||itemId)
    HC->>HC: envelope = magic|ver|flags|kem_id|salt|epoch|kem_ct|nonce|aead_ct
    HC->>HC: zero pepper, totpCode, DEK, plaintext, kemSecret
    HC->>Col: createItem(label, base64(envelope), hardened.* attrs)
    Col-->>HC: item path
    HC-->>App: Optional<path>   (Optional.empty on any crypto/keystore failure)
```

The whole sealing body runs in one `try/finally` so **every** key buffer is zeroed even on an exception path, and the method returns `Optional.empty()` rather than throwing on a KEM/AES failure (fail-safe contract).

## Read — `getSecret` / `withSecret`

```mermaid
sequenceDiagram
    autonumber
    participant App
    participant HC as HardenedCollection
    participant Col as CollectionInterface (daemon)
    participant KMP as KeyMaterialProvider
    participant KEM as HybridKem + EpochKeystore

    App->>HC: withSecret(path, callback)
    HC->>Col: withSecret(path) → base64 body
    HC->>HC: env = Envelope.fromBytes(base64-decode)
    alt not a hardened item (no SSv1 magic / hardened.version)
        HC-->>App: Optional.empty()  (refuses foreign/plaintext items)
    end
    HC->>KEM: decapsulateForRead(env)  (epoch private key)
    KEM-->>HC: kem_shared_secret  (or fail-closed if epoch destroyed)
    HC->>KMP: getPepper()
    loop for each TOTP candidate
        HC->>HC: DEK = HKDF(...), then plaintext = AES-256-GCM-open(DEK, nonce, aead_ct, AAD)
        alt GCM tag verifies
            HC->>App: callback(char[] plaintext)
            HC->>HC: zero plaintext + all key buffers (finally)
        else tag fails
            HC->>HC: try next candidate
        end
    end
    Note over HC: no candidate verified → Optional.empty() (fail closed)
```

The plaintext is handed to the callback as a `char[]` and zeroed in a `finally` block; the library never returns a `String` and never leaves plaintext on the heap past the callback.

## Correctness (proven by)

| Property | Test |
|----------|------|
| Write then read returns the exact plaintext | `HardenedCollectionTest.createAndReadRoundTrip`, `postQuantumRoundTripWritesKemCtAndRecoversPlaintext` |
| The stored body is a `SSv1` envelope, not plaintext | `emittedSecretIsBase64EnvelopeNotPlaintext` |
| Default (non-PQ) write uses the classical X25519 KEM, non-empty `kem_ct` | `defaultBuilderWritesKemIdX25519` |
| Wrong pepper cannot decrypt (fail closed) | `wrongPepperFailsClosed` |
| Tampered / non-base64 body yields empty, not a crash | `matchesSecretEmptyForTamperedEnvelope`, `withSecretsFailsFastOnAnyItemFailure` |
| Foreign / plaintext items in a shared collection are refused | `refusesPlaintextItemInSharedCollection`, `withSecretsScopesToHardenedItemsOnly` |
| Envelope round-trips every field; rejects bad magic/version/lengths | `EnvelopeTest.roundTripPreservesAllFields_*`, `magicIsRequired`, `rejectsUnsupportedVersion`, `rejectsTruncatedInput`, `rejectsInvalidSaltLengthField`, `rejectsTooShortAeadCiphertext` |
| `kem_id`/`kem_ct` consistency invariant holds | `EnvelopeTest.kemIdAndKemCtMustBeConsistent` |
| Reads survive a step rollover during write | `storedStepSurvivesStepRolloverDuringWrite` |
| `matchesSecret` is constant-time and plaintext-free | `matchesSecretReturnsTrueForEquality`, `...FalseForMismatch`, `constantTimeEqualsIsLengthIndependentOfFirstMismatchIndex` |

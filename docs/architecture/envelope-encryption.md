# Envelope encryption (write / read)

Each secret body is sealed in an **AEAD envelope** (AES-256-GCM by default, or ChaCha20-Poly1305) under a per-item data-encryption key (DEK). The DEK is derived fresh per item with HKDF-SHA256: the secret inputs — the application **pepper** and the **KEM shared secret** — form the HKDF input keying material mixed with a per-item random **salt**; the public context (a domain tag, the **epoch id**, the **item id**) is the HKDF info. No key is stored; the DEK is recomputed on read from the same inputs.

Source: `HardenedCollection.createItem` / `decryptToChars` / `deriveDek`, `Envelope`.

## Wire format (the item body, base64-encoded)

```mermaid
flowchart LR
    subgraph env["Envelope bytes (then base64 → item secret body)"]
      direction LR
      magic["magic<br/>'SSv1' (4)"] --> ver["version<br/>3 (1)"] --> flags["flags<br/>(1)"] --> aid["aead_id<br/>(1)"] --> kdid["kdf_id<br/>(1)"] --> kid["kem_id<br/>(1)"] --> salt["salt<br/>(16)"] --> epoch["epoch_len(1)+epoch_id"] --> item["item_id_len(1)+item_id"] --> kemct["kem_ct_len(2)+kem_ct<br/>(0 iff kem_id=NONE)"] --> nonce["nonce<br/>(12)"] --> ct["aead_ct<br/>(AEAD tag included)"]
    end
```

The 4-byte `magic` is the fixed family tag `SSv1` (unchanged across revisions); the authoritative format version is the separate 1-byte `version` field, currently **3**. Parsing rejects v1 and v2 (`fromBytes` accepts only v3). The `aead_id` / `kdf_id` / `kem_id` selector bytes name the cipher suite so a new AEAD, KDF, or KEM lands without a format migration.

Alongside the body, non-secret **index metadata** travels as item attributes: `hardened.version`, `hardened.epoch`, `hardened.aead`, `hardened.kdf`, `hardened.kem`, `hardened.kem.id`, `hardened.item.id`. These are non-authoritative — the item id and cipher suite are read from the authenticated envelope header, never from the attributes. The `kem_id == NONE  ⇔  kem_ct is empty` invariant is enforced by the `Envelope` constructor.

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
    HC->>KMP: getPepper()
    HC->>KEM: encapsulateForWrite(epochId)
    KEM-->>HC: (kem_ct, kem_shared_secret)
    Note over HC: DEK = HKDF-SHA256(<br/>salt=per-item salt, ikm=pepper || kemSecret,<br/>info = TAG || epoch || itemId)
    HC->>HC: aead_ct = AEAD(DEK, nonce, plaintext,<br/>AAD = full envelope header)
    HC->>HC: envelope = magic|ver|flags|aead_id|kdf_id|kem_id|salt|epoch|item_id|kem_ct|nonce|aead_ct
    HC->>HC: zero pepper, DEK, plaintext, kemSecret
    HC->>Col: createItem(label, base64(envelope), hardened.* attrs)
    Col-->>HC: item path
    HC-->>App: Optional<path>   (Optional.empty on any crypto/keystore failure)
```

The whole sealing body runs in one `try/finally` so **every** key buffer is zeroed even on an exception path, and the method returns `Optional.empty()` rather than throwing on a KEM/AEAD failure (fail-safe contract). The AEAD is selectable via `Builder.aead(AeadId)` (AES-256-GCM default, or ChaCha20-Poly1305) and recorded in the authenticated `aead_id` byte.

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
    HC->>HC: DEK = HKDF(...), then plaintext = AEAD-open by env.aead_id (DEK, nonce, aead_ct, AAD = full header)
    alt tag verifies
        HC->>App: callback(char[] plaintext)
        HC->>HC: zero plaintext + all key buffers (finally)
    else tag fails / unsupported suite
        HC-->>App: Optional.empty() (fail closed)
    end
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
| Tampering any header byte fails AEAD authentication (full-header AAD) | `tamperingWithEnvelopeHeaderFailsAuthentication` |
| ChaCha20-Poly1305 items round-trip and stamp `aead_id` | `chaCha20Poly1305RoundTrips`, `AeadTest.*` |
| Envelope parser survives arbitrary/adversarial input (fuzzed) | `EnvelopeFuzzTest.fromBytesOnlyThrowsIllegalArgument` |
| `matchesSecret` is constant-time and plaintext-free | `matchesSecretReturnsTrueForEquality`, `...FalseForMismatch`, `constantTimeEqualsIsLengthIndependentOfFirstMismatchIndex` |

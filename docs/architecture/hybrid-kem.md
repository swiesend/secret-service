# Hybrid KEM (X25519 + optional ML-KEM-768)

The KEM binds each item's DEK to a **per-epoch keypair** held in the `EpochKeystore`, so destroying the epoch key (via `rotateEpoch`) makes prior envelopes undecryptable — the forward-secrecy primitive. The KEM is **always on**: classical X25519 by default (`kem_id = 0x03`), or hybrid X25519 + ML-KEM-768 (`kem_id = 0x01`) when `enablePostQuantum(true)` and the runtime provides ML-KEM.

Source: `HybridKem`, `KemId`, `Envelope`.

## `kem_id` values

```mermaid
flowchart LR
    none["0x00 NONE<br/>no KEM (legacy alpha, read-only)"]:::legacy
    x["0x03 X25519<br/>classical, default"]:::live
    hyb["0x01 X25519_MLKEM768<br/>hybrid PQ"]:::live
    hqc["0x02 X25519_HQC192<br/>reserved, not implemented"]:::resv
    classDef live fill:#173,stroke:#2b6,color:#efe;
    classDef legacy fill:#444,stroke:#888,color:#ddd;
    classDef resv fill:#553,stroke:#aa6,color:#ffd;
```

`KemId` (an enum, not bare bytes) is the single source of truth for the id, its label, and whether it `carriesPqCiphertext()` — so the write flag and the read "is hybrid?" decision can never disagree.

## Encapsulate (write side)

```mermaid
sequenceDiagram
    autonumber
    participant HC as HardenedCollection
    participant KEM as HybridKem
    participant EKS as EpochKeystore

    HC->>EKS: getOrCreate(epochId) → epoch keypair(s)
    HC->>KEM: encapsulate(epoch.X25519_pub, epoch.MLKEM_pub?)
    KEM->>KEM: generate ephemeral X25519 keypair
    KEM->>KEM: ss_x25519 = ECDH(eph_priv, epoch_X25519_pub)
    opt PQ enabled and epoch has ML-KEM pub
        KEM->>KEM: (ss_pq, pq_ct) = ML-KEM-768.encapsulate(epoch_MLKEM_pub)
    end
    KEM->>KEM: shared = HKDF(ss_x25519 || ss_pq, "secret-service/hybrid-kem/v1", 32)
    KEM->>KEM: kem_ct = uint16(eph_spki_len) || eph_spki || pq_ct
    KEM-->>HC: Encapsulation(shared, kem_ct)
    Note over HC: shared secret is mixed into the item DEK (HKDF info).<br/>kem_ct is stored in the envelope
```

## Decapsulate (read side)

```mermaid
sequenceDiagram
    autonumber
    participant HC as HardenedCollection
    participant EKS as EpochKeystore
    participant KEM as HybridKem

    HC->>EKS: get(env.epoch) → epoch private key(s)
    alt epoch missing (rotated & destroyed, or wrong pepper)
        EKS-->>HC: empty → IllegalState → read returns Optional.empty() (fail closed)
    end
    HC->>KEM: decapsulate(epoch_X25519_priv, epoch_MLKEM_priv?, kem_ct, envIsHybrid)
    KEM->>KEM: split kem_ct → eph_X25519_spki, pq_ct
    KEM->>KEM: ss_x25519 = ECDH(epoch_X25519_priv, eph_pub)
    opt envIsHybrid (kem_id carriesPqCiphertext)
        KEM->>KEM: ss_pq = ML-KEM-768.decapsulate(epoch_MLKEM_priv, pq_ct)
    end
    KEM->>KEM: shared = HKDF(ss_x25519 || ss_pq, same tag, 32)
    KEM-->>HC: shared  (identical to the write-side value)
```

`envIsHybrid` is derived from `KemId.fromId(env.kemId()).carriesPqCiphertext()`. A hybrid-flagged envelope whose `kem_ct` has no PQ part is **rejected** rather than silently downgraded.

## Correctness (proven by)

| Property | Test |
|----------|------|
| Classical encapsulate/decapsulate agree on the shared secret | `HybridKemTest.classicalEncapDecapRoundTrip` |
| Hybrid encapsulate/decapsulate agree (when ML-KEM available) | `HybridKemTest.hybridEncapDecapRoundTrip_whenPqAvailable` |
| `postQuantumAvailable()` and the `kem_id`/label are honest | `HybridKemTest.postQuantumFlagIsHonest`, `disabledPqAlwaysReportsClassicalOnly` |
| Hybrid-flagged but PQ-less ciphertext is rejected, not downgraded | `HybridKemTest.hybridDecapFailsIfFlaggedHybridButCiphertextHasNoPqPart` |
| `kem_ct` carries a length-prefixed X25519 SPKI | `HybridKemTest.packedKemCiphertextHasLengthPrefix` |
| Full PQ write→read round-trip recovers the plaintext | `HardenedCollectionTest.postQuantumRoundTripWritesKemCtAndRecoversPlaintext` |
| Legacy `kem_id = NONE` envelopes still read (routed to the pepper-only path) | `HardenedCollectionTest.legacyKemIdNoneEnvelopeIsToleratedNotRejectedByKeystore` |
| All reserved `kem_id` bytes round-trip through the envelope | `EnvelopeTest.kemIdRoundTripsAllReservedValues`, `kemIdLabelIsSensible` |

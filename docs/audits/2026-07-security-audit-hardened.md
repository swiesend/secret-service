# Security Audit — `secret-service-hardened` (and `-hardened-tpm2`)

- **Scope:** the application-layer encryption layer — `hardened/` and `hardened-tpm2/` modules.
- **Version audited:** `3.0.0-alpha` (commit `613d8b4`).
- **Date:** 2026-07-04.
- **Method:** source read of the crypto core (`Envelope`, `HardenedCollection`, `HybridKem`,
  `EpochKeystore`) plus the key-material providers, TOTP, the anti-rollback anchor, and the
  documented threat model. Findings are cross-referenced to `file:line`.
- **Nature:** static review only. No code was modified. No dynamic/fuzz testing, no formal proof,
  no side-channel measurement was performed.

This audit answers two questions: **(1) does the layer deliver the mechanisms it promises, and
(2) is the underlying premise — application-layer encryption on top of the OS keyring — the correct
one?**

---

## 1. Executive summary

**Delivery: mostly yes, within an honestly-scoped set of promises.** The documentation is the
strongest part of the project. It rates the env-var provider as "theater," places the headline
attacker (same-UID, CVE-2018-19358) **out of scope**, and admits forward secrecy is "theoretical"
if backups are retained. The code matches those scoped claims. The remaining gaps are (a) a few
crypto-hygiene deviations that are sound-but-non-idiomatic, and (b) several headline features that
are **off or worthless in the default configuration** and only become real with the TPM module plus
OS-level controls the library cannot enforce.

**Premise: partially correct, and structurally limited.** The premise is sound as *defense-in-depth
for offline/backup-theft (class C) and harvest-now-decrypt-later (class D)* attackers. But it is
**structurally incapable of solving the same-UID threat the README leads with**, and it says so.
Nearly all the genuinely novel security value is concentrated in the TPM path. For the default
providers on a single-tenant desktop — the common case — the layer is closer to a complexity tax
than the feature list implies, which the project's own "do I need this?" tree concedes.

### Severity legend

| Severity | Meaning |
|---|---|
| **High** | Confidentiality/integrity break, or a headline promise not delivered as a reasonable reader would understand it. |
| **Medium** | Real weakness that materially narrows a claim or degrades robustness; exploit requires specific conditions. |
| **Low** | Hygiene / hardening / documentation-precision issue; no direct compromise. |
| **Info** | Design observation or positive finding; no action strictly required. |

### Findings at a glance

| # | Severity | Finding |
|---|---|---|
| F-1 | Medium | Anti-rollback is silently **off** by default; a `null` anchor lets a keyring-writer resurrect destroyed epochs and undo forward secrecy. |
| F-2 | Medium | Forward secrecy is undone by retained backups (old keystore = all live epoch keys, under a pepper-only KEK). |
| F-3 | Medium | AEAD authenticates only `(salt, epoch, itemId)`; envelope header, and the `itemId`/`totp.mode` used on read, come from **unauthenticated** D-Bus attributes. |
| F-4 | Low | DEK KDF places the KEM/TOTP secrets in HKDF-Expand `info`, not the IKM — sound but non-idiomatic reduction. |
| F-5 | Low | `STORED_STEP` TOTP is self-defeating (labeled "theater" in code); `LIVE_CODE` is a liveness window, not a possession factor. |
| F-6 | Low | Provider self-reports outrun enforcement (non-POSIX FS skips 0600 check but still claims `crossUid=REAL`); several providers never scrub on `close()`. |
| F-7 | Low | `HardenedHealthCheck` reports "HEALTHY" with `sameUid=NONE`, attach mechanism on, and heap dumps enabled (those are WARN, not FAIL). |
| P-1 | High (premise) | Root of trust is the pepper; the layer cannot defend class A (same-UID) in-process — the threat the README motivates with. |
| P-2 | Medium (premise) | Real, delivered value is concentrated in `hardened-tpm2` + a deployment posture the library can only recommend. |
| G-1..G-6 | Info (positive) | AEAD usage, hybrid combiner, FS mechanism, fail-safe/zeroing hygiene, honest self-assessment. |

---

## 2. Architecture recap (as built)

On write (`HardenedCollection.createItem`, `HardenedCollection.java:212-294`):

1. `pepper = provider.getPepper()` — root key material (see §4 for where it lives).
2. Encapsulate against the current per-epoch keypair held by `EpochKeystore`: classical X25519
   always, plus ML-KEM-768 when PQ is enabled (`encapsulateForWrite`, line 793). Yields
   `kemSecret` + `kemCiphertext`.
3. `dek = HKDF-SHA256(salt, pepper, info = tag‖totp‖epoch‖itemId‖kemSecret)` (`deriveDek`, line 846).
4. `aeadCt = AES-256-GCM(dek, nonce, plaintext, aad = salt‖epoch‖itemId)` (`aeadEncrypt`, line 886).
5. Serialize a versioned `Envelope` (`Envelope.java`), base64, hand to the wrapped
   `CollectionInterface` as if it were the plaintext. Transport encryption (core) then wraps it.

On read the DEK is recomputed from the same factors; the KEM ciphertext is decapsulated with the
stored epoch private key; plaintext is delivered to a `withSecret(char[])` callback and zeroed in
`finally`.

**The single governing fact:** every derived secret roots in the **pepper**. DEKs derive from it;
the epoch keystore (holding all KEM private keys) is encrypted under a deterministic pepper-only KEK
(`EpochKeystore.deriveKek`, line 352); forward secrecy and PQ hang off keys stored under it.
Therefore the security of the entire layer against any attacker reduces to: *can the attacker obtain
the pepper?* This fact drives both the delivery findings and the premise analysis.

---

## 3. Threat model as documented

From `docs/threat_models_and_mitigation.md` §2 (lines 87-92); vocabulary fixed at line 41
(`ThreatCoverage.Level` = NONE / PARTIAL / REAL / NOT_APPLICABLE):

| Class | Attacker | In scope for the wrapper? |
|---|---|---|
| **A** | Same-UID process on a live host (canonical CVE-2018-19358) | **No** — "needs OS isolation" (`architecture/README.md:69`, `README.md:60`) |
| **B** | Cross-UID process reaching the session bus | Yes — envelope opacity |
| **C** | Offline disk/backup thief (stolen laptop, exfiltrated `~/.local/share/keyrings`) | Yes — pepper-not-on-disk + envelope opacity |
| **D** | Network adversary, harvest-now-decrypt-later | Yes — `enablePostQuantum(true)` + `rotateEpoch()`; `NOT_APPLICABLE` for a local-only keyring |

This scoping is intellectually honest and is the correct frame for the rest of the audit: the
question is not "does hardened stop a malicious local app" (it explicitly does not) but "does it
deliver B/C/D defense-in-depth."

---

## 4. Key-material providers — where the root of trust lives

| Provider | Pepper at rest | Same-UID reachable? | Self-report (`sameUid`/`crossUid`/`offline`) |
|---|---|---|---|
| `EnvVarKeyMaterialProvider` | env `SECRET_SERVICE_PEPPER` | **Yes** — `/proc/<pid>/environ` | NONE / NONE / NONE — honest; gated by theater check |
| `Argon2KeyMaterialProvider` | decorator; Argon2id-stretched inner pepper, cached in heap | **Yes** — ptrace the post-Argon value | passthrough, only bumps `offline` (NONE→PARTIAL→REAL) |
| `FileKeyMaterialProvider` | base64 file (enforced 0600) | **Yes** — owner reads it | NONE / REAL / PARTIAL (default) |
| `InteractiveKeyMaterialProvider` | prompted, held in heap | Live process only (ptrace) | PARTIAL / REAL / REAL |
| `Tpm2KeyMaterialProvider` | TPM-sealed blob (password policy, **not** PCR) | PARTIAL — ptrace unsealed heap, or open `/dev/tpmrm0` with the same password | PARTIAL / REAL / REAL |

Key observations:

- The **only** provider that creates a secret independent of the disk is the TPM provider. For
  env/file/argon2, a same-UID attacker *or* a full-disk-image thief who also captures the pepper
  source defeats the whole layer.
- The TPM seal is bound to a **password policy only** — no PCR selection is used
  (`Tpm2Provisioner.seal`, empty `TPMS_PCR_SELECTION[0]`). The docs are explicit that "TPM PCR
  policy is a partial defense *only when* Secure Boot + IMA-EVM + measured boot are in the chain …
  Without those, the TPM is a fancy file lock" (`threat_models_and_mitigation.md:1636`). The TPM
  authenticates *possession of the password + platform state, not caller identity*, so a same-UID
  attacker either ptraces the unsealed pepper or issues `TPM2_Unseal` themselves (throttled by the
  DA lockout because the templates deliberately omit `noDA`).
- The SPI hands out **raw pepper** (`char[]`), never a derived key; derivation happens in
  `HardenedCollection`. Only `Argon2` and `Tpm2` override `close()` to scrub; `EnvVar`, `File`,
  `Interactive` hold their pepper for the instance/process lifetime and never zero it (F-6). Env-var
  pepper is additionally an unzeroable immutable `String` inside the JVM before the provider ever
  sees it.

---

## 5. Delivery findings (does the code do what it says?)

### F-1 — Anti-rollback is silently OFF by default *(Medium)*

`HardenedCollection.Builder.generationAnchor` defaults to `null`. The only shipped implementation is
`Tpm2GenerationAnchor` (plus a test `FakeAnchor`); there is **no file- or JVM-backed anchor**. With
no anchor, `EpochKeystore.loadIfPresent` trusts "highest generation present"
(`EpochKeystore.java:187-195`, and the `anchor != null` guard at 196). An attacker who can write the
keyring can reintroduce an older genuine keystore snapshot and **resurrect the epoch keys that
`rotateEpoch` destroyed, silently undoing forward secrecy** — the exact attack
`docs/architecture/anti-rollback-anchor.md` describes.

Consequence: forward secrecy (a headline feature) is only robust when *both* (a) the pepper is
outside same-UID reach *and* (b) a `Tpm2GenerationAnchor` is configured. In the default build,
neither holds.

**Recommendation:** when `enablePostQuantum(true)` or `rotateEpoch()` is used without an anchor,
emit a loud construction-time `WARN` (mirroring the same-UID theater gate), or require an explicit
acknowledgement, so "forward secrecy" is never silently defeatable.

### F-2 — Forward secrecy is undone by backup retention *(Medium)*

The `EpochKeystore` holding all *live* epoch private keys is stored in the same keyring, encrypted
under a **deterministic pepper-only KEK** (fixed salt + fixed info, `EpochKeystore.deriveKek`,
line 352). Any keyring snapshot taken before a rotation still contains the old keys. So forward
secrecy protects only epochs that were destroyed *before* the attacker's snapshot; an attacker who
captured the keyring at time T and later learns the pepper can decrypt everything live at T.

The `HardenedCollection` Javadoc phrasing ("… no longer be decapsulated even by an attacker who
later learns the pepper", lines 60-62) slightly overstates this; the precise guarantee is "… who
later learns the pepper *and did not already hold a snapshot containing the old keystore*." The
threat doc states the limitation correctly (`threat_models_and_mitigation.md:1569`): FS is
"theoretical" unless backup retention is rotated too.

**Recommendation:** align the `HardenedCollection` Javadoc with the threat doc's honest phrasing;
state that FS presupposes backup-retention discipline and effective delete semantics in the
underlying store (gnome-keyring may retain deleted items in unallocated file space).

### F-3 — AEAD authenticates only part of the record *(Medium)*

`aad = associatedData(salt, epoch, itemId)` (`HardenedCollection.java:877`). It **excludes** the
envelope header: `version`, `flags`, `kem_id`, `nonce`, `kemCiphertext`. Furthermore, on read the
`itemId` and the TOTP `mode` are read from **unauthenticated D-Bus attributes**
(`hardened.item.id`, `hardened.totp.mode`) rather than from the sealed envelope
(`decryptToChars`, lines 686-697; `totpCodesForRead`, line 757).

Every tampering traced degrades to a decryption failure (GCM tag mismatch → `Optional.empty()`),
not forgery or disclosure — GCM still protects the secret because forging requires the DEK, which
requires pepper + KEM secret. So this is **not** a confidentiality/integrity break. But:

- `kem_id` tampering, `flags` tampering, and attribute tampering are all only *DoS*, and rely on the
  key-derivation mismatch to fail safe rather than on explicit authentication.
- A cross-item **relocation**: an attacker with keyring write access can set path Y's
  `hardened.item.id` to X's value and store X's envelope there, causing a legitimate reader (who
  holds the pepper) to receive X's plaintext when reading Y. No disclosure to the attacker, but an
  integrity-of-view issue on the application.

**Recommendation:** bind the full envelope header and the item identity/TOTP mode inside the AEAD
(as AAD, or by moving item-id and mode into the sealed plaintext). Removes the mutable-attribute
fragility and the relocation confusion.

### F-4 — DEK KDF uses `info`, not IKM, for the secret inputs *(Low)*

`deriveDek` computes `prk = HKDF-Extract(salt, pepper)` then
`dek = HKDF-Expand(prk, info = tag‖totp‖epoch‖itemId‖kemSecret)` (`HardenedCollection.java:846-874`).
The KEM shared secret and TOTP code are placed in **Expand's `info`** rather than concatenated into
the **IKM** alongside the pepper.

The construction still achieves the intended AND-composition (an attacker needs *both* pepper and
KEM secret):

- Attacker with pepper but not KEM secret (the post-rotation FS attacker): knows `prk`, but
  `dek = HMAC(prk, …‖kemSecret‖…)` is unpredictable without the 256-bit `kemSecret`. Safe — relies
  on HMAC-with-known-key being preimage-resistant (true for HMAC-SHA256, but not the textbook
  assumption).
- Attacker with keyring but not pepper: `prk` unknown → HMAC is a PRF → DEK pseudorandom. Safe.

So it is **sound, not a vulnerability**, but non-idiomatic; a reviewer/auditor will flag it.

**Recommendation:** feed all secret inputs as the IKM — `IKM = pepper ‖ kemSecret ‖ totp`, `salt` as
the Extract salt, and public context (`epoch`, `itemId`, tag) as `info` — for a clean, textbook
reduction.

### F-5 — TOTP modes: `STORED_STEP` self-defeating, `LIVE_CODE` a liveness window *(Low)*

TOTP is a KDF factor `HMAC(seed, step)`, not an independent second factor, and the seed lives in the
**same env/file as the pepper**. Therefore:

- **`STORED_STEP`**: the step is written to a cleartext attribute (`hardened.totp.step`,
  `HardenedCollection.java:284`) beside the ciphertext; anyone who can read the item and the
  key-material source recomputes the identical factor. The code itself labels it
  `"stored_step (theater)"` (`HardenedStatus.timeBindingLabel`).
- **`LIVE_CODE`**: adds only the constraint that a read occurs within ±1 step (~30-60 s) of write;
  since the attacker holds the seed, this is a liveness/time-window constraint, not a possession
  factor.

Delivered as documented (the code and docs both call `STORED_STEP` theater), but worth stating
plainly in the audit so no deployer mistakes TOTP for a second authentication factor.

### F-6 — Self-reports outrun enforcement; incomplete scrubbing *(Low)*

- `FileKeyMaterialProvider.validatePermissions` and `Tpm2SealedBlob.validateOwnerReadOnly` **skip**
  the 0600/owner check on non-POSIX filesystems (warn only) while still emitting `crossUid=REAL`.
  The self-report should degrade when the check cannot run.
- `EnvVar`, `File`, `Interactive` providers never override `close()` to zero cached material;
  `NoTotpKeyMaterialProvider` does not propagate `close()` to its delegate.

### F-7 — "HEALTHY" does not mean "hardened" *(Low)*

`HardenedHealthCheck.Report.healthy()` is true iff no finding is severity `FAIL`. The `sameUid=NONE`
posture, a missing `-XX:+DisableAttachMechanism`, and enabled heap dumps are all **WARN**, so a
collection with an env-var provider, attach mechanism on, and heap dumps enabled still reports
**HEALTHY** (as long as the canary decrypts or no canary is supplied). "Healthy" means "the canary
round-tripped," not "the deployment resists same-UID." Consider renaming or splitting the signal so
a WARN-only-but-weak deployment does not read as green.

---

## 6. Positive findings (mechanisms that are correctly built)

- **G-1 — AEAD usage is correct.** AES-256-GCM, fresh random 12-byte nonce per write, 128-bit tag,
  and a **unique DEK per item** (per-item salt + per-item KEM encapsulation). GCM nonce reuse under a
  fixed key — the one catastrophic GCM failure — cannot occur even across items.
- **G-2 — Hybrid KEM combiner is the recommended shape.** `combined = HKDF(ss_x25519 ‖ ss_pq)` with
  X25519 **always** present (`HybridKem.combine`, line 307). If either primitive is later broken, the
  other still protects the combined secret.
- **G-3 — Forward secrecy is a real mechanism.** The destroyable component is the per-epoch KEM
  private key; `rotateEpoch → retainOnly(next)` deletes superseded entries and re-persists
  (`EpochKeystore.java:264-271`). Because the DEK needs the KEM secret, and the KEM secret needs the
  epoch private key, destroying the key makes the pre-rotation DEK genuinely underivable even with
  the pepper. Correct approach for a long-lived-pepper design. (Scope caveats: F-1, F-2.)
- **G-4 — Fail-safe and memory hygiene.** `Optional.empty()` on any KEM/AEAD failure; key buffers
  zeroed in `finally` on every path; non-destructive to foreign items; create-then-delete keystore
  persistence (no data loss on crash); `char[]`-only plaintext, never `String`.
- **G-5 — Constant-time compare** for `matchesSecret` (`constantTimeEquals`, line 314).
- **G-6 — Honest self-assessment infrastructure.** `ThreatCoverage`, the `SecurityTheaterException`
  gate that refuses `sameUid=NONE` providers in production, `HardenedStatus` labels, and loud
  construction-time warnings. This honesty is unusual and is the project's biggest security asset.

---

## 7. Premise analysis — is application-layer encryption over the keyring the right idea?

### P-1 — The premise cannot address its own headline threat *(High, conceptual)*

The README motivates the whole effort with CVE-2018-19358: *any application you run can read your
unlocked keyring.* But **you cannot solve that with encryption performed inside the same process that
must hold the key.** A same-UID attacker, by definition, can read your process memory
(`/proc/<pid>/mem`, ptrace, jmap/attach), read your env and files, and invoke the same TPM unseal you
do. Plaintext is in the heap during the `withSecret` window; the pepper is in the heap right after
unseal; the TPM authenticates a password, not a caller. The docs concede every point of this
(`threat_models_and_mitigation.md` §11 "Honest anti-checklist", lines 1628-1650).

Solving class A requires a **different security principal** to hold *and use* the key:

- a separate-UID broker/agent process that performs decryption and returns only what the caller
  needs;
- a hardware token that performs the decryption *internally* (smartcard/FIDO), so the key never
  enters the app's address space — a TPM that unseals into your heap does not qualify;
- OS sandboxing that brokers access (Flatpak portals — which the docs note are **incompatible** with
  the wrapper, `threat_models_and_mitigation.md:341`).

The hardened layer instead redirects effort to B/C/D. That is a legitimate choice, but it means the
layer's most-advertised motivation is the one thing its architecture cannot deliver.

### P-2 — Delivered value is concentrated in the TPM path + deployment posture *(Medium, conceptual)*

Mapping the premise honestly against the pepper-is-the-root fact:

| Attacker | Plain keyring | Hardened delivers |
|---|---|---|
| **A** same-UID live | NONE | NONE → PARTIAL, **only** with TPM + MAC policy + JVM hardening. Structurally unsolvable in-process. |
| **B** cross-UID via bus | partial | Real but narrow (envelope opacity); presupposes a process that can already reach your session bus. |
| **C** offline disk/backup | depends on login pw | Real **only if the pepper is not in the same disk/backup** (TPM-sealed or off-host). Co-located env/file pepper → "buys nothing" (`threat_models_and_mitigation.md:1488`). |
| **D** HNDL | N/A | Real mechanism (hybrid PQ + FS); `NOT_APPLICABLE` for a local-only keyring by the project's own admission. |

Where the premise genuinely pays off:

- **An independent second secret**, so compromising the login password ≠ compromising the secrets —
  real **only** with a pepper root independent of the disk (TPM/off-host).
- **HNDL / post-quantum forward secrecy** for secrets that sync off-host — real mechanism, correctly
  built, caveated by F-1/F-2.
- **Crypto-agility and an auditable, daemon-opaque envelope** — engineering value; occasionally
  decisive for compliance/exfil scenarios.

But the honest verdict is that **almost all the delivered value lives in `hardened-tpm2` plus a full
deployment posture** — measured boot, a MAC policy confining `/dev/tpmrm0`, JVM hardening flags,
disciplined backup rotation — that the library can only *recommend* and the health check only
*warns* about. Strip the TPM and you are left with envelope opacity against a narrow cross-UID case
and offline protection that evaporates the moment the pepper shares a backup with the keyring. For
the default `EnvVar`/`Argon2`/`File` providers on a single-tenant desktop, the layer approaches what
the project itself calls "a complexity tax without proportional security benefit"
(`threat_models_and_mitigation.md:45`). The dominant threats the docs identify are **A (same-UID)
and C (stolen laptop)** (line 540); hardened does not touch A, and C on a single-tenant laptop is
already covered by full-disk encryption.

**Conclusion on the premise:** correct as scoped (B/C/D defense-in-depth with an independent pepper
root), incorrect if read as a general local-secret-isolation mechanism. The design is honest about
this; the top-level framing oversells relative to the deeper docs.

---

## 8. Recommendations (consolidated)

| Priority | Action | Addresses |
|---|---|---|
| 1 | Lead the README/coordinates framing with the honest scoping the threat doc already contains — "no class-A defense; real value needs the TPM + measured boot + MAC + backup rotation." | P-1, P-2 |
| 2 | Make anti-rollback fail loud: `WARN` (or require acknowledgement) when PQ/`rotateEpoch` is used without a `GenerationAnchor`. | F-1 |
| 3 | Fold the full envelope header + item identity + TOTP mode into the AEAD (AAD or sealed plaintext). | F-3 |
| 4 | Move KEM/TOTP secrets into the HKDF IKM rather than `info`. | F-4 |
| 5 | Align the `HardenedCollection` forward-secrecy Javadoc with the threat doc's backup-retention caveat. | F-2 |
| 6 | Degrade provider `ThreatCoverage` when the 0600/owner check is skipped (non-POSIX FS); scrub cached pepper on `close()` in all providers; propagate `close()` through decorators. | F-6 |
| 7 | Split or rename the health-check verdict so a WARN-only-but-weak deployment does not read as "HEALTHY." | F-7 |
| 8 | Longer-term: if defeating the CVE-2018-19358 (class-A) attacker is an actual goal, evaluate a separate-UID broker or hardware-token-performs-crypto architecture. In-process encryption cannot deliver it. | P-1 |

None of the delivery findings is a confidentiality or integrity break of a correctly-configured
TPM-backed deployment. The findings narrow the *scope* of several headline claims and harden the
construction; the premise findings concern framing and architectural fit, not a code defect.

---

## 9. Method, coverage, and limitations

- **Files read in full:** `Envelope.java`, `HardenedCollection.java`, `HybridKem.java`,
  `EpochKeystore.java`; provider set (`KeyMaterialProvider` + `EnvVar`/`Argon2`/`File`/`Interactive`/
  `NoTotp`), `Totp.java`, `GenerationAnchor.java`, `ThreatCoverage.java`, `KemId.java`,
  `HardenedHealthCheck.java`, `HardenedStatus.java`; TPM set (`Tpm2KeyMaterialProvider`,
  `Tpm2SealedBlob`, `Tpm2GenerationAnchor`, `Tpm2Availability`, `Tpm2Provisioner`); and the threat/
  architecture docs.
- **Not covered:** dynamic testing, fuzzing of the `Envelope` parser, timing/side-channel
  measurement, review of the core (non-hardened) transport encryption, and the D-Bus layer beyond
  how the hardened layer uses attributes.
- **Confidence:** high on the mechanism/correctness findings (traced to source); the premise
  findings are architectural judgments, stated as such.
- This document reflects the state at commit `613d8b4` and should be re-reviewed if the DEK
  derivation, envelope format, anchor wiring, or provider set changes.

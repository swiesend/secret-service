# Security & deployment guide


**Audience:** operators, packagers, and downstream library consumers shipping a JVM application that depends on `de.swiesend:secret-service` and (optionally) `secret-service-hardened` / `secret-service-hardened-tpm2`.
**Not audience:** end users of a desktop password manager built on top of this library.

This guide collects, in one place, every threat the library acknowledges and every Linux-side mechanism a deployer can apply against it. The tables and recipes are deliberately concrete — copy-paste ready — because the security material elsewhere in the project (README §CVE-2018-19358, every provider's `ThreatCoverage` rationale string) is correct but scattered.

It is structured as **threats first, then defenses, then deployment recipes**:

- [Threat catalogue](threat-catalogue.md) — attacker classes A–D and concrete threats
- [Defense mechanism inventory](defense-mechanisms.md) — every Linux-side guard, with coverage ratings
- [D-Bus policy in detail](dbus-policy.md) — what session-bus policy can and cannot do
- [Secret Service backend choice](backend-choice.md) — gnome-keyring vs KeePassXC
- [LUKS / full-disk encryption](full-disk-encryption.md) — LUKS, TPM-bound unlock, swap, snapshots
- [Desktop App consumer scenarios](desktop-deployment.md) — per distribution format, tar.gz through Nix
- [CI Tool consumer scenarios](ci-deployment.md) — JARs, packages, OCI containers, CI platforms
- [Mitigation matrices and sample configurations](sample-configurations.md) — matrices and copy-paste configs (systemd, AppArmor, SELinux, …)
- [Backup, escrow, and recovery](backup-and-recovery.md) — what to back up, escrow, and recovery
- [Honest anti-checklist](anti-checklist.md) — honest anti-checklist and references

## Introduction & scope

The `secret-service` library is a Java client for the [freedesktop Secret Service API 0.2](https://specifications.freedesktop.org/secret-service/0.2/). It does two things:

- **Transport encryption**: a Diffie–Hellman + AES-128-CBC session between the client and the daemon (gnome-keyring-daemon, KeePassXC, …) so the D-Bus wire is opaque to a passive listener. Standard, mandatory, already there in core.
- **Optional application-layer encryption** via `secret-service-hardened`: AES-256-GCM envelopes whose DEK is derived from a pluggable `KeyMaterialProvider` (env var, file, TPM2). This is the ciphertext-at-rest layer that the daemon itself cannot decrypt.

This document is about the **Linux-side guards** that surround such a JVM process: what threats they address, how to apply them, and which packaging format makes them easiest to apply.

**Out of scope:**

- In-JVM zeroing discipline (already documented in `withSecret` Javadoc)
- The plaintext-escape `@apiNote` on `withSecret` (already in the interface)
- Choosing between `withSecret` / `matchesSecret` (covered by interface Javadoc)
- Cross-platform parity (Windows/macOS — this library is Linux-only)
- End-user documentation (passphrase strength, device hygiene, etc.)

**Vocabulary used here:** the four attacker classes **A / B / C / D** defined in the [threat catalogue](threat-catalogue.md). Levels of mitigation are expressed using `ThreatCoverage.Level` words: **NONE**, **PARTIAL**, **REAL**, **NOT_APPLICABLE** — the same vocabulary the library's `ThreatCoverage` records publish at runtime. No new threat-model vocabulary is introduced.

### Do I need this?

Most consumers of `secret-service` should **only depend on the core artifact** and not pull in `secret-service-hardened` or `secret-service-hardened-tpm2` at all. The hardened layers exist for specific deployment shapes; for everything else they are a complexity tax without proportional security benefit.

Walk this tree:

```
Q1. Does my app handle real user secrets (passwords, tokens, signing keys)?
    No  → Use core only. Stop reading.
    Yes → Q2.

Q2. Is the Linux host I deploy onto multi-tenant
     (multi-user, container sidecars, shared CI runner)?
    Yes → hardened layer pays off (class B defense). Continue to Q3.
    No  → Q3.

Q3. Will the keyring file ever leave the host
     (cloud backup, off-host rsync, container snapshot, exfiltrated /home)?
    Yes → hardened layer pays off (class C defense). Continue to Q4.
    No  → Hardened buys little; consider stopping with core + KeePassXC backend.

Q4. Is the host stable (server / desktop with stable hardware,
     not a roaming laptop that might lose its TPM via motherboard swap)?
    Yes → hardened-tpm2 + Tpm2KeyMaterialProvider is the right default.
    No  → hardened with FileKeyMaterialProvider; document the recovery story (“Backup, escrow, and recovery” (backup-and-recovery.md)).

Q5. Are encrypted backups of secrets ever archived
     for years (off-site cold storage, long-retention CI logs)?
    Yes → enable PQ via .enablePostQuantum(true) -- ML-KEM-768 + X25519
          shared secret participates in HKDF; rotateEpoch() destroys old
          private keys for forward secrecy.
    No  → leave PQ off. The default is X25519 only.
```

The honest one-liner: **if you can answer "no" to Q2 and Q3, you do not need the hardened layer.** The doc remains useful — [Defense mechanism inventory](defense-mechanisms.md)-[LUKS / full-disk encryption](full-disk-encryption.md) are general Linux deployment hygiene that benefits any secret-handling app — but the wrapper itself is sized for the deployments where Q2 or Q3 are "yes."

The decision flips somewhat for **CI tools** (see [CI Tool consumer scenarios](ci-deployment.md)): even the hardened wrapper buys little against a CI platform compromise (the platform *is* class A in that environment). The wrapper's class-B benefit (envelope opacity) still matters when CI build artifacts are stored long-term, but the dominant action there is to use platform-injected secrets correctly, not to stack the hardened layer.

---

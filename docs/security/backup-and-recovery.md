# Backup, escrow, and recovery

*Part of the [Security & deployment guide](index.md).*


The hardened layer's failure modes are mostly *not* "the crypto broke" — they are "the operator forgot the password" or "the TPM died and the seal blob is unrecoverable." This section covers the operational realities: what to back up, where, and how to recover from each kind of loss.

## Inventory of secret material the operator manages

| Material | Where it lives | Lost ⇒ what happens | Backup target |
|---|---|---|---|
| **Pepper** (KeyMaterialProvider's source) | env var, file, TPM-sealed blob, KMS — depending on provider | All hardened items become unreadable | Out-of-band copy in a different trust domain (password manager, paper, KMS) |
| **TPM seal password** (operator-typed at provisioning) | only in the operator's head / password manager | The TPM-sealed pepper is unrecoverable; same effect as losing the pepper | Two independent copies (memorised + password manager / paper) |
| **`pepper.tpm2blob`** (the TPM-wrapped pepper file) | `~/.config/secret-service/hardened/pepper.tpm2blob` (mode 0600) | Without the blob you cannot unseal even with TPM + password | LUKS-encrypted backup; safe to copy because it is useless without the same TPM |
| **EpochKeystore item** (hardened.kind=epoch-keystore inside the wrapped collection) | A regular item in the gnome-keyring/KeePassXC database | All PQ-flagged hardened items become unreadable; non-PQ items are unaffected | Captured automatically by any backup that copies the keyring database |
| **The keyring file itself** | `~/.local/share/keyrings/*.keyring` (gnome-keyring) or `~/Documents/*.kdbx` (KeePassXC) | All items lost unless covered by daemon-level backup | Daemon's own backup story (out of scope for this library) |

The headline rule: **if the pepper is on the same disk as the keyring file and both are in the same backup, the wrapper buys nothing for class C** (the offline-disk thief gets both). The honest backup story keeps them in different trust domains.

## Pepper backup strategies (per provider)

#### `EnvVarKeyMaterialProvider`

The pepper is whatever you put in `SECRET_SERVICE_PEPPER`. Back up wherever you back up your environment / configuration. Two practical patterns:

```bash
# Generate once, store in your password manager (e.g. pass / Bitwarden / 1Password):
PEPPER=$(openssl rand -base64 32)
echo "$PEPPER" | pass insert -m yourapp/secret-service-pepper

# At each app launch, retrieve it:
SECRET_SERVICE_PEPPER=$(pass yourapp/secret-service-pepper) yourapp
```

Since `EnvVarKeyMaterialProvider` is class-A theatre by design (Javadoc says so loudly), the backup story matters mostly for class C: lose the password manager → lose the pepper → cannot read items. **Print a paper copy** for high-value deployments where the password manager itself could go away.

#### `FileKeyMaterialProvider` *(when present in your application)*

The pepper file at mode 0600 is the canonical artefact. Backup options, in order of trust-boundary separation:

1. **Encrypted offline copy on a separate device** (USB drive in a safe, encrypted with a password the user has memorised). Best for class C.
2. **Password manager** — paste the pepper as a "secure note." Convenient but co-mingles pepper with everything else the password manager protects.
3. **Paper printout** in a tamper-evident envelope. Tedious but immune to digital exfiltration.

Avoid: cloud sync (Dropbox/iCloud), which puts the pepper in the same trust domain as your keyring backup. Defeats the purpose.

#### `Tpm2KeyMaterialProvider`

Two artefacts to back up: the **seal password** (which gates `TPM2_Unseal`) and the **`pepper.tpm2blob`** file (which the TPM unseals).

```
                 Password         Blob file       TPM hardware
Backup needed?       YES              YES              NO (tied to host)
Loss tolerant?       NO               NO               recoverable from
                                                       a fresh provisioning
```

- **Password**: store in two independent locations (e.g. a password manager + a paper printout + a memorised passphrase). The TPM enforces dictionary-attack lockout (typically 32 wrong attempts → standby), so brute-forcing a 12+ character password is infeasible — but typing it wrong many times in a row will lock you out for hours. Plan ahead.
- **Blob file**: safe to copy widely (it is useless without the TPM). Bake it into your machine images / backups so a re-deployment of the same host re-uses the same sealed pepper. Backup it because losing it forces you to re-provision (which generates a *new* pepper, requiring a `rotateEpoch()` over every existing item).
- **TPM**: not backupable. Motherboard swap, firmware reset, or hardware failure means you must re-provision (`Tpm2Provisioner --out new.tpm2blob --password-stdin`) and then `rotateEpoch()` to rewrap items. Plan a *cross-host escrow* for high-value deployments: generate the pepper on a side channel, seal it in a TPM, and *also* archive the pepper itself in an offline KMS / paper safe so a host failure is recoverable.

The recommended operator script for TPM provisioning + escrow:

```bash
# 1. Generate a strong pepper (off-host or on-host, your choice).
PEPPER_RAW=$(openssl rand -base64 32)

# 2. Generate a strong seal password.
SEAL_PW=$(openssl rand -base64 24)

# 3. Escrow both BEFORE sealing. If anything fails after this, you can still recover.
echo "$PEPPER_RAW" | pass insert -m yourapp/pepper-raw         # paper backup recommended too
echo "$SEAL_PW"    | pass insert -m yourapp/seal-password      # paper backup recommended too

# 4. Seal the pepper with the password.
#    (a hypothetical companion tool that takes the raw pepper on stdin; today's
#    Tpm2Provisioner generates the pepper itself -- see “Recovery procedures” (backup-and-recovery.md) for the open gap.)
printf '%s' "$SEAL_PW"    | <provisioner> --out ~/.config/yourapp/pepper.tpm2blob \
                                          --password-stdin --pepper-source stdin <<< "$PEPPER_RAW"

unset PEPPER_RAW SEAL_PW   # zero from the shell environment
```

Today's `Tpm2Provisioner` generates a fresh pepper internally and seals it; the *raw* pepper is never exposed to the operator (good for class A on the operator's workstation, bad for escrow). If you need cross-host recoverability, treat the TPM blob + password as the escrow unit and accept that re-provisioning on a different host produces a new pepper.

## Backing up `pepper.tpm2blob`

The blob is **opaque ciphertext** — useless without the TPM that produced it and the password. Three sensible places:

1. **Bake it into your machine image / Ansible playbook / deployment archive.** Same host re-provisioning = same blob, same TPM, no ceremony.
2. **Copy to encrypted offline media** alongside the seal password. If the host dies and you re-deploy on the same hardware (e.g. swap a disk, keep the motherboard), you re-use the blob.
3. **Push to a cloud secret manager** (AWS SSM Parameter Store, GCP Secret Manager, Vault). Same trust-boundary caveat as the password: don't co-mingle. The cloud manager handles backup + access control.

## Backing up the EpochKeystore

The EpochKeystore lives as an item inside the wrapped collection (label `__hardened_epoch_keystore__`, attribute `hardened.kind=epoch-keystore`). Any backup that captures the keyring database also captures the keystore. Two consequences:

- A **partial restore** that brings back the keyring without the pepper / TPM does not give back any items — the keystore is encrypted and the recovery keys (pepper, seal password) live elsewhere.
- After a `rotateEpoch()` destroys the old keypair, **older keyring backups still containing the old keypair can be replayed to recover pre-rotation items**. This subverts the forward-secrecy property of `rotateEpoch()`. If forward secrecy matters in your threat model (genuine class-D defense), you must also rotate the *backup retention* — old keyring backups must age out, or the forward-secrecy guarantee is theoretical.

## Recovery procedures

**Lost the seal password** (TPM-sealed pepper):
1. Items are unrecoverable through the wrapper.
2. Use any *out-of-band copy* of the raw pepper (if you escrowed one) to bootstrap a new install.
3. Otherwise, all hardened items are gone. Restore from a higher-level backup of the original plaintexts if available.

**Lost the TPM hardware** (motherboard swap, firmware reset):
1. Provision a *new* `pepper.tpm2blob` on the new TPM with a *new* seal password.
2. If you escrowed the old pepper, decrypt items off-host (a small tool that runs the wrapper's HKDF-SHA256 — native `javax.crypto.KDF` — plus the AEAD each envelope names in its `aead_id`, i.e. AES-256-GCM or ChaCha20-Poly1305, with the old pepper), re-encrypt under the new pepper, re-import into the keyring.
3. If you did not escrow, items are gone. Class-C (laptop theft) is exactly the threat model TPM binding defends — losing your own laptop hits this same code path.

**Lost the keyring file** but kept pepper + TPM:
1. Items are gone. The wrapper has no role; a daemon-level keyring backup (Borg / restic / Snapper) is the only recovery.

**Lost the EpochKeystore item** (e.g. accidentally deleted):
1. Non-PQ items continue to read normally (they don't consult the keystore).
2. PQ items become unreadable. Recovery requires a backup of the keyring database from before the deletion. Document an explicit "do not delete items with `hardened.kind=epoch-keystore`" warning to your operators; the library refuses to delete it via `HardenedCollection.deleteItem` but a stray `secret-tool` invocation can.

**Forgot which provider was configured**:
1. Inspect any item's `hardened.*` attributes — they tell you the algorithm, mode, and KEM id.
2. The startup INFO log (`HardenedCollection initialised: provider=…`) names the provider class for the running JVM. If you have logs from a previous run, you have your answer.

## Pepper rotation

The wrapper has no built-in "rotate pepper" command. Pepper rotation is a multi-step operator procedure:

1. Generate a new pepper.
2. Read all hardened items with the *old* provider.
3. Construct a new `HardenedCollection` with a *new* provider (same backend, new pepper).
4. Write each item via the new collection (`createItem`).
5. Delete each old item.
6. Migrate the EpochKeystore: it is encrypted under the old pepper, so it must be re-created under the new pepper. Easiest: delete the old keystore item; the new collection lazily creates a fresh one.
7. Update your password-manager / paper backup to the new pepper.

Pepper rotation is rare (only when the old pepper is suspected compromised). For *epoch* rotation — which is forward-secrecy preserving — use `rotateEpoch()`; it does not require a new pepper.

## Backup recipe summary

A single defensive checklist for an operator commissioning a new TPM-backed deployment:

- [ ] Pepper: generated by `Tpm2Provisioner`; not directly visible to the operator
- [ ] Seal password: stored in *two* independent places (password manager + paper printout)
- [ ] `pepper.tpm2blob`: copied to encrypted offline media + included in machine image
- [ ] Keyring database: under daemon-level backup with **retention shorter than the rotateEpoch interval** if forward-secrecy matters
- [ ] Operator runbook: documents which provider is in use, where each artefact lives, how to recover

## When *not* to back up

- Don't back up an env-var pepper alongside the keyring database. Same trust domain → no class-C benefit.
- Don't print the seal password and store it next to the laptop. Class-C defense gone.
- Don't commit `pepper.tpm2blob` into a git repository or Docker image layer that is published broadly. The blob is opaque, but combined with a leaked seal password from elsewhere it becomes openable.

Backup discipline is the operator's job; the library cannot enforce it. The honest thing this section can do is name the artefacts and the failure modes — see [Honest anti-checklist](anti-checklist.md) (anti-checklist) for what the library still does not protect against.

---

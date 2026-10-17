# LUKS / full-disk encryption

*Part of the [Security & deployment guide](index.md).*


LUKS deserves its own section because it is the foundation for class-C defense and it interacts with the TPM in non-obvious ways.

## What LUKS covers

| Class | Coverage | Why |
|---|---|---|
| A | NONE | The system is running, the volume is unlocked. Same-UID processes see the decrypted FS. |
| B | NONE | Same UID or different UID, both processes see the same decrypted FS. |
| **C** | **REAL** | Disk at rest is opaque. Stolen laptop = no plaintext. |
| D | NOT_APPLICABLE | Network adversary doesn't have the disk. |

LUKS is necessary but not sufficient. It defeats class C only when the disk is **actually at rest** — laptop closed and powered off, drive removed, decommissioned, *or* the LUKS volume dismounted. A running machine with LUKS unlocked is class-C-equivalent to a machine with no LUKS.

## Where the keyring file lives

- gnome-keyring: `~/.local/share/keyrings/login.keyring` (and other named collections).
- KeePassXC: wherever the user put the `.kdbx` file (typically `~/Documents/Passwords.kdbx`).
- Hardened wrapper: items live inside whichever Secret Service backend you use; only the *envelope ciphertext* is stored. The TPM sealed-blob lives at a path you choose (recommended: `~/.config/secret-service/hardened/pepper.tpm2blob`, mode 0600).

All of these are on the encrypted root partition under a typical Linux install. None require special LUKS configuration beyond "encrypt the whole disk."

## TPM-bound LUKS (`systemd-cryptenroll --tpm2-device=auto`)

This is a feature where LUKS unlocks itself at boot using a key sealed in the TPM (typically PCR-bound). Pros: no passphrase prompt, frictionless boot. Cons: requires Secure Boot + measured boot to be meaningful — without those, an attacker who replaces your initrd unlocks the disk just by booting.

**Important distinction**: TPM-bound LUKS and the hardened wrapper's `Tpm2KeyMaterialProvider` are independent uses of the TPM. You can run either, both, or neither. They protect different things:

| | TPM-bound LUKS | Hardened wrapper TPM provider |
|---|---|---|
| Protects | Block-device contents at rest | Application-layer pepper |
| Threat addressed | C (offline disk) | C (backup of `~`) plus B (cross-UID readers of the pepper file) |
| Failure if TPM lost | Disk unrecoverable without recovery key | Wrapper unrecoverable; secrets lost |
| Failure if PCR changes (kernel update) | Disk needs `systemd-cryptenroll --recovery-key` | Wrapper unaffected (we use password policy, not PCR policy in v1) |

If you only do one: **TPM-bound LUKS is more impactful for class C** (it covers everything on the disk, not just the keyring). The hardened wrapper's TPM provider is the right next step when the threat extends beyond "stolen physical disk" to "exfiltrated home directory backup."

## Swap and hibernation

- **Swap encryption** is a silent prerequisite. Without it, `mlockall` is the only thing standing between plaintext in RAM and plaintext on disk. Configure either via LUKS-encrypted swap (persistent) or `crypttab` random-key swap (re-keyed each boot, breaks hibernation).
- **Hibernation** writes the entire RAM (every byte your process owns, including unsealed peppers and DEKs) to a swap file or partition. If that swap is unencrypted, hibernation defeats every other class-C mitigation. Either encrypt the swap or disable hibernation (`systemctl mask hibernate.target`).

## Filesystem snapshots — the silent class-C path

Btrfs / ZFS / LVM snapshots run in kernel and can be read by an attacker who has root or a snapshot-readable user (`btrfs subvolume`-permitted user). Class C effectively reaches the snapshot even if the live FS is locked.

**Two practical hazards:**

1. Backup tools that snapshot before backing up (Timeshift, Snapper, Borg) — the snapshot persists on the same disk. If LUKS is unlocked and the snapshot is readable, class C reaches the snapshot.
2. Container build pipelines that retain layer caches (`overlayfs` upper dirs) — secrets baked into a build layer get baked into the cached layer, even after the file is "deleted" in a later layer.

**Practical guidance**: never build container images with secrets present in any layer; always use Docker BuildKit secret mounts or equivalent. For desktop snapshot tools, configure them to exclude `~/.local/share/keyrings/` and the TPM blob path.

---

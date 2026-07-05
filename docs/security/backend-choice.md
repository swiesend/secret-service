# Secret Service backend choice

*Part of the [Security & deployment guide](index.md).*


The library is the *client* of the freedesktop Secret Service API. The *daemon* on the other end of the session bus is one of:

- **gnome-keyring-daemon** (default on GNOME-based desktops, also used headless via `gnome-keyring-daemon --daemonize`)
- **KeePassXC** with the "Enable Secret Service Integration" plugin
- (Less common) `pass-secret-service`, `kdewallet5` via `keychain` shim, custom implementations

The library's CHANGELOG already notes that `org.gnome.keyring` is deferred-loaded so it works on non-GNOME backends, and the [roadmap](../roadmap.md) calls out KeePassXC as a target backend. The choice has real security consequences.

## gnome-keyring vs KeePassXC at a glance

| Property | gnome-keyring | KeePassXC |
|---|---|---|
| **At-rest format** | `~/.local/share/keyrings/<name>.keyring` (binary, AES-128 by default) | `~/Documents/<vault>.kdbx` (Argon2 + AES-256 / ChaCha20) |
| **Unlock model** | PAM-unlocked at login; remains unlocked for the whole session | User unlocks the database explicitly; can auto-lock on idle / lock screen |
| **Class-A defense** | NONE — once unlocked, anything same-UID gets items | **PARTIAL — interactive per-item access prompt** (configurable: ask once per app, ask every time, deny by default) |
| **Per-item ACLs** | None | Yes — per database group, per item, per requester |
| **Master-password strength** | Equivalent to login password (often weak) | Independent, typically stronger; supports key file + YubiKey challenge-response as additional factors |
| **Cross-platform** | Linux only | Linux / Windows / macOS (Secret Service integration is Linux-only) |
| **Default on** | Ubuntu, Fedora, Debian (with GNOME) | Anywhere the user installs it |

## Class-by-class comparison

| Class | gnome-keyring (alone) | KeePassXC (alone) | gnome-keyring + hardened wrapper | KeePassXC + hardened wrapper |
|---|---|---|---|---|
| **A** | NONE | PARTIAL (interactive prompt) | PARTIAL (only if pepper TPM-sealed + MAC) | **PARTIAL → REAL** when stacked: interactive prompt + opaque envelope + TPM unseal |
| **B** | PARTIAL (depends on file modes + bus permissions) | PARTIAL | REAL with file mode 0600 | REAL |
| **C** | NONE if pepper colocated; PARTIAL otherwise | PARTIAL (Argon2 KDF over the .kdbx is real cost) | **REAL** with TPM provider | **REAL** (two layers: KDBX + envelope) |
| **D** | NOT_APPLICABLE for local-only | NOT_APPLICABLE | REAL when PQ enabled and ciphertext leaves host | REAL |

## Stacking: hardened wrapper on top of either backend

The hardened wrapper runs the *envelope*, not the *daemon*. It treats whichever Secret Service implementation is on the bus as opaque storage. Two stacking effects:

1. **gnome-keyring + hardened**: items in `~/.local/share/keyrings/login.keyring` become opaque AES-256-GCM ciphertext. Even when the keyring is unlocked (which it always is on a logged-in GNOME desktop), the daemon cannot decrypt them. A class-A attacker who walks up to the bus and asks for an item gets ciphertext, not plaintext. They still need to ptrace the JVM or open `/dev/tpmrm0` to advance — and that's where MAC + memory hygiene help.

2. **KeePassXC + hardened**: triple defense. KeePassXC asks the user before exposing any item to a previously-unknown bus client (defeats class A passively); the hardened envelope is opaque to KeePassXC itself (defeats class A even if the user clicks "allow"); the TPM unseal is bound to the host (defeats class C even if the .kdbx file is exfiltrated). Each layer has independent failure modes — no single misconfiguration loses everything.

## Recommendation

- **Server / headless**: backend doesn't matter much for the library's purposes; use whatever the distro packages and run it under a dedicated UID that isn't shared with anything else. The hardened wrapper carries most of the weight.
- **Linux desktop deployments**: prefer **KeePassXC** as the backend. Its per-item ACL prompt is the only realistic class-A defense available without operator-installed MAC, and it stacks well with the hardened wrapper.
- **Cross-platform applications**: this library is Linux-only. On Windows/macOS use the platform OS keychain directly.

---

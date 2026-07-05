# Threat Models and Mitigation

**Audience:** operators, packagers, and downstream library consumers shipping a JVM application that depends on `de.swiesend:secret-service` and (optionally) `secret-service-hardened` / `secret-service-hardened-tpm2`.
**Not audience:** end users of a desktop password manager built on top of this library.

This document collects, in one place, every threat the library acknowledges and every Linux-side mechanism a deployer can apply against it. The tables and recipes are deliberately concrete — copy-paste ready — because the security material elsewhere in the project (CLAUDE.md, README §CVE-2018-19358, `docs/vision.md`, every provider's `ThreatCoverage` rationale string) is correct but scattered.

It is structured as **threats first, then defenses, then deployment recipes**:

1. [Introduction & scope](#1-introduction--scope)
   - [1.1 Do I need this?](#11-do-i-need-this) — quick decision tree
2. [Threat catalogue](#2-threat-catalogue) — attacker classes and concrete threats
3. [Defense mechanism inventory](#3-defense-mechanism-inventory) — every Linux-side guard
4. [D-Bus policy in detail](#4-d-bus-policy-in-detail)
5. [Secret Service backend choice — gnome-keyring vs KeePassXC](#5-secret-service-backend-choice)
6. [LUKS / full-disk encryption](#6-luks--full-disk-encryption)
7. [Desktop App consumer scenarios](#7-desktop-app-consumer-scenarios) — step by step, by distribution format
8. [CI Tool consumer scenarios](#8-ci-tool-consumer-scenarios) — step by step, by distribution format
9. [Mitigation matrices and sample configurations](#9-mitigation-matrices-and-sample-configurations) — including the mitigation-vs-environment matrix
10. [Backup, escrow, and recovery](#10-backup-escrow-and-recovery) — what to back up, where, and how to recover
11. [Honest anti-checklist](#11-honest-anti-checklist)
12. [References](#12-references)

## 1. Introduction & scope

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

**Vocabulary used here:** the four attacker classes **A / B / C / D** from the project's existing threat model (§Threat Model in the implementation plan). Levels of mitigation are expressed using `ThreatCoverage.Level` words: **NONE**, **PARTIAL**, **REAL**, **NOT_APPLICABLE** — the same vocabulary the library's `ThreatCoverage` records publish at runtime. No new threat-model vocabulary is introduced.

### 1.1 Do I need this?

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
    No  → hardened with FileKeyMaterialProvider; document the recovery story (§10).

Q5. Are encrypted backups of secrets ever archived
     for years (off-site cold storage, long-retention CI logs)?
    Yes → enable PQ via .enablePostQuantum(true) -- ML-KEM-768 + X25519
          shared secret participates in HKDF; rotateEpoch() destroys old
          private keys for forward secrecy.
    No  → leave PQ off. The default is X25519 only.
```

The honest one-liner: **if you can answer "no" to Q2 and Q3, you do not need the hardened layer.** The doc remains useful — §3-§6 are general Linux deployment hygiene that benefits any secret-handling app — but the wrapper itself is sized for the deployments where Q2 or Q3 are "yes."

The decision flips somewhat for **CI tools** (see §8): even the hardened wrapper buys little against a CI platform compromise (the platform *is* class A in that environment). The wrapper's class-B benefit (envelope opacity) still matters when CI build artifacts are stored long-term, but the dominant action there is to use platform-injected secrets correctly, not to stack the hardened layer.

---

## 2. Threat catalogue

The library names four attacker classes. The table below is the *canonical* shape — concrete threats further down expand each row.

| # | Attacker | Has keyring? | Same UID? | `/proc/<pid>` access? | Host disk? |
|---|---|---|---|---|---|
| **A** | Same-UID process on live host (canonical CVE-2018-19358) | yes | **yes** | **yes** | yes |
| **B** | Cross-UID process on same host (sandboxed app, other user) | yes (via D-Bus) | no | no | no |
| **C** | Offline disk/backup thief (stolen laptop, exfiltrated `~/.local/share/keyrings`) | yes (cold) | no | no | yes (cold) |
| **D** | Network adversary with harvest-now-decrypt-later ambition | no | no | no | no |

### 2.1 Class A — same-UID live process

The hardest attacker to defend against, because they share the trust domain that contains both the ciphertext *and* most of the wrapping material. Concrete attack vectors:

- **JVM heap inspection**: `ptrace(2)` + `process_vm_readv(2)` on the running JVM, `/proc/<pid>/mem`, kernel-`ptrace`-via-`PTRACE_PEEKDATA`. Reads the unsealed pepper, the cached DEK, and any plaintext sitting in the `withSecret` callback window.
- **JVM attach API**: `jstack`, `jmap`, `jcmd`, custom JVMTI agent. Same UID can attach to a JVM that hasn't passed `-XX:+DisableAttachMechanism`.
- **Environment / cmdline scrape**: `/proc/<pid>/environ` reveals env-var peppers; `/proc/<pid>/cmdline` reveals plaintext password CLI flags. (See §6 in the implementation review for why the Tpm2Provisioner refuses to take `--password <plaintext>`.)
- **Direct daemon access**: open the session bus (`$DBUS_SESSION_BUS_ADDRESS`) and just *ask* the Secret Service daemon for the unlocked items — no exploit needed; the daemon's design assumes same-UID is trusted.
- **Direct TPM access**: open `/dev/tpmrm0` and issue TPM 2.0 commands. The TPM authenticates possession of secrets and platform state, *not* caller identity. Knowing the seal password — or extracting it from JVM heap — yields the unsealed pepper.
- **Kernel keyring**: read user/session keyrings via `keyctl(2)` if the application uses the kernel keyring as a transport.
- **Side channels**: `/proc/<pid>/status` (peak memory), `/proc/<pid>/io` (bytes read), `/sys/fs/cgroup/<…>/memory.stat`, sched_yield timing — useful for inferring activity, rarely for extracting plaintext directly.

This class is what the project's plan §Security Theater Audit calls out: *"the most common local-machine attacker."*

### 2.2 Class B — cross-UID process on same host

Sandboxed app, multi-user system, sidecar container running as a different UID. Concrete vectors:

- **Loose file modes** on `~/.local/share/keyrings/*.keyring`, the pepper file, or `pepper.tpm2blob`. Group-readable or other-readable lets B exfiltrate.
- **Leaked `DBUS_SESSION_BUS_ADDRESS`**: if the victim's session bus address is reachable from B (shared `/run/user/<uid>` mount, accidentally bind-mounted into a sidecar), B can connect and ask for items.
- **Container volume cross-talk**: shared volumes between sidecars in a Pod, anonymous volumes that survive container teardown.
- **`/dev/tpmrm0` permissions**: the udev default usually puts the device into the `tss` group with mode 0660. Anyone in `tss`, regardless of UID, can talk to the TPM. If your application user and the attacker user are both in `tss`, B is effectively a TPM client.

### 2.3 Class C — offline disk/backup thief

The disk is at rest; the attacker has bytes but no live process. Concrete vectors:

- **Stolen laptop / decommissioned drive / disposed SSD**.
- **Exfiltrated `rsync`** of `~`, container snapshot, ZFS/Btrfs snapshot, LVM snapshot.
- **Cloud-synced backup** that contains `~/.local/share/keyrings`, the pepper file, the `pepper.tpm2blob`, *and* the env-var-style configuration that names the seal password.
- **Swap-file recovery / hibernation image**: `/var/lib/swap` or `/swapfile` if not encrypted. Hibernation writes the entire RAM (including unlocked secrets) to disk.
- **Core dumps**: `/var/lib/systemd/coredump`, `/proc/sys/kernel/core_pattern` redirects, `coredumpctl dump`. JVM heap dump on OOM (`-XX:+HeapDumpOnOutOfMemoryError`) lands plaintext on disk in clear.
- **Filesystem journal / undelete**: ext4 journal or NTFS USN journal can retain blocks of recently-deleted files; forensic recovery from "I deleted the keyring" is realistic.

### 2.4 Class D — network harvest-now-decrypt-later

Ciphertext that ever leaves the host, archived for future quantum decryption.

- **Backup uploaded to cloud storage** that the provider (or an attacker who breaches the provider) retains for years.
- **IMAP-delivered secrets** routed through a long-retention mail provider.
- **Sync protocols** that ship the keyring file across the network.
- **Audit log replication** that captures encrypted secrets in transit.

This is the row where hybrid post-quantum (X25519 + ML-KEM-768, see `HybridKem`) matters. The wrapper's PQ mode (`Builder.enablePostQuantum(true)`) wires the ML-KEM shared secret into HKDF DEK derivation and stores the KEM ciphertext in the envelope's `kem_ct` field. `rotateEpoch()` destroys the previous epoch's keypair via the `EpochKeystore`, so pre-rotation envelopes captured by an HNDL attacker become unrecoverable: a real class-D defense, not just a label. For a purely local keyring with no off-host sync, class D remains `NOT_APPLICABLE`.

### 2.5 Cross-cutting threats (don't fit one class cleanly)

- **Supply-chain attack**: malicious update of a transitive dep — `bcprov-jdk18on`, `TSS.Java`, `dbus-java-core`. Reads plaintext directly; out of scope of OS guards but worth naming.
- **CI build-log leakage**: `mvn -X` printing env vars, GitHub Actions secret echo, Jenkins log retention. Class C-shaped but with the build infrastructure as the disk.
- **Evil maid**: firmware tamper, BIOS implant, bootloader replacement before measured boot. TPM PCR policy is a partial defense if Secure Boot + IMA-EVM are in the chain; otherwise NONE.
- **DMA attack**: Thunderbolt / FireWire / PCIe device with bus-master access reads RAM directly. IOMMU + kernel `iommu=force` is the answer; out of scope here.
- **Cold-boot attack**: RAM contents survive a power cycle for seconds to minutes if the chip is cooled. Defeated by `mlockall` only against swap, not against this.
- **Kernel exploit**: a kernel-level adversary trivially bypasses every userspace MAC framework. All defenses in §3 assume the kernel is trusted.

---

## 3. Defense mechanism inventory

Each entry: **what it does → which threat classes it addresses (and at what `Level`) → how to apply it to a JVM Secret Service consumer → limitations.**

### 3.1 LUKS / dm-crypt full-disk encryption

**What it does.** Encrypts a block device under a key sealed in a LUKS header. The kernel decrypts on the fly while the device is unlocked; bytes on the disk are useless without the LUKS key.

**Threat coverage.** A: NONE (system is running, disk is unlocked) · B: NONE (same disk, both processes see decrypted FS) · **C: REAL** · D: NOT_APPLICABLE.

**How to apply.** Install on a LUKS-formatted root partition. For application data dirs explicitly:

```
sudo cryptsetup luksFormat /dev/sdX
sudo cryptsetup open /dev/sdX secrets
sudo mkfs.ext4 /dev/mapper/secrets
echo 'secrets UUID=… none luks,discard' | sudo tee -a /etc/crypttab
```

For TPM-bound LUKS that unlocks at boot without a passphrase prompt:

```
sudo systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0+7 /dev/sdX
```

**Limitations.** Once the system boots and LUKS is unlocked, every other class (A/B/D) sees the decrypted contents. LUKS is a class-C mitigation only. In particular, "LUKS is unlocked by my TPM at boot" is NOT the same as "my application secret is sealed in my TPM" — both are useful, neither replaces the other. See §6.

### 3.2 POSIX DAC (file modes, ownership, umask)

**What it does.** Per-file owner/group/other read/write/execute bits, enforced by every syscall.

**Threat coverage.** A: NONE (same UID is the file owner) · **B: REAL** when modes are right · **C: REAL** as a defense-in-depth on top of LUKS · D: NOT_APPLICABLE.

**How to apply.** The library already enforces this for the TPM sealed-blob file (`Tpm2SealedBlob.writeTo` creates the file mode 0600 from the outset; `Tpm2SealedBlob.readFrom` refuses to load over-permissive files). Mirror the discipline for any pepper file your `KeyMaterialProvider` reads. Set a strict umask (`umask 077`) in the systemd unit's `UMask=` directive so transient files inherit owner-only permissions.

**Limitations.** Class A bypasses DAC entirely (they *are* the owner). DAC against B requires that the application user differs from the attacker's UID — not always the case in containerised deployments where everything runs as one UID.

### 3.3 POSIX capabilities

**What it does.** Splits root's privileges into ~40 fine-grained capabilities (`CAP_NET_BIND_SERVICE`, `CAP_IPC_LOCK`, etc.) that can be granted to non-root processes or removed from a privileged one.

**Threat coverage for our use case.**
- **`CAP_IPC_LOCK`** to allow `mlockall(MCL_CURRENT | MCL_FUTURE)` from a non-root JVM — defense-in-depth against C (no swap leakage) and partial against A (no ptrace from a process that lacks `CAP_SYS_PTRACE`).
- **Drop `CAP_SYS_PTRACE`** in the bounding set so the JVM cannot ptrace others (and, more importantly, so anything the JVM spawns inherits the absence).
- **Drop `CAP_DAC_OVERRIDE`** so even if exploited the JVM can't read files it doesn't own.

**How to apply.** systemd `AmbientCapabilities=CAP_IPC_LOCK` + `CapabilityBoundingSet=CAP_IPC_LOCK` + `NoNewPrivileges=true`. Or `setcap cap_ipc_lock+ep /usr/lib/jvm/.../bin/java`.

**Limitations.** Capabilities apply to syscalls; they do not restrict what the JVM does inside its own address space.

### 3.4 MAC: SELinux

**What it does.** Type Enforcement: every process has a domain, every file/device a type, and the policy declares which domains may do what to which types. The kernel enforces, irrespective of UID. Default on RHEL, Fedora, CentOS Stream, AlmaLinux, Rocky.

**Threat coverage.** **A: REAL** when policy is tight (denies `ptrace`, denies `/dev/tpmrm0` open from outside the application's domain) · **B: REAL** · C: NOT_APPLICABLE (offline) · D: NOT_APPLICABLE.

**How to apply.** Ship a small policy module that confines the application to a `secret_service_app_t` domain and grants it `tpm_device_t` access. See §9.6 for the skeleton.

**Limitations.** Policy authoring is non-trivial; misconfigured policy is silently denied (check `audit2allow`). SELinux is bypassed by a kernel-level adversary.

### 3.5 MAC: AppArmor

**What it does.** Path-based access control: profiles list which file paths a binary can read/write/execute and which capabilities it has. Default on Ubuntu, Debian, openSUSE, SUSE.

**Threat coverage.** Same as SELinux for our use case — **A: REAL** with a tight profile, **B: REAL**.

**How to apply.** Drop a profile in `/etc/apparmor.d/usr.local.bin.secret-service-app`. See §9.5 for a sample. AppArmor profiles are cheaper to write than SELinux modules but path-based, so a renamed binary or symlinked path bypasses them.

**Limitations.** Path-based ⇒ symlink/rename hazards, and bind-mounts can shift things out of profile coverage. A kernel-level adversary bypasses AppArmor.

### 3.6 seccomp-bpf

**What it does.** A BPF program filters every syscall the process makes; non-matching syscalls return `EPERM` or kill the process.

**Threat coverage.** Hardens A and B further by removing dangerous syscalls (`ptrace`, `process_vm_readv`, `kcmp`, `mount`, `unshare`, `clone3` with namespace flags, …). Most useful when the attacker is exploiting an in-JVM bug to spawn code; less useful against the canonical `ptrace`-from-outside attacker.

**How to apply.** systemd `SystemCallFilter=@system-service` is the easy default — that allowlist excludes most dangerous syscalls. For a JVM, the wide default syscall surface (futex, file I/O, threading, GC) means a *block-list* (`SystemCallFilter=~ptrace process_vm_readv kcmp`) is more practical than a precise allowlist.

**Limitations.** seccomp filters the JVM, not what attaches *to* the JVM. A separate process with `CAP_SYS_PTRACE` is unaffected.

### 3.7 Linux namespaces

**What it does.** Per-process kernel-resource isolation. Six namespaces matter here:

- **user** — UID/GID remapping; the process can be `root` inside, unprivileged outside
- **mount** — own filesystem view
- **network** — own network stack (no D-Bus session bus reachable unless explicitly mounted in)
- **pid** — own process tree (no `/proc/<pid>` visible)
- **ipc** — own SysV IPC, shared memory, message queues
- **uts** — own hostname

**Threat coverage.** Foundation for all sandboxing: containers, Flatpak, Snap, systemd `Private*=` directives all stack on namespaces. Helps A (the namespaced process can't see its host's `/proc`), helps B (different network and IPC namespaces hide D-Bus addresses).

**How to apply.** Indirectly via systemd `PrivateTmp=`, `PrivateNetwork=`, `PrivateUsers=`, `ProtectProc=invisible`, etc. — see §3.10.

**Limitations.** A namespaced JVM that needs to talk to the *host*'s session bus must have that bus's socket bind-mounted in, which negates the network/IPC namespace benefit for that path.

### 3.8 cgroups v2 (device controller)

**What it does.** The `device` controller in cgroup v2 (eBPF-based) explicitly allows or denies access to specific device nodes per cgroup.

**Threat coverage.** Useful complement to MAC for `/dev/tpmrm0`: cgroup denies `open(2)` regardless of UID or selinux/apparmor verdict. Defense-in-depth.

**How to apply.** systemd `DeviceAllow=/dev/tpmrm0 rw` + `DevicePolicy=closed` (closed = deny everything except explicit allows).

**Limitations.** Container runtimes manage their own cgroup hierarchies; OCI's default device cgroup denies most things, and you must explicitly opt the TPM in via `--device=/dev/tpmrm0`.

### 3.9 Memory hygiene (mlockall, no swap, no core dumps, no attach)

**What it does.** Stops plaintext / pepper / DEK from leaking out of RAM into places the attacker can read.

**Threat coverage.**
- `mlockall(MCL_CURRENT | MCL_FUTURE)`: **C: REAL** (no swap leakage, no hibernation leakage).
- `prctl(PR_SET_DUMPABLE, 0)` + `RLIMIT_CORE=0`: **C: REAL** (no core dumps).
- `-XX:+DisableAttachMechanism`: **A: PARTIAL** (defeats `jstack`/`jmap` from same UID without root, but `ptrace` still works).
- `-XX:-HeapDumpOnOutOfMemoryError`: **C: REAL** (no plaintext heap dump on OOM).

**How to apply (consolidated).**

```ini
# systemd unit fragment
[Service]
LimitCORE=0
LimitMEMLOCK=infinity
AmbientCapabilities=CAP_IPC_LOCK
Environment="JAVA_TOOL_OPTIONS=-XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError"
```

Plus, in JVM startup: enable `mlockall` via JNA in your application's `main()` (the library doesn't auto-mlock; that decision belongs to the consumer).

**Limitations.** `mlockall` doesn't help against live RAM extraction (cold-boot, JTAG). Attach-mechanism disable doesn't block `ptrace` — that's MAC's job.

### 3.10 systemd unit hardening

**What it does.** systemd exposes the kernel's namespace/cgroup/seccomp/MAC primitives as declarative directives in the unit file. The richest single-tool way to harden a daemon on Linux.

**Threat coverage.** Composes the above mechanisms — coverage matches whichever primitives you enable.

**Key directives for our use case** (see §9.4 for a full unit):

| Directive | Effect | Class addressed |
|---|---|---|
| `ProtectSystem=strict` | Whole filesystem read-only except `/var`, `/etc/machine-id`, allowlisted paths | A, B, C |
| `ProtectHome=true` | `/home`, `/root`, `/run/user` invisible | B, C |
| `PrivateTmp=true` | New `/tmp` and `/var/tmp` namespaces | A |
| `PrivateDevices=true` | New `/dev` with only minimal nodes | A, B |
| `DeviceAllow=/dev/tpmrm0 rw` | Re-add TPM after `PrivateDevices=` | (re-enabling necessary access) |
| `NoNewPrivileges=true` | `setuid` binaries can't escalate | A |
| `ProtectKernelTunables=true` | `/proc/sys`, `/sys` read-only | A |
| `ProtectControlGroups=true` | `/sys/fs/cgroup` read-only | A |
| `RestrictAddressFamilies=AF_UNIX` | Only Unix sockets — denies network | B |
| `RestrictNamespaces=true` | Cannot create new namespaces | A |
| `LockPersonality=true` | Cannot change personality (e.g. for ASLR-defeat) | A |
| `MemoryDenyWriteExecute=true` | No W^X violations — defeats some JIT-spray exploits | A |
| `SystemCallFilter=@system-service` | seccomp allowlist | A, B |
| `SystemCallArchitectures=native` | Only native syscalls (no `ia32` shadow surface) | A |
| `LimitCORE=0` | No core dumps | C |
| `LimitMEMLOCK=infinity` | Permit `mlockall` | C |
| `RemoveIPC=true` | Clean up SysV IPC on exit | A |
| `UMask=0077` | Files created mode 0600 by default | B, C |

**Limitations.** Some directives interact badly with the JVM (`MemoryDenyWriteExecute=` breaks JIT in older JVMs; modern HotSpot is fine). Always `systemd-analyze security <unit>` and `systemd-analyze verify <unit>` before deploying.

### 3.11 Secure Boot, Measured Boot, IMA-EVM

**What it does.** Establishes a chain of trust from firmware → bootloader → kernel → initrd that the TPM measures into PCRs. PCR values then bind sealed objects to a known-good boot state.

**Threat coverage.** **C: REAL** (a tampered boot path produces different PCRs, the seal won't open). Partial against the firmware-tamper "evil maid" if the chain is unbroken.

**How to apply.** Distribution-specific (Fedora `sbverify`, Ubuntu `mokutil`, …). Required upstream of the TPM PCR-policy mode this library reserves but doesn't yet ship (`Tpm2SealedBlob.PolicyKind.PCR`).

**Limitations.** Operationally heavy — kernel updates, initrd regeneration, and bootloader changes all shift PCR values, breaking sealed objects. Plan a rotation strategy.

### 3.12 udev rules for `/dev/tpmrm0`

**What it does.** Sets ownership, group, mode, and tags on device nodes when they appear.

**Threat coverage.** Defense-in-depth on top of MAC: confining `/dev/tpmrm0` to a specific group (or the application's UID) reduces class B's TPM access.

**How to apply.** See §9.11 for a sample rule.

**Limitations.** udev runs as root with no MAC awareness; rules are advisory inputs to the device-node permission decision, not security boundaries.

### 3.13 xdg-desktop-portal `org.freedesktop.portal.Secret`

**What it does.** A sandbox-friendly indirection for Secret Service: instead of letting a Flatpak'd app talk to the session bus directly, the portal mediates and prompts the user for consent.

**Threat coverage.** Class B (sandboxed app → host secrets), class A in the limited sense that the portal can require interactive user confirmation.

**How to apply.** *Not a substitute for this library; an alternative path.* If your application is Flatpak-distributed, consider using the portal directly (via `Gio.DBusProxy` or equivalent) instead of the freedesktop Secret Service interface this library implements. See §7.5 for the Flatpak/TPM tension.

**Limitations.** The portal exposes Secret Service-shaped operations only; advanced operations (custom collections, attribute search) are not supported. The hardened wrapper layer this library provides cannot run inside the portal-sandboxed mode because the portal hides the underlying daemon.

### 3.14 Unseal-password delivery (TPM provider)

**What it does.** With `Tpm2KeyMaterialProvider` the pepper is never stored — at rest there is only the TPM-wrapped blob, useless without the physical chip plus the unseal password (wrong guesses hardware-rate-limited by the DA lockout). The remaining design decision is how the *unseal password* reaches the process at startup; the choice determines how much of the TPM's class-C guarantee survives operational reality.

**Threat coverage.** The password is one of two factors, so its handling never has to carry class C alone: even a leaked password is useless off-host. Delivery choice mainly affects whether class B can read it (file modes) and whether a human is in the loop against class A.

**How to apply.** Ranked for a desktop (full reasoning in `usage_examples.md` §9.1): (1) interactive prompt — nothing persisted, human-in-the-loop, no autostart; (2) login keyring — autostart-friendly, and the offline thief still lacks the TPM, so class C survives; class A was already `PARTIAL`; (3) systemd `LoadCredentialEncrypted=` for services (user-scoped credentials need systemd ≥ 256); (4) a 0600 file as the floor. Never argv (see the `Tpm2Provisioner` history) and never env vars (`/proc/<pid>/environ`, §2.1). Do **not** park the password in a KeePassXC database: a locked `.kdbx` fails your startup closed, and if KeePassXC is also the Secret Service backend the password co-locates with the ciphertexts it protects.

**Limitations.** None of these mediate class A — a same-UID process reads the password wherever the legitimate process can (or the unsealed pepper from the JVM heap, §2.1). Same-UID confinement remains the job of MAC policy on `/dev/tpmrm0` (§3.4, §3.5, §3.12).

---

## 4. D-Bus policy in detail

D-Bus has two buses with different security postures. Knowing the difference matters because **Secret Service is on the session bus** — and the session bus's policy surface is fundamentally limited.

### 4.1 System bus vs session bus

| | System bus | Session bus |
|---|---|---|
| Daemon address | `unix:path=/var/run/dbus/system_bus_socket` | `unix:path=$XDG_RUNTIME_DIR/bus` |
| Runs as | `messagebus` / `dbus-daemon` system user | The user themselves |
| Policy files | `/etc/dbus-1/system.d/*.conf` (admin), `/usr/share/dbus-1/system.d/*.conf` (vendor) | `/etc/dbus-1/session.d/*.conf`, `/usr/share/dbus-1/session.d/*.conf`, `~/.config/dbus-1/session.d/*.conf` |
| Default policy | Deny-by-default; vendors must explicitly allow access | Allow-by-default for the user's own UID; cross-UID access is rare |
| Used by | systemd, NetworkManager, polkit, udisks2 | gnome-shell, **gnome-keyring**, **KeePassXC**, pipewire |

**Secret Service is session-bus-only.** No `/etc/dbus-1/system.d/` configuration applies to it.

### 4.2 Session-bus policy XML

Policy file structure (see `dbus-daemon(1)`):

```xml
<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy context="default">
    <allow send_destination="org.freedesktop.secrets"/>
  </policy>
  <policy user="alice">
    <allow send_destination="org.freedesktop.secrets" send_interface="org.freedesktop.Secret.Service"/>
  </policy>
  <policy user="untrusted-sandbox-user">
    <deny send_destination="org.freedesktop.secrets"/>
  </policy>
</busconfig>
```

Policies match on `<policy context="default|mandatory">`, `<policy user="…">`, `<policy group="…">`, or `<policy at_console="true">`. Inside, rules use `<allow>` or `<deny>` with attributes like `send_destination`, `send_interface`, `send_member`, `send_path`, `eavesdrop`, `own`.

### 4.3 What you can policy-control

- **Deny cross-UID access entirely.** A `<policy user="malicious-uid"><deny send_destination="org.freedesktop.secrets"/></policy>` block stops class B from talking to the daemon.
- **Restrict to specific interfaces.** Allow `org.freedesktop.Secret.Service` but deny `org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface` so even legitimate clients can't reach the privileged GNOME-specific surface.
- **Restrict bus name ownership.** `<deny own="org.freedesktop.secrets"/>` for everyone except the daemon binary's UID prevents an attacker from squatting the bus name.
- **Block eavesdropping.** Deny `eavesdrop="true"` (rarely needed; only `dbus-monitor`-style tools care).

### 4.4 What you cannot policy-control

- **Same-UID access (class A).** The session bus runs as the user; the user can rewrite `~/.config/dbus-1/session.d/*.conf`, restart the bus, or just connect with the right credentials. Session-bus policy is **not** a class-A defense.
- **Replacement of the daemon.** A class-A attacker can launch their own dbus-daemon and arrange for legitimate clients to connect to it. Defenses against that live in MAC, not in dbus-daemon's own policy.

**Headline:** session-bus policy buys you defense against class B (cross-UID via leaked `DBUS_SESSION_BUS_ADDRESS`) and against accidental cross-app interactions. It does not meaningfully constrain class A.

### 4.5 Polkit interplay

Polkit (formerly PolicyKit) gates D-Bus method calls behind authorisation rules — typically prompting the user via an agent (`gnome-shell`, `pkexec`, `lxpolkit`). Standard freedesktop Secret Service does **not** require polkit; the daemon's own auth (collection unlock prompt) is internal.

The library's deferred-loaded `org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface` interacts with polkit on some distributions (mostly for the `unlockWithMasterPassword` admin operation). If you carry a polkit policy that restricts this interface, the library tolerates the deferred-load failure cleanly.

### 4.6 KeePassXC's per-item ACL prompt

KeePassXC's Secret Service implementation is the only Secret Service backend that defends against **class A** without requiring MAC. When an unknown caller asks for an item, KeePassXC prompts the user interactively before exposing the secret. This is finer-grained than D-Bus policy can express (D-Bus matches on bus name / interface / member, not on bus-name → KeePass-database-item).

See §5 for the full backend comparison.

### 4.7 dbus-broker

`dbus-broker` is the systemd-blessed replacement for the reference `dbus-daemon`. Default in Fedora ≥ 30, Arch, RHEL ≥ 9. It uses the **same policy XML format** as `dbus-daemon`, so everything in §4.2–§4.4 applies identically. Faster, more memory-efficient, but the security surface is unchanged.

### 4.8 Worked example: deny class-B sidecar from the session bus

Scenario: a user-session daemon runs as `alice`; a containerised CI agent runs as `ci-agent` on the same host and shouldn't reach `alice`'s gnome-keyring.

1. Make sure `ci-agent`'s container does NOT bind-mount `/run/user/$ALICE_UID`.
2. Drop a session-bus policy fragment for safety:

   `~alice/.config/dbus-1/session.d/30-deny-ci.conf`:
   ```xml
   <busconfig>
     <policy user="ci-agent">
       <deny send_destination="org.freedesktop.secrets"/>
     </policy>
   </busconfig>
   ```
3. Verify with `dbus-send --session --dest=org.freedesktop.secrets …` from `ci-agent`'s context — should fail with `org.freedesktop.DBus.Error.AccessDenied`.

This is the canonical class-B mitigation. It does nothing for class A.

---

## 5. Secret Service backend choice

The library is the *client* of the freedesktop Secret Service API. The *daemon* on the other end of the session bus is one of:

- **gnome-keyring-daemon** (default on GNOME-based desktops, also used headless via `gnome-keyring-daemon --daemonize`)
- **KeePassXC** with the "Enable Secret Service Integration" plugin
- (Less common) `pass-secret-service`, `kdewallet5` via `keychain` shim, custom implementations

The library's CHANGELOG already notes that `org.gnome.keyring` is deferred-loaded so it works on non-GNOME backends, and `vision.md` calls out KeePassXC as a target backend. The choice has real security consequences.

### 5.1 gnome-keyring vs KeePassXC at a glance

| Property | gnome-keyring | KeePassXC |
|---|---|---|
| **At-rest format** | `~/.local/share/keyrings/<name>.keyring` (binary, AES-128 by default) | `~/Documents/<vault>.kdbx` (Argon2 + AES-256 / ChaCha20) |
| **Unlock model** | PAM-unlocked at login; remains unlocked for the whole session | User unlocks the database explicitly; can auto-lock on idle / lock screen |
| **Class-A defense** | NONE — once unlocked, anything same-UID gets items | **PARTIAL — interactive per-item access prompt** (configurable: ask once per app, ask every time, deny by default) |
| **Per-item ACLs** | None | Yes — per database group, per item, per requester |
| **Master-password strength** | Equivalent to login password (often weak) | Independent, typically stronger; supports key file + YubiKey challenge-response as additional factors |
| **Cross-platform** | Linux only | Linux / Windows / macOS (Secret Service integration is Linux-only) |
| **Default on** | Ubuntu, Fedora, Debian (with GNOME) | Anywhere the user installs it |

### 5.2 Class-by-class comparison

| Class | gnome-keyring (alone) | KeePassXC (alone) | gnome-keyring + hardened wrapper | KeePassXC + hardened wrapper |
|---|---|---|---|---|
| **A** | NONE | PARTIAL (interactive prompt) | PARTIAL (only if pepper TPM-sealed + MAC) | **PARTIAL → REAL** when stacked: interactive prompt + opaque envelope + TPM unseal |
| **B** | PARTIAL (depends on file modes + bus permissions) | PARTIAL | REAL with file mode 0600 | REAL |
| **C** | NONE if pepper colocated; PARTIAL otherwise | PARTIAL (Argon2 KDF over the .kdbx is real cost) | **REAL** with TPM provider | **REAL** (two layers: KDBX + envelope) |
| **D** | NOT_APPLICABLE for local-only | NOT_APPLICABLE | REAL when PQ enabled and ciphertext leaves host | REAL |

### 5.3 Stacking: hardened wrapper on top of either backend

The hardened wrapper runs the *envelope*, not the *daemon*. It treats whichever Secret Service implementation is on the bus as opaque storage. Two stacking effects:

1. **gnome-keyring + hardened**: items in `~/.local/share/keyrings/login.keyring` become opaque AES-256-GCM ciphertext. Even when the keyring is unlocked (which it always is on a logged-in GNOME desktop), the daemon cannot decrypt them. A class-A attacker who walks up to the bus and asks for an item gets ciphertext, not plaintext. They still need to ptrace the JVM or open `/dev/tpmrm0` to advance — and that's where MAC + memory hygiene help.

2. **KeePassXC + hardened**: triple defense. KeePassXC asks the user before exposing any item to a previously-unknown bus client (defeats class A passively); the hardened envelope is opaque to KeePassXC itself (defeats class A even if the user clicks "allow"); the TPM unseal is bound to the host (defeats class C even if the .kdbx file is exfiltrated). Each layer has independent failure modes — no single misconfiguration loses everything.

### 5.4 Recommendation

- **Server / headless**: backend doesn't matter much for the library's purposes; use whatever the distro packages and run it under a dedicated UID that isn't shared with anything else. The hardened wrapper carries most of the weight.
- **Linux desktop deployments**: prefer **KeePassXC** as the backend. Its per-item ACL prompt is the only realistic class-A defense available without operator-installed MAC, and it stacks well with the hardened wrapper.
- **Cross-platform applications**: this library is Linux-only. On Windows/macOS use the platform OS keychain directly.

---

## 6. LUKS / full-disk encryption

LUKS deserves its own section because it is the foundation for class-C defense and it interacts with the TPM in non-obvious ways.

### 6.1 What LUKS covers

| Class | Coverage | Why |
|---|---|---|
| A | NONE | The system is running, the volume is unlocked. Same-UID processes see the decrypted FS. |
| B | NONE | Same UID or different UID, both processes see the same decrypted FS. |
| **C** | **REAL** | Disk at rest is opaque. Stolen laptop = no plaintext. |
| D | NOT_APPLICABLE | Network adversary doesn't have the disk. |

LUKS is necessary but not sufficient. It defeats class C only when the disk is **actually at rest** — laptop closed and powered off, drive removed, decommissioned, *or* the LUKS volume dismounted. A running machine with LUKS unlocked is class-C-equivalent to a machine with no LUKS.

### 6.2 Where the keyring file lives

- gnome-keyring: `~/.local/share/keyrings/login.keyring` (and other named collections).
- KeePassXC: wherever the user put the `.kdbx` file (typically `~/Documents/Passwords.kdbx`).
- Hardened wrapper: items live inside whichever Secret Service backend you use; only the *envelope ciphertext* is stored. The TPM sealed-blob lives at a path you choose (recommended: `~/.config/secret-service/hardened/pepper.tpm2blob`, mode 0600).

All of these are on the encrypted root partition under a typical Linux install. None require special LUKS configuration beyond "encrypt the whole disk."

### 6.3 TPM-bound LUKS (`systemd-cryptenroll --tpm2-device=auto`)

This is a feature where LUKS unlocks itself at boot using a key sealed in the TPM (typically PCR-bound). Pros: no passphrase prompt, frictionless boot. Cons: requires Secure Boot + measured boot to be meaningful — without those, an attacker who replaces your initrd unlocks the disk just by booting.

**Important distinction**: TPM-bound LUKS and the hardened wrapper's `Tpm2KeyMaterialProvider` are independent uses of the TPM. You can run either, both, or neither. They protect different things:

| | TPM-bound LUKS | Hardened wrapper TPM provider |
|---|---|---|
| Protects | Block-device contents at rest | Application-layer pepper |
| Threat addressed | C (offline disk) | C (backup of `~`) plus B (cross-UID readers of the pepper file) |
| Failure if TPM lost | Disk unrecoverable without recovery key | Wrapper unrecoverable; secrets lost |
| Failure if PCR changes (kernel update) | Disk needs `systemd-cryptenroll --recovery-key` | Wrapper unaffected (we use password policy, not PCR policy in v1) |

If you only do one: **TPM-bound LUKS is more impactful for class C** (it covers everything on the disk, not just the keyring). The hardened wrapper's TPM provider is the right next step when the threat extends beyond "stolen physical disk" to "exfiltrated home directory backup."

### 6.4 Swap and hibernation

- **Swap encryption** is a silent prerequisite. Without it, `mlockall` is the only thing standing between plaintext in RAM and plaintext on disk. Configure either via LUKS-encrypted swap (persistent) or `crypttab` random-key swap (re-keyed each boot, breaks hibernation).
- **Hibernation** writes the entire RAM (every byte your process owns, including unsealed peppers and DEKs) to a swap file or partition. If that swap is unencrypted, hibernation defeats every other class-C mitigation. Either encrypt the swap or disable hibernation (`systemctl mask hibernate.target`).

### 6.5 Filesystem snapshots — the silent class-C path

Btrfs / ZFS / LVM snapshots run in kernel and can be read by an attacker who has root or a snapshot-readable user (`btrfs subvolume`-permitted user). Class C effectively reaches the snapshot even if the live FS is locked.

**Two practical hazards:**

1. Backup tools that snapshot before backing up (Timeshift, Snapper, Borg) — the snapshot persists on the same disk. If LUKS is unlocked and the snapshot is readable, class C reaches the snapshot.
2. Container build pipelines that retain layer caches (`overlayfs` upper dirs) — secrets baked into a build layer get baked into the cached layer, even after the file is "deleted" in a later layer.

**Practical guidance**: never build container images with secrets present in any layer; always use Docker BuildKit secret mounts or equivalent. For desktop snapshot tools, configure them to exclude `~/.local/share/keyrings/` and the TPM blob path.

---

## 7. Desktop App consumer scenarios

You are building a Linux desktop application that depends on `de.swiesend:secret-service` to read or write user secrets via the Secret Service daemon. Your users run a typical Linux desktop with `gnome-keyring-daemon` or KeePassXC providing the bus. The threats you must care about are dominated by **class A** (the CVE-2018-19358 same-UID attacker — a malicious `.desktop` file, a compromised browser extension, a curl|sh script the user ran an hour ago) and **class C** (the laptop gets stolen). Class B and D apply at the margins.

Step by step, by distribution format. For each: *what your users get out of the box*, *what you must add*, *what your library configuration should look like*, and *what to verify before shipping*.

### 7.1 Plain binary archive (`tar.gz` / `zip`)

**What this looks like.** A tarball containing `bin/yourapp`, `lib/yourapp.jar`, `lib/<deps>.jar`, optional `share/yourapp/`. The user extracts somewhere (often `~/Apps/yourapp/`) and runs `bin/yourapp`.

**What your users get.** Whatever the host provides — distro defaults. No MAC profile because there is no install path. No systemd integration. The launcher script is your only place to set JVM hardening flags.

**What you must add to the launcher (`bin/yourapp`):**

```bash
#!/bin/sh
set -eu
ulimit -c 0    # no core dumps
exec java \
    -XX:+DisableAttachMechanism \
    -XX:-HeapDumpOnOutOfMemoryError \
    -Djava.security.egd=file:/dev/urandom \
    -jar "$(dirname "$0")/../lib/yourapp.jar" "$@"
```

**Library configuration.** Use `EnvVarKeyMaterialProvider` for the pepper read from a config file, or `Tpm2KeyMaterialProvider` if you ship a `--init` step that runs `Tpm2Provisioner` on first launch. Backend: whatever is on the bus (gnome-keyring or KeePassXC).

**Class coverage.**

| Class | Without operator hardening | With your launcher's `-XX` flags |
|---|---|---|
| A | NONE | PARTIAL — JVM attach blocked; ptrace still works |
| B | NONE | NONE |
| C | depends on user's LUKS | same |
| D | NOT_APPLICABLE for local-only | same |

**Pitfalls.**
- No place to ship a systemd-user unit, AppArmor profile, or D-Bus policy. Document them in your README so power users can wire them up.
- Users *will* `wget | tar` your release; no signing, no integrity check by default. Ship `.tar.gz.sig` + a public key in the README.

**Ship-readiness check.**
```sh
shellcheck bin/yourapp        # lint launcher
sha256sum yourapp-3.0.0.tar.gz > yourapp-3.0.0.tar.gz.sha256
```

### 7.2 Self-contained JAR (`java -jar yourapp.jar`)

**What this looks like.** A single `yourapp.jar` (Maven Shade / shadowJar / jlink runtime image). User runs `java -jar yourapp.jar`.

**What your users get.** Even less than §7.1 — no launcher means no place for `ulimit -c 0` or `-XX:+DisableAttachMechanism` unless the user reads your README and types them in by hand.

**Library configuration.** Same as §7.1. Add a runtime `mlockall` call via JNA early in `main()` so memory hygiene at least partially holds without operator help — see §3.9 for details and the `CAP_IPC_LOCK` requirement.

**Class coverage.** Same as §7.1, *minus* the launcher-set JVM flags. Effectively no improvement over a vanilla `java -jar`.

**Pitfalls.**
- Shadow-JAR'ing `bcprov-jdk18on` (BouncyCastle) into your fat JAR can trip JCE provider signing requirements at runtime. Test on a vanilla JDK 25 install, not just your dev box.
- `java -jar` ignores `-XX` flags before the `-jar` argument unless the user types them.

**Ship-readiness check.**
```sh
mvn package
java -jar target/yourapp-3.0.0.jar --version  # smoke test on JDK 25
```

**Recommendation.** Use §7.3 (jpackage) instead of §7.2 for desktop apps — it gives you the launcher and the install path for free.

### 7.3 jpackage-built `.deb` / `.rpm`

**What this looks like.** `jpackage` (bundled with JDK 17+) takes your runtime image and produces a native `.deb`, `.rpm`, `.dmg`, or `.exe`. Linux output: a proper system package with `/usr/bin/yourapp`, `/usr/lib/yourapp/`, `/usr/share/applications/yourapp.desktop`, optional systemd-user unit. **This is the right answer for Linux desktop distribution.**

**Sample invocation.**
```sh
jpackage \
    --type deb \
    --name yourapp \
    --app-version 3.0.0 \
    --vendor "Your Org" \
    --description "Description" \
    --linux-shortcut \
    --input target/distribution \
    --main-jar yourapp.jar \
    --main-class com.example.Main \
    --java-options "-XX:+DisableAttachMechanism" \
    --java-options "-XX:-HeapDumpOnOutOfMemoryError" \
    --linux-package-deps "libsecret-1-0, dbus-x11"
```

**What your users get.** A native package signed and installable via `apt`/`dnf`. Distro hooks fire: `apparmor_parser` picks up profiles you ship in `/etc/apparmor.d/`, `restorecon` labels your binary for SELinux. `systemctl --user enable yourapp.service` works if you ship a `--linux-service` unit.

**What you must add to the package.**
- `/etc/apparmor.d/usr.bin.yourapp` (see §9.5 — copy-paste, adjust the binary path).
- `/usr/share/dbus-1/session.d/yourapp.conf` if you want to lock down which UIDs talk to Secret Service.
- `debian/postinst` runs `apparmor_parser -r /etc/apparmor.d/usr.bin.yourapp` for systems without the auto-hook.
- Optional `/etc/udev/rules.d/99-yourapp-tpm.rules` to give the user's primary group TPM access.

**Library configuration.** `Tpm2KeyMaterialProvider` is the recommended default here because:
1. The install path is well-known so `pepper.tpm2blob` lives somewhere predictable (`~/.config/yourapp/pepper.tpm2blob`).
2. `Tpm2Provisioner` can run as a systemd-user oneshot on first launch.
3. The AppArmor profile you ship covers `/dev/tpmrm0` access.

**Class coverage.**

| Class | Coverage |
|---|---|
| A | **REAL** with shipped AppArmor profile + interactive KeePassXC backend |
| B | **REAL** with shipped D-Bus policy fragment |
| C | **REAL** with TPM-bound pepper (TPM-bound LUKS recommended on top) |
| D | NOT_APPLICABLE for local-only apps |

**Pitfalls.**
- Two binaries means two MAC profiles. If you bundle a JRE in the package, point the AppArmor profile at the bundled `java`, not `/usr/bin/java`.
- jpackage's launcher is a tiny C binary; AppArmor must allow it to `exec` the bundled JVM.

**Ship-readiness check.**
```sh
lintian yourapp_3.0.0_amd64.deb
apparmor_parser -Q /etc/apparmor.d/usr.bin.yourapp  # syntax check on built profile
systemd-analyze verify build/yourapp.service        # if you ship a unit
```

### 7.4 AppImage

**The single root cause.** AppImage has no install path. The user `chmod +x`-es a self-extracting squashfs that mounts at runtime in `/tmp/.mount_xxxxxx/` (a randomised path that changes every run) and unmounts when the process exits. **AppImage's defining feature — no install path — is exactly what every Linux security framework needs to attach a policy. For an app that handles secrets, that's the whole problem.**

**What this means concretely.**

- **No AppArmor / SELinux profile.** Both are path-based; the AppImage's binary lives at a randomised mount point, so you cannot ship a profile that confines it.
- **No D-Bus policy fragment.** Session-bus drop-in lives in `/usr/share/dbus-1/session.d/`; an AppImage isn't "installed" so there is nowhere to register one.
- **No systemd unit.** No place for the rich `Protect*=` / `Restrict*=` / `SystemCallFilter=` directives that §3.10 leans on.
- **No udev rule.** No place to scope `/dev/tpmrm0` access to your binary specifically.
- **No package signing in practice.** AppImage's embedded GPG-signature option exists but almost no user or updater verifies it.

**Class coverage.** Same as §7.1 (plain `tar.gz`) *minus* the launcher script — some AppImage builders rewrite the entrypoint, so even the `-XX:+DisableAttachMechanism` flag from §7.1 is not guaranteed. NONE for A/B, depends-on-host for C.

**Asymmetry vs Flatpak / Snap (the other "single-file portable" formats).** AppImage's lack of a stable install path means it can talk to the TPM directly (no sandbox to break) — but it also means it has no other defenses. Flatpak and Snap make a tradeoff (give up some flexibility, gain a sandbox); AppImage makes neither half of that tradeoff.

**When AppImage is fine.** One-off troubleshooting tools, image/video editors, portable USB-stick apps, demos and pre-release builds, bridging old distros via bundled `glibc`. The "no install" property is a feature for those use-cases.

**When it is not.** Any app whose threat model includes class A or class B (per §2). For those, AppImage gives you nothing the OS can attach guards to.

**Recommendation.** Avoid AppImage for secret-handling desktop apps. Use §7.3 (jpackage `.deb`/`.rpm`) when class-A defense matters; §7.6 (Snap) when you also want strict-confinement plus first-class TPM via the `tpm` interface.

### 7.5 Flatpak

**What this looks like.** A `.flatpak` bundle distributed via Flathub or your own repo. Users `flatpak install`. The app runs in a bubblewrap sandbox with portal-mediated access to host resources.

**What your users get.** Strong sandbox by default. No host filesystem, no host network, no devices, no access to the host session bus — unless you explicitly opt each in via `finish-args` in the manifest.

**The TPM tension.** `/dev/tpmrm0` is **not exposed via any Flatpak portal**. To use the hardened wrapper's `Tpm2KeyMaterialProvider` from inside Flatpak, you must declare `--device=all` in your manifest, which gives access to *every* device node and effectively defeats the device-isolation half of the sandbox. **This is the single biggest reason Flatpak and the hardened wrapper do not pair well.**

**The two honest options.**

1. **Use the Flatpak portal instead of this library's wrapper.** `xdg-desktop-portal-secret` exposes Secret Service-shaped operations through the portal, with interactive user-consent prompts as the class-A defense. Your app talks to the portal, not the daemon — and not to this library at all for secret access. Manifest:
   ```yaml
   finish-args:
     - --talk-name=org.freedesktop.portal.Secret
     - --filesystem=xdg-data/yourapp:create
     # NO --device=all, NO --socket=session-bus
   ```
2. **Drop Flatpak for this app.** If your threat model demands TPM, ship via §7.3 (`.deb`/`.rpm`) and document why Flatpak isn't on the menu.

**Library configuration if you go with option 1.** You won't use `secret-service-hardened` or `secret-service-hardened-tpm2` from inside the Flatpak. The library is then irrelevant to the Flatpak'd build; consider conditionally compiling it out.

**Class coverage (option 1, portal-based).**

| Class | Coverage |
|---|---|
| A | PARTIAL — interactive portal prompt |
| B | REAL — Flatpak namespace isolation |
| C | depends on host LUKS |
| D | NOT_APPLICABLE |

**Pitfalls.**
- Don't request `--socket=session-bus` "just in case" — that gives full session-bus access and undoes the portal's class-A defense.
- The portal API is narrower than full Secret Service; advanced operations (custom collections, attribute search) are unavailable.

**Ship-readiness check.**
```sh
flatpak-builder --force-clean --user --install build-dir org.example.YourApp.yml
flatpak run --command=sh org.example.YourApp -c 'ls /dev/tpm* 2>&1'   # should fail / show no nodes
```

### 7.6 Snap

**What this looks like.** A `.snap` bundle distributed via the Snap Store. Users `snap install yourapp`. The app runs under AppArmor confinement with slot-based interfaces declared in `snapcraft.yaml`.

**What your users get.** AppArmor confinement, seccomp filter, namespace isolation. **Crucially, Snap has a `tpm` interface** — a first-class concept for granting TPM access without breaking the sandbox. This makes Snap the only mainstream Linux app-format that pairs cleanly with the hardened wrapper.

**Sample manifest fragment.**
```yaml
name: yourapp
base: core22
confinement: strict
apps:
  yourapp:
    command: bin/yourapp
    plugs:
      - tpm                   # /dev/tpmrm0 access via the TPM interface
      - secret-service-client # session-bus to org.freedesktop.secrets
      - home                  # user data
plugs:
  secret-service-client:
    interface: dbus
    bus: session
    name: org.freedesktop.secrets
```

`snap connect yourapp:tpm` (or auto-connect via store policy) wires up the device cgroup. The user gets confined desktop integration plus working TPM.

**Library configuration.** `Tpm2KeyMaterialProvider` works as expected; the sealed-blob lives at `$SNAP_USER_COMMON/pepper.tpm2blob` (typically `~/snap/yourapp/common/pepper.tpm2blob`).

**Class coverage.**

| Class | Coverage |
|---|---|
| A | PARTIAL — strict confinement; ptrace blocked by default seccomp |
| B | REAL — namespace + AppArmor |
| C | REAL with TPM provider; depends on host LUKS otherwise |
| D | NOT_APPLICABLE |

**Pitfalls.**
- Auto-connect for `tpm` requires store-team review; expect delay between manifest update and "just works for users."
- `snap install --classic` (classic confinement) **disables** all the above — only use it as a last resort, e.g. for ops tools that need raw filesystem access.

**Ship-readiness check.**
```sh
snapcraft --use-lxd
snap install --dangerous yourapp_3.0.0_amd64.snap
snap connections yourapp                  # should list tpm + secret-service-client
snap run yourapp --version                # smoke test
```

**Recommendation.** Snap is the **best Linux desktop format for secret-handling apps that benefit from the hardened wrapper + TPM**, especially when targeting Ubuntu / Ubuntu Core.

### 7.7 Nix / NixPkgs / Home Manager

**What this looks like.** A Nix derivation that produces a `/nix/store/<hash>-yourapp/` tree. NixOS / Home-Manager users add it to their config; non-NixOS users `nix-env -iA`.

**What your users get.** Reproducible builds, content-addressed store, `/nix/store` is read-only by construction. NixOS modules can declare a complete deployment (package + AppArmor profile + udev rule + D-Bus policy) in one Nix expression. Closest thing to "distribution and policy in one place."

**Library configuration.** Same as §7.3 — TPM provider is recommended, AppArmor profile shipped via the module's `security.apparmor.policies` option.

**Class coverage.** Equivalent to §7.3 (`.deb`/`.rpm`) for a NixOS user, plus reproducibility (mitigates supply-chain class of attack against the build).

**Recommendation.** Ship a Nix flake alongside §7.3 for the NixOS minority. Don't make Nix your only Linux distribution path — Nix-only desktop apps stay a niche.

### 7.8 Quick decision tree for desktop apps

```
Does your app handle real user secrets?
├── No  → AppImage is fine; ignore the rest of this section.
└── Yes
    ├── Do you need TPM-sealed pepper?
    │   ├── Yes → §7.3 (.deb/.rpm) preferred; §7.6 (Snap) viable.
    │   │        AVOID Flatpak (§7.5) — TPM tension.
    │   └── No  → §7.3 (.deb/.rpm) for OS integration; §7.5 (Flatpak via
    │             portal) for sandboxed cross-distro reach.
    └── Are users primarily on Ubuntu / Ubuntu Core?
        └── Strongly consider §7.6 (Snap) — best Linux sandbox + TPM.
```

The plain `tar.gz` (§7.1) and self-contained JAR (§7.2) remain useful for power-user releases and Java-savvy audiences but should not be your only Linux distribution channel for a secret-handling app.

---


## 8. CI Tool consumer scenarios

You are building a tool that runs in a continuous-integration or build/deploy pipeline and depends on `de.swiesend:secret-service` to fetch credentials, signing keys, registry tokens, or similar build-time secrets. The environment is fundamentally different from §7:

- **Headless** — no `$DBUS_SESSION_BUS_ADDRESS`, no `java.io.Console` for interactive prompts, no logged-in user. Most CI environments do not run a Secret Service daemon at all.
- **Ephemeral or daemonised** — either a one-shot job (GitHub Actions, GitLab CI, Jenkins agent, Buildkite) that lives for minutes and is then torn down, or a long-lived self-hosted runner / build agent serving many jobs.
- **Threat model dominated by:** class B (sidecar / cohabitating jobs leaking into yours), class C (job logs persisted by the platform, credential blobs left in build artifacts), and supply-chain attacks on the build itself. Class A is also relevant for self-hosted runners. Class D (HNDL) typically does not apply because secrets are short-lived.
- **Backends:** rarely a desktop keyring. Usually file-based providers reading credentials injected by the platform (env var, `--password-fd`, mounted file), or an external KMS / secret manager (HashiCorp Vault, AWS KMS, GCP Secret Manager) called via its own SDK — outside the scope of this library.

Step by step, by distribution format. The library can still help if you choose the right delivery shape.

### 8.1 Release JAR (Maven Central / GitHub Releases)

**What this looks like.** You publish the JAR; downstream pipelines depend on it via Maven/Gradle, or download a release artifact. The CI tool that consumes the JAR is itself the deployment unit.

**What the consumer gets.** Whatever the host JDK provides. No isolation, no MAC, no JVM flags unless the consumer's wrapper script sets them. The library's discipline (zeroing, callback-only API) is the entire defense.

**Library configuration.** `EnvVarKeyMaterialProvider` reading the pepper from an env var the CI platform injects (`SECRET_SERVICE_PEPPER`), or a file-based provider reading from a mounted file. The TPM provider is rarely available in CI; if your self-hosted runner has a TPM, document it as an opt-in.

**Class coverage.**

| Class | Coverage |
|---|---|
| A | NONE — anything on the runner shares your trust domain |
| B | NONE — sibling jobs see your `/proc/<pid>/environ` |
| C | depends entirely on whether the runner persists job state |
| D | NOT_APPLICABLE for short-lived secrets |

**Pitfalls.**
- Build logs are the most underestimated class-C path. `mvn -X` echoes env vars; many CI platforms retain logs for 90+ days; some make logs public. Make sure the library never logs the pepper or DEK (it doesn't, but verify with `grep -ri pepper logs/`).
- Test code that prints `System.getenv()` for debugging finds its way into a release. Ban `System.out.println(env)` patterns at PR-review time.

**Ship-readiness check.**
```sh
mvn deploy -DperformRelease=true
# After release, simulate consumer integration:
mkdir -p /tmp/consumer && cd /tmp/consumer
echo '<dependency>...</dependency>' > pom.xml  # template
mvn dependency:tree | grep -i secret-service
```

### 8.2 Distribution package (`.deb` / `.rpm`) for self-hosted runner

**What this looks like.** A self-hosted GitHub Actions runner, GitLab Runner, or Jenkins agent installed as a long-lived systemd service on a dedicated VM. Your tool is part of the runner's image or installed as a system package.

**What the consumer gets.** Real systemd hardening (§3.10 directive set), AppArmor/SELinux integration (§3.4–§3.5), persistent state outside `~/.local/share/` (typically `/var/lib/<runner>/`).

**Sample systemd unit fragment for the runner agent.** This is more aggressive than §7.3 because the daemon is fully headless and never needs to spawn child desktop processes:

```ini
[Service]
User=ci-runner
Group=ci-runner
SupplementaryGroups=tss
ExecStart=/usr/bin/java -jar /usr/lib/ci-runner/agent.jar
LimitCORE=0
LimitMEMLOCK=infinity
AmbientCapabilities=CAP_IPC_LOCK
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
DeviceAllow=/dev/tpmrm0 rw
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=true
LockPersonality=true
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @ptrace
SystemCallArchitectures=native
ReadWritePaths=/var/lib/ci-runner
```

**Library configuration.** `Tpm2KeyMaterialProvider` is realistic here because the runner VM has stable hardware. Provision via `Tpm2Provisioner --password-fd 3 3<<<"$RUNNER_PEPPER_PASSWORD"` from a one-shot install hook; the password lives in the cloud provider's instance metadata or a dedicated secret store, never on disk.

**Class coverage.** REAL for A/B/C with the unit above, the AppArmor profile from §9.5, and per-job UID isolation (one job → one ephemeral UID). Your CI orchestrator's job-level isolation does the heavy lifting; the systemd unit hardens the agent itself.

**Pitfalls.**
- Job-step processes inherit the agent's environment by default. Drop sensitive env vars before `Runtime.getRuntime().exec(...)` calls.
- `RestrictAddressFamilies=AF_UNIX` breaks runners that need network access for artifact upload; widen to `AF_UNIX AF_INET AF_INET6` as needed.

**Ship-readiness check.**
```sh
systemd-analyze verify ci-runner.service
systemd-analyze security ci-runner.service   # target ≥ "OK" / score ≤ 4.0
```

### 8.3 OCI container (Docker, Podman, k8s) — the dominant CI format in 2026

**What this looks like.** A `Dockerfile` that bakes your tool + a runtime JDK; the image runs as a CI step (`docker run`, `kubernetes pod`, `tekton task`). One image = one job.

**What the consumer gets.** Default Docker security profile: namespaces, seccomp default, capability drop, cgroup device deny-all. Strong class-B defense between concurrent jobs by construction.

**The Secret Service tension in containers.** Your container does **not** have a session bus. The Secret Service daemon is on the *host*'s bus, which the container cannot reach unless you bind-mount `$XDG_RUNTIME_DIR/bus` — and doing so undoes most of the container's class-A/B defense. **In practice, CI containers should not use Secret Service at all.** Read your secrets from:

- An env var injected by the orchestrator (`docker run -e`, `kubernetes envFrom: secretRef`, GitHub Actions `env:`).
- A mounted file (`docker run -v /run/secrets/pepper:/run/secrets/pepper:ro`, k8s `secret` volume).
- An external secret manager via its SDK (Vault, AWS Secrets Manager).

Use this library's `Tpm2Availability.isAvailable()` preflight (§3.13 of `secret-service-hardened-tpm2`) to detect "no TPM here, fall back to file-based provider" gracefully.

**The TPM tension in containers.** `--device=/dev/tpmrm0` works in plain Docker but is **forbidden in most managed CI** (GitHub-hosted runners, GitLab.com SaaS runners, CircleCI). On self-hosted Kubernetes you can device-plugin through, but it's per-cluster ops work. Plan for "no TPM" as the CI default.

**Sample Dockerfile.**

```dockerfile
FROM eclipse-temurin:21-jre-jammy
RUN useradd -r -m -u 10001 ci-tool
USER ci-tool
ENV JAVA_TOOL_OPTIONS="-XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError"
COPY --chown=ci-tool:ci-tool target/ci-tool.jar /opt/ci-tool/ci-tool.jar
ENTRYPOINT ["java", "-jar", "/opt/ci-tool/ci-tool.jar"]
```

**Sample Kubernetes pod spec fragment.**

```yaml
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    seccompProfile: { type: RuntimeDefault }
  containers:
  - name: ci-tool
    image: ghcr.io/example/ci-tool:3.0.0
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities: { drop: ["ALL"] }
    env:
    - name: SECRET_SERVICE_PEPPER
      valueFrom:
        secretKeyRef: { name: ci-tool-secrets, key: pepper }
```

**Class coverage.**

| Class | Coverage |
|---|---|
| A (host-level admin) | NONE — `kubectl exec` / `nsenter` bypass |
| B (sibling pods/containers) | REAL — namespaces |
| C (image layers retain secrets) | REAL only if you use BuildKit secret mounts |
| D | NOT_APPLICABLE |

**Pitfalls.**
- **Never** `RUN echo $SECRET > /opt/.config` in a Dockerfile — the secret persists in a layer forever, even if a later layer deletes the file. Use `--mount=type=secret` (BuildKit).
- `kubectl logs` retains everything written to stdout. Configure SLF4J to send sensitive paths to a file appender that the runtime tears down with the pod.
- A `readOnlyRootFilesystem: true` container cannot write `/tmp` for the JVM; mount an `emptyDir { medium: Memory }` at `/tmp` so plaintext temp files at least never hit disk.

**Ship-readiness check.**
```sh
docker build --no-cache -t ci-tool:test .
docker run --rm --read-only --cap-drop=ALL --user=10001 ci-tool:test --version
trivy image ci-tool:test    # CVE scan
hadolint Dockerfile         # lint
```

### 8.4 GitHub Actions / GitLab CI integration

**What this looks like.** You ship your CI tool as a reusable action (GH `action.yml` Docker or composite action, GitLab `include:` template). The platform's secret store injects credentials.

**Sample GitHub Actions Docker action (`action.yml`).**

```yaml
name: 'Run secret-service tool'
inputs:
  pepper:
    description: 'KeyMaterialProvider pepper'
    required: true
runs:
  using: 'docker'
  image: 'docker://ghcr.io/example/ci-tool:3.0.0'
  env:
    SECRET_SERVICE_PEPPER: ${{ inputs.pepper }}
```

**Caller workflow:**
```yaml
- uses: example/ci-tool@v3
  with:
    pepper: ${{ secrets.PEPPER }}     # GH Actions secret store
```

**Sample GitLab CI fragment.**

```yaml
variables:
  SECRET_SERVICE_PEPPER: $PEPPER     # injected from GitLab CI variables (masked, protected)

ci-tool-job:
  image: ghcr.io/example/ci-tool:3.0.0
  script:
    - java -jar /opt/ci-tool/ci-tool.jar fetch
```

**Library configuration.** `EnvVarKeyMaterialProvider` reading `SECRET_SERVICE_PEPPER`. The library's loud warning at construction is appropriate: env-var pepper is class-A theatre. In CI that's acceptable because the CI runner *is* the trust boundary — there is no other class-A actor to defend against. Document this loudly so a copy-pasted snippet does not migrate to a desktop deployment.

**Pitfalls.**
- **GH Actions auto-masks the literal value of `secrets.PEPPER`** in logs, but only the literal string. If your tool transforms it (`base64 -d`, splits, hashes) the *transformed* form is unmasked. Use the raw secret end-to-end.
- GitLab CI's "masked" variables only mask values that are 8+ characters and pass a charset check. A short or special-character pepper unmasks silently.
- Forks of public repos do **not** receive secrets in PR/MR builds (by default). Test paths that depend on secrets must run only on `push` to the main repo.

**Ship-readiness check.**
```sh
act -W .github/workflows/test.yml --secret-file .secrets   # local GHA dry-run
gitlab-runner exec docker ci-tool-job --env-file .env      # local GitLab CI dry-run
```

### 8.5 Self-hosted long-running CI controller (Jenkins, Buildkite, Harness, …)

**What this looks like.** A controller process that schedules jobs, fetches credentials, signs artifacts. Typically runs as `systemd` on a dedicated VM behind a load balancer.

**What the consumer gets.** Same as §8.2 (`.deb`/`.rpm` self-hosted runner), but the controller talks to a real secret manager (Vault / KMS / cloud-native) over the network rather than reading peppers from disk.

**Library configuration.** Implement a custom `KeyMaterialProvider` that delegates to your secret manager's SDK; cache the unsealed pepper for the JVM lifetime, zero on shutdown. The library's `KeyMaterialProvider` SPI is designed for exactly this.

**Class coverage.** REAL for A/B/C provided the secret-manager SDK does its part (TLS, audit log, credential rotation). The library's role shrinks to "expose `char[] getPepper()`."

**Pitfalls.**
- Your `getPepper()` implementation is now on the hot path: every `withSecret` call hits it. Cache aggressively, refresh on rotation events.
- Don't forget to zero the cached pepper on JVM shutdown — the library's `AutoCloseable` discipline applies to your custom provider too.

### 8.6 Snap classic confinement (rare; ops-tool edge case)

**What this looks like.** A `snap install --classic ci-tool`. Classic confinement disables AppArmor mediation — the snap runs with full filesystem and device access.

**Recommendation.** Almost never appropriate for CI tools. Classic confinement exists for things like `snapcraft` itself or `kubectl` that need raw filesystem access. If your tool can run under `confinement: strict` (§7.6), do that instead. If you must use classic, the security posture is identical to a `tar.gz` (§7.1) with worse update semantics.

### 8.7 Quick decision tree for CI tools

```
Is the CI environment ephemeral (one job, then torn down)?
├── Yes (typical GHA / GitLab.com / CircleCI)
│   ├── Use §8.3 (OCI container) + §8.4 (action wrapper).
│   ├── EnvVarKeyMaterialProvider reading platform-injected secret.
│   └── DO NOT try to use Secret Service or TPM here; they are not present.
└── No — it's a long-lived runner / controller
    ├── Self-hosted runner on dedicated VM → §8.2 (.deb/.rpm + systemd hardening).
    ├── TPM available on the runner → Tpm2KeyMaterialProvider.
    └── Centralised controller talking to KMS/Vault → §8.5 (custom KeyMaterialProvider).
```

The dominant honest path for CI is: **OCI container + platform-injected env-var pepper**. The hardened wrapper's class-A defense doesn't help against a CI platform compromise (the platform *is* class A in that environment). The wrapper's class-B defense via AEAD envelopes still matters when CI build artifacts are stored long-term — even if a later attacker exfiltrates them, the items are opaque.

---


## 9. Mitigation matrices and sample configurations

This section is the cross-cutting reference: the format-vs-class summary, the backend stacking summary, and — most useful as a quick lookup — the **mitigation-vs-environment matrix** that lets a downstream consumer pick a row (their environment) and read off which guards apply, partially apply, or are unavailable. Sample configurations follow as subsections §9.4–§9.12 and are referenced from §7 and §8.

### 9.1 Distribution format vs threat-class summary

| Format | Class A | Class B | Class C | Notes |
|---|---|---|---|---|
| Plain `tar.gz` (§7.1) / fat JAR (§7.2) | NONE | NONE | depends on user's LUKS | Operator owns the entire hardening story |
| jpackage `.deb`/`.rpm` (§7.3) | **REAL** with shipped AppArmor profile + KeePassXC | **REAL** with shipped D-Bus policy | **REAL** with TPM provider + LUKS | Distro-native; recommended for desktop apps |
| AppImage (§7.4) | NONE | NONE | depends on user's LUKS | Avoid for secret-handling |
| Flatpak (§7.5) — portal-only | PARTIAL — interactive portal | REAL — namespace + portal | depends on host LUKS | TPM unavailable; library mostly bypassed |
| Snap (§7.6) — strict confinement | PARTIAL — AppArmor + seccomp | REAL — namespace + AppArmor | REAL with TPM provider | Best Linux sandbox + TPM combination |
| Nix / NixOS (§7.7) | matches `.deb`/`.rpm` | matches `.deb`/`.rpm` | matches `.deb`/`.rpm` | Plus reproducibility |
| OCI container (§8.3) | NONE — host bypass | REAL — namespace | REAL with BuildKit secret mounts | Dominant in CI; TPM tension |
| `.deb`/`.rpm` self-hosted runner (§8.2) | **REAL** with hardened systemd unit | **REAL** with policy fragment | **REAL** with TPM provider | Best CI runner posture |

### 9.2 Backend stacking summary (from §5)

| Stack | Class A | Class B | Class C |
|---|---|---|---|
| gnome-keyring alone | NONE | depends on file modes | NONE if pepper colocated |
| KeePassXC alone | PARTIAL — interactive prompt | PARTIAL | PARTIAL — Argon2 KDF |
| gnome-keyring + hardened (TPM) | PARTIAL — needs MAC | REAL with file mode 0600 | **REAL** |
| **KeePassXC + hardened (TPM)** | **PARTIAL → REAL** stacked | **REAL** | **REAL** — two layers |

### 9.3 Mitigation-vs-environment matrix

The grid below maps each mitigation listed in §3 (plus the application-layer additions from §5/§7/§8) against the deployment environments downstream consumers actually ship into. Read it like a lookup table: pick your row (environment), read off which mitigations apply.

Legend:
- **✓** — available and recommended in this environment
- **◐** — partially available / partial value (see footnote below the table)
- **—** — not applicable in this environment (the threat model doesn't include the class this mitigation addresses)
- **✗** — unavailable / actively defeated by this environment's design

|  | Single-user desktop | Multi-user host | OCI container (CI / k8s) | Flatpak sandbox | Snap strict | Headless server (`.deb`/systemd) | Ephemeral CI job |
|---|---|---|---|---|---|---|---|
| **Storage** |  |  |  |  |  |  |  |
| LUKS / dm-crypt full-disk | ✓ | ✓ | ◐ host-only | ◐ host-only | ◐ host-only | ✓ | — short-lived |
| Encrypted swap / no-hibernate | ✓ | ✓ | — | — | — | ✓ | — |
| Filesystem snapshot exclusion list | ✓ | ✓ | — | — | — | ✓ | — |
| **File-system DAC** |  |  |  |  |  |  |  |
| Pepper / blob file mode 0600 | ✓ | ✓ | ◐ via secret mount | ◐ inside `~/.var/app/` | ◐ inside `$SNAP_USER_COMMON` | ✓ | ◐ tmpfs |
| Strict `umask 077` | ✓ | ✓ | ✓ via systemd `UMask=` | sandbox handles | sandbox handles | ✓ | ✓ |
| Different-UID file owner check | ✗ same UID | ✓ | ✓ | — | — | ✓ | ◐ runner UID |
| **Mandatory access control** |  |  |  |  |  |  |  |
| AppArmor / SELinux profile shipped with package | ✗ no install path (tar.gz) / ✓ (`.deb`) | ✓ | ✓ via container or host | sandbox MAC | ✓ first-class | ✓ | — |
| MAC restricting `/dev/tpmrm0` to your binary | ✓ if you ship the profile | ✓ | ◐ host-side only | ✗ portal-incompatible | ◐ via `tpm` interface | ✓ | — TPM rare |
| **POSIX capabilities** |  |  |  |  |  |  |  |
| `CAP_IPC_LOCK` granted (mlockall) | ◐ via systemd-user | ✓ | ◐ explicit `cap_add` | ✗ | ✓ via plug | ✓ | ◐ |
| `CAP_SYS_PTRACE` dropped from bounding set | ✓ | ✓ | ✓ default | ✓ | ✓ | ✓ | ✓ default |
| **Sandboxing primitives** |  |  |  |  |  |  |  |
| Linux namespaces (mount/PID/net/IPC) | — | ◐ via firejail | ✓ | ✓ | ✓ | ◐ via systemd `Private*=` | ✓ |
| seccomp-bpf syscall filter | ◐ via launcher | ◐ | ✓ default | ✓ | ✓ | ✓ via `SystemCallFilter=` | ✓ |
| cgroups v2 device controller for TPM | — | ✓ | ✓ | partial | ✓ | ✓ | ✗ |
| Read-only root filesystem | — | — | ✓ `--read-only` | ✓ | ✓ | ✓ via `ProtectSystem=strict` | ✓ |
| **JVM memory hygiene** |  |  |  |  |  |  |  |
| `-XX:+DisableAttachMechanism` | ✓ launcher | ✓ launcher | ✓ env | ✓ env | ✓ env | ✓ unit | ✓ env |
| `-XX:-HeapDumpOnOutOfMemoryError` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `mlockall(MCL_CURRENT|FUTURE)` via JNA | ◐ needs cap | ✓ | ◐ | ✗ | ✓ | ✓ | ◐ |
| `RLIMIT_CORE=0` / `ulimit -c 0` | ✓ launcher | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `prctl(PR_SET_DUMPABLE, 0)` | ✓ in main() | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **D-Bus posture** |  |  |  |  |  |  |  |
| Session-bus policy fragment denying class B | ◐ user-writable | ✓ | — bus rarely present | sandbox handles | ✓ via plug | ✓ | — |
| `xdg-desktop-portal-secret` via portal | — | — | ✗ | **✓** primary path | — | — | — |
| KeePassXC backend (interactive ACL) | ✓ — best class A | ✓ | ✗ | ✗ | ◐ requires user interaction | ◐ unattended is awkward | ✗ |
| **TPM (hardware root)** |  |  |  |  |  |  |  |
| `Tpm2KeyMaterialProvider` available | ✓ if hardware present | ✓ | ◐ if `--device=/dev/tpmrm0` | ✗ no portal | ✓ via `tpm` plug | ✓ | ✗ typically |
| TPM-bound LUKS (`systemd-cryptenroll`) | ✓ recommended | ✓ | — host-side | — | — | ✓ | — |
| Secure Boot + measured boot chain | ✓ | ✓ | — | — | — | ✓ | — |
| Dictionary-attack lockout (no `noDA` on seal) | ✓ baked into provider | ✓ | ✓ | — | ✓ | ✓ | — |
| **Application-layer (this library)** |  |  |  |  |  |  |  |
| AES-256-GCM envelope (hardened wrapper) | ✓ | ✓ | ✓ | ◐ via portal-only path | ✓ | ✓ | ✓ |
| Hybrid PQ KEM (X25519 + ML-KEM-768) — `enablePostQuantum(true)` | — class D rare | — | — usually | — | — | ✓ if archived (forward-secret via rotateEpoch) | ◐ if logs persist |
| `withSecret` / `matchesSecret` callback API | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `EnvVarKeyMaterialProvider` (theatre, but appropriate in CI) | ✗ class A | ✗ | ◐ honest CI default | ◐ portal substitute | ◐ | ✗ | **✓** primary CI path |

**Footnotes for the ◐ cells:**

- **LUKS in containers / sandboxes:** the host's LUKS protects the underlying disk; the container/sandbox cannot itself do FDE for its own filesystem layers, so the row is partial.
- **`umask 077` inside sandboxes:** the sandbox enforces tighter permissions than 077 by default, so the rule applies but is often redundant.
- **`CAP_IPC_LOCK` on systemd-user units:** newer systemd grants `CAP_IPC_LOCK` to user units when `LimitMEMLOCK=` is set, but older user-mode setups need a per-binary `setcap`.
- **MAC profile via Snap `tpm` interface:** the snap's confinement is enforced; `tpm` plug specifically grants `/dev/tpmrm0` device access, so the MAC story is "good enough" but operator-visible policy is the snap's, not a separate AppArmor file.
- **OCI / k8s + `--device=/dev/tpmrm0`:** works in self-hosted clusters and plain Docker; not available on most managed CI (GitHub-hosted runners, GitLab.com SaaS).
- **`mlockall` outside container UID-mapped mode:** `--cap-add=IPC_LOCK` is required; on Kubernetes that's a `securityContext.capabilities.add: ["IPC_LOCK"]`.
- **KeePassXC in headless server / CI:** the interactive prompt is a hard blocker in non-interactive contexts; either keep the database unlocked at startup (defeats class A) or pick a different backend.
- **EnvVarKeyMaterialProvider in desktop / multi-user:** any process running as the user reads `/proc/<pid>/environ`; the provider's Javadoc warning calls this out and the builder refuses it without `acknowledgeSecurityTheater(true)`.

**How to use this matrix.** Pick your environment column. Each ✓ row is a guard you should adopt; each ◐ row is a guard worth adopting once you understand the footnote; each ✗ row is unavailable — if your threat model requires the class that mitigation addresses (cross-reference §3), you need to change environments.

### 9.4 systemd unit (`/etc/systemd/system/secret-service-app.service`)

```ini
# Verify with: systemd-analyze verify secret-service-app.service
#              systemd-analyze security secret-service-app.service
[Unit]
Description=Secret Service Application
After=dbus.service tpm2.target
Requires=dbus.service

[Service]
Type=simple
User=secretsvc
Group=secretsvc
SupplementaryGroups=tss
ExecStart=/usr/bin/java \
    -XX:+DisableAttachMechanism \
    -XX:-HeapDumpOnOutOfMemoryError \
    -jar /usr/share/secret-service-app/app.jar
Restart=on-failure
RestartSec=5

# Memory hygiene
LimitCORE=0
LimitMEMLOCK=infinity
AmbientCapabilities=CAP_IPC_LOCK
CapabilityBoundingSet=CAP_IPC_LOCK

# Filesystem
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/secret-service-app
UMask=0077

# Devices
PrivateDevices=true
DeviceAllow=/dev/tpmrm0 rw
DevicePolicy=closed

# Kernel surface
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
ProcSubset=pid

# Process / namespace
NoNewPrivileges=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=false  # JIT compatibility; flip if your JVM tolerates it
RemoveIPC=true

# Network
RestrictAddressFamilies=AF_UNIX

# Syscalls
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @ptrace
SystemCallArchitectures=native
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
```

After dropping the unit: `systemctl daemon-reload && systemd-analyze security secret-service-app.service` (target score ≥ "OK").

### 9.5 AppArmor profile (`/etc/apparmor.d/usr.bin.java.secret-service-app`)

```
# Verify with: apparmor_parser -Q /etc/apparmor.d/usr.bin.java.secret-service-app
#              aa-status | grep secret-service-app
#include <tunables/global>

profile secret-service-app /usr/bin/java {
  #include <abstractions/base>
  #include <abstractions/dbus-session-strict>

  # JVM and JAR
  /usr/bin/java                                  rix,
  /usr/lib/jvm/**                                rmix,
  /usr/share/secret-service-app/app.jar          r,

  # Application data (writable)
  owner /var/lib/secret-service-app/             rw,
  owner /var/lib/secret-service-app/**           rwk,

  # TPM device
  /dev/tpmrm0                                    rw,
  /sys/class/tpm/**                              r,

  # D-Bus session bus
  /run/user/[0-9]*/bus                           rw,

  # Memory hygiene
  capability ipc_lock,

  # Deny everything else explicitly
  deny /home/** rwklx,
  deny /root/** rwklx,
  deny /etc/shadow r,
  deny capability sys_ptrace,
  deny ptrace,
  deny /proc/*/mem r,
  deny @{PROC}/[0-9]*/environ r,
}
```

Enable with `apparmor_parser -r /etc/apparmor.d/usr.bin.java.secret-service-app && aa-enforce secret-service-app`.

### 9.6 SELinux policy module (`secret_service_app.te`)

```
# Verify build with: checkmodule -M -m -o secret_service_app.mod secret_service_app.te
#                    semodule_package -o secret_service_app.pp -m secret_service_app.mod
# Install with:      semodule -i secret_service_app.pp
policy_module(secret_service_app, 1.0.0)

require {
    type tpm_device_t, init_t, user_runtime_t, dbus_session_bus_t, unconfined_t;
    class chr_file { read write open ioctl getattr };
    class dbus { send_msg acquire_svc };
    class file { read execute getattr open };
}

# Domain definition
type secret_service_app_t;
type secret_service_app_exec_t;
init_daemon_domain(secret_service_app_t, secret_service_app_exec_t)

# TPM access
allow secret_service_app_t tpm_device_t:chr_file { read write open ioctl getattr };

# D-Bus session bus
allow secret_service_app_t dbus_session_bus_t:dbus send_msg;

# Application data dir
type secret_service_app_var_lib_t;
files_type(secret_service_app_var_lib_t)
allow secret_service_app_t secret_service_app_var_lib_t:file { read write create unlink getattr };

# Deny ptrace from anywhere into us
neverallow * secret_service_app_t:process { ptrace };
```

After install: `restorecon -R /var/lib/secret-service-app /usr/share/secret-service-app && setsebool -P …` as needed.

### 9.7 D-Bus session-bus policy (`/usr/share/dbus-1/session.d/org.example.secret-service-app.conf`)

```xml
<!-- Verify with: dbus-daemon --session --print-address --check-policy
                                      (run as the target user) -->
<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <!-- Allow the service UID to talk to Secret Service -->
  <policy user="secretsvc">
    <allow send_destination="org.freedesktop.secrets"/>
    <allow send_destination="org.freedesktop.secrets"
           send_interface="org.freedesktop.Secret.Service"/>
    <allow send_destination="org.freedesktop.secrets"
           send_interface="org.freedesktop.Secret.Collection"/>
    <allow send_destination="org.freedesktop.secrets"
           send_interface="org.freedesktop.Secret.Item"/>
    <allow send_destination="org.freedesktop.secrets"
           send_interface="org.freedesktop.Secret.Session"/>
    <allow send_destination="org.freedesktop.secrets"
           send_interface="org.freedesktop.Secret.Prompt"/>
  </policy>

  <!-- Deny the privileged GNOME-specific surface to everyone (the library
       deferred-loads it; the daemon shouldn't expose it widely) -->
  <policy context="default">
    <deny send_destination="org.freedesktop.secrets"
          send_interface="org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface"/>
  </policy>

  <!-- Block known sandbox/sidecar UIDs that should never reach the keyring -->
  <policy user="ci-agent">
    <deny send_destination="org.freedesktop.secrets"/>
  </policy>
</busconfig>
```

### 9.8 Dockerfile + `docker-compose.yml`

```dockerfile
# Verify with: docker build --no-cache -t secret-service-app . \
#              && docker run --rm secret-service-app java -version
FROM eclipse-temurin:21-jre-jammy

RUN groupadd -r tss && useradd -r -m -g tss secretsvc \
    && mkdir -p /var/lib/secret-service-app \
    && chown secretsvc:tss /var/lib/secret-service-app \
    && chmod 0700 /var/lib/secret-service-app

COPY --chown=secretsvc:tss target/app.jar /usr/share/secret-service-app/app.jar

USER secretsvc
ENV JAVA_TOOL_OPTIONS="-XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError"
ENTRYPOINT ["java", "-jar", "/usr/share/secret-service-app/app.jar"]
```

```yaml
# docker-compose.yml — verify with: docker compose config --quiet
services:
  secret-service-app:
    image: secret-service-app:latest
    user: "secretsvc:tss"
    read_only: true
    tmpfs:
      - /tmp:size=64M,mode=1777
    volumes:
      - ./pepper.tpm2blob:/var/lib/secret-service-app/pepper.tpm2blob:ro
      - ${XDG_RUNTIME_DIR}/bus:/run/user/1000/bus  # session bus into container
    devices:
      - /dev/tpmrm0:/dev/tpmrm0
    cap_drop: [ "ALL" ]
    cap_add:  [ "IPC_LOCK" ]
    security_opt:
      - no-new-privileges:true
      - apparmor:secret-service-app   # if AppArmor profile is loaded on host
    environment:
      DBUS_SESSION_BUS_ADDRESS: "unix:path=/run/user/1000/bus"
```

### 9.9 Flatpak manifest (`org.example.SecretServiceApp.yml`)

```yaml
# Verify with: flatpak-builder --force-clean build-dir org.example.SecretServiceApp.yml
app-id: org.example.SecretServiceApp
runtime: org.freedesktop.Platform
runtime-version: '23.08'
sdk: org.freedesktop.Sdk
command: secret-service-app

finish-args:
  # Use the portal, not the host bus directly:
  - --talk-name=org.freedesktop.portal.Secret
  # No --device=tpm: Flatpak does not have a TPM portal; use EnvVarKeyMaterialProvider
  # or document that this Flatpak'd build cannot use the hardened TPM provider.
  - --filesystem=xdg-data/secret-service-app:create
  # No network access — secrets stay local
  # No host filesystem
modules:
  - name: secret-service-app
    sources:
      - type: archive
        path: secret-service-app-3.0.0.tar.gz
```

### 9.10 Snap recipe (`snap/snapcraft.yaml`)

```yaml
# Verify with: snapcraft --use-lxd
name: secret-service-app
base: core22
version: '3.0.0-alpha'
summary: Secret Service application with hardened TPM-sealed pepper
confinement: strict
grade: stable

apps:
  secret-service-app:
    command: bin/secret-service-app
    plugs:
      - tpm                         # TPM 2.0 access — auto-connects on most systems
      - secret-service-client       # session-bus to org.freedesktop.secrets
      - home                        # user data
    environment:
      JAVA_TOOL_OPTIONS: "-XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError"

plugs:
  secret-service-client:
    interface: dbus
    bus: session
    name: org.freedesktop.secrets

parts:
  secret-service-app:
    plugin: maven
    source: .
```

### 9.11 udev rule (`/etc/udev/rules.d/99-secret-service-tpm.rules`)

```
# Verify with: udevadm control --reload && udevadm test /sys/class/tpm/tpm0
# Pin the TPM resource manager device to the tss group at mode 0660.
# Stricter alternative: GROUP="secretsvc", MODE="0660" — denies all other UIDs.
KERNEL=="tpmrm0", SUBSYSTEM=="tpm", GROUP="tss", MODE="0660"
KERNEL=="tpm0",   SUBSYSTEM=="tpm", GROUP="tss", MODE="0660"
```

After install: `udevadm control --reload && udevadm trigger`. Verify with `ls -la /dev/tpmrm0`.

### 9.12 JVM launcher (`/usr/bin/secret-service-app`)

```bash
#!/bin/sh
# Verify with: shellcheck /usr/bin/secret-service-app
set -eu

# Disable core dumps
ulimit -c 0

# Allow mlockall in non-systemd contexts (systemd handles via AmbientCapabilities=).
# In dev/CI without systemd, run: setcap cap_ipc_lock+ep "$(readlink -f $(which java))"

exec java \
    -XX:+DisableAttachMechanism \
    -XX:-HeapDumpOnOutOfMemoryError \
    -Djava.security.egd=file:/dev/urandom \
    -jar /usr/share/secret-service-app/app.jar "$@"
```

---

## 10. Backup, escrow, and recovery

The hardened layer's failure modes are mostly *not* "the crypto broke" — they are "the operator forgot the password" or "the TPM died and the seal blob is unrecoverable." This section covers the operational realities: what to back up, where, and how to recover from each kind of loss.

### 10.1 Inventory of secret material the operator manages

| Material | Where it lives | Lost ⇒ what happens | Backup target |
|---|---|---|---|
| **Pepper** (KeyMaterialProvider's source) | env var, file, TPM-sealed blob, KMS — depending on provider | All hardened items become unreadable | Out-of-band copy in a different trust domain (password manager, paper, KMS) |
| **TPM seal password** (operator-typed at provisioning) | only in the operator's head / password manager | The TPM-sealed pepper is unrecoverable; same effect as losing the pepper | Two independent copies (memorised + password manager / paper) |
| **`pepper.tpm2blob`** (the TPM-wrapped pepper file) | `~/.config/secret-service/hardened/pepper.tpm2blob` (mode 0600) | Without the blob you cannot unseal even with TPM + password | LUKS-encrypted backup; safe to copy because it is useless without the same TPM |
| **EpochKeystore item** (hardened.kind=epoch-keystore inside the wrapped collection) | A regular item in the gnome-keyring/KeePassXC database | All PQ-flagged hardened items become unreadable; non-PQ items are unaffected | Captured automatically by any backup that copies the keyring database |
| **The keyring file itself** | `~/.local/share/keyrings/*.keyring` (gnome-keyring) or `~/Documents/*.kdbx` (KeePassXC) | All items lost unless covered by daemon-level backup | Daemon's own backup story (out of scope for this library) |

The headline rule: **if the pepper is on the same disk as the keyring file and both are in the same backup, the wrapper buys nothing for class C** (the offline-disk thief gets both). The honest backup story keeps them in different trust domains.

### 10.2 Pepper backup strategies (per provider)

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
#    Tpm2Provisioner generates the pepper itself -- see §10.5 for the open gap.)
printf '%s' "$SEAL_PW"    | <provisioner> --out ~/.config/yourapp/pepper.tpm2blob \
                                          --password-stdin --pepper-source stdin <<< "$PEPPER_RAW"

unset PEPPER_RAW SEAL_PW   # zero from the shell environment
```

Today's `Tpm2Provisioner` generates a fresh pepper internally and seals it; the *raw* pepper is never exposed to the operator (good for class A on the operator's workstation, bad for escrow). If you need cross-host recoverability, treat the TPM blob + password as the escrow unit and accept that re-provisioning on a different host produces a new pepper.

### 10.3 Backing up `pepper.tpm2blob`

The blob is **opaque ciphertext** — useless without the TPM that produced it and the password. Three sensible places:

1. **Bake it into your machine image / Ansible playbook / deployment archive.** Same host re-provisioning = same blob, same TPM, no ceremony.
2. **Copy to encrypted offline media** alongside the seal password. If the host dies and you re-deploy on the same hardware (e.g. swap a disk, keep the motherboard), you re-use the blob.
3. **Push to a cloud secret manager** (AWS SSM Parameter Store, GCP Secret Manager, Vault). Same trust-boundary caveat as the password: don't co-mingle. The cloud manager handles backup + access control.

### 10.4 Backing up the EpochKeystore

The EpochKeystore lives as an item inside the wrapped collection (label `__hardened_epoch_keystore__`, attribute `hardened.kind=epoch-keystore`). Any backup that captures the keyring database also captures the keystore. Two consequences:

- A **partial restore** that brings back the keyring without the pepper / TPM does not give back any items — the keystore is encrypted and the recovery keys (pepper, seal password) live elsewhere.
- After a `rotateEpoch()` destroys the old keypair, **older keyring backups still containing the old keypair can be replayed to recover pre-rotation items**. This subverts the forward-secrecy property of `rotateEpoch()`. If forward secrecy matters in your threat model (genuine class-D defense), you must also rotate the *backup retention* — old keyring backups must age out, or the forward-secrecy guarantee is theoretical.

### 10.5 Recovery procedures

**Lost the seal password** (TPM-sealed pepper):
1. Items are unrecoverable through the wrapper.
2. Use any *out-of-band copy* of the raw pepper (if you escrowed one) to bootstrap a new install.
3. Otherwise, all hardened items are gone. Restore from a higher-level backup of the original plaintexts if available.

**Lost the TPM hardware** (motherboard swap, firmware reset):
1. Provision a *new* `pepper.tpm2blob` on the new TPM with a *new* seal password.
2. If you escrowed the old pepper, decrypt items off-host (a small tool that runs the wrapper's HKDF + AES-GCM with the old pepper), re-encrypt under the new pepper, re-import into the keyring.
3. If you did not escrow, items are gone. Class-C (laptop theft) is exactly the threat model TPM binding defends — losing your own laptop hits this same code path.

**Lost the keyring file** but kept pepper + TPM:
1. Items are gone. The wrapper has no role; a daemon-level keyring backup (Borg / restic / Snapper) is the only recovery.

**Lost the EpochKeystore item** (e.g. accidentally deleted):
1. Non-PQ items continue to read normally (they don't consult the keystore).
2. PQ items become unreadable. Recovery requires a backup of the keyring database from before the deletion. Document an explicit "do not delete items with `hardened.kind=epoch-keystore`" warning to your operators; the library refuses to delete it via `HardenedCollection.deleteItem` but a stray `secret-tool` invocation can.

**Forgot which provider was configured**:
1. Inspect any item's `hardened.*` attributes — they tell you the algorithm, mode, and KEM id.
2. The startup INFO log (`HardenedCollection initialised: provider=…`) names the provider class for the running JVM. If you have logs from a previous run, you have your answer.

### 10.6 Pepper rotation

The wrapper has no built-in "rotate pepper" command. Pepper rotation is a multi-step operator procedure:

1. Generate a new pepper.
2. Read all hardened items with the *old* provider.
3. Construct a new `HardenedCollection` with a *new* provider (same backend, new pepper).
4. Write each item via the new collection (`createItem`).
5. Delete each old item.
6. Migrate the EpochKeystore: it is encrypted under the old pepper, so it must be re-created under the new pepper. Easiest: delete the old keystore item; the new collection lazily creates a fresh one.
7. Update your password-manager / paper backup to the new pepper.

Pepper rotation is rare (only when the old pepper is suspected compromised). For *epoch* rotation — which is forward-secrecy preserving — use `rotateEpoch()`; it does not require a new pepper.

### 10.7 Backup recipe summary

A single defensive checklist for an operator commissioning a new TPM-backed deployment:

- [ ] Pepper: generated by `Tpm2Provisioner`; not directly visible to the operator
- [ ] Seal password: stored in *two* independent places (password manager + paper printout)
- [ ] `pepper.tpm2blob`: copied to encrypted offline media + included in machine image
- [ ] Keyring database: under daemon-level backup with **retention shorter than the rotateEpoch interval** if forward-secrecy matters
- [ ] Operator runbook: documents which provider is in use, where each artefact lives, how to recover

### 10.8 When *not* to back up

- Don't back up an env-var pepper alongside the keyring database. Same trust domain → no class-C benefit.
- Don't print the seal password and store it next to the laptop. Class-C defense gone.
- Don't commit `pepper.tpm2blob` into a git repository or Docker image layer that is published broadly. The blob is opaque, but combined with a leaked seal password from elsewhere it becomes openable.

Backup discipline is the operator's job; the library cannot enforce it. The honest thing this section can do is name the artefacts and the failure modes — see §11 (anti-checklist) for what the library still does not protect against.

---

## 11. Honest anti-checklist

Things nothing in this document defends against. List them here so a downstream consumer cannot claim they were misled.

- **Malicious code running inside the JVM.** Compromised dependency, deserialization gadget, classloader attack, JNI native exploit. Once the attacker is in your JVM, plaintext is in the heap during the `withSecret` callback window. No OS-level guard helps. Defenses are inside the JVM (dependency vetting, SBOM scanning, SLSA provenance) and outside the scope of this document.

- **Live RAM extraction.** Cold-boot attack, JTAG, `kdump` on a malicious kernel, DMA via Thunderbolt/PCIe. `mlockall` only stops swap-resident plaintext from leaking — it does nothing against an attacker with hardware access to RAM.

- **Firmware-level adversaries.** BIOS implants, UEFI rootkits, evil-maid attacks on the bootloader. TPM PCR policy is a partial defense *only when* Secure Boot + IMA-EVM + measured boot are in the chain end-to-end. Without those, the TPM is a fancy file lock.

- **Kernel-level adversaries.** Anyone with a `CAP_SYS_ADMIN`-equivalent or kernel-module-load capability bypasses every userspace MAC framework. SELinux, AppArmor, seccomp, namespaces all assume the kernel is trusted.

- **Policy bypass via legitimate user.** Phishing, social engineering, "click here to disable the protections," sudo-prompt fatigue. The user can always undo the operator's hardening. Out of scope.

- **Application callback misbehaviour.** A `withSecret` body that logs the plaintext, sends it to a HTTP endpoint, or stores it in a String field. The library's `@apiNote` warning documents this risk; OS guards don't help.

- **Uncontrolled child processes.** A daemon that spawns helper processes that inherit memory or environment. Capabilities-bounding doesn't follow exec'd children unless `NoNewPrivileges=true` and `AmbientCapabilities=` are correctly set.

- **Time of check / time of use.** Even with all guards in place, the window between unsealing the pepper and using it for AEAD is plaintext-resident. Every guard in §3 reduces the attacker's options during that window; none eliminates the window.

- **Unrelated services on the same host.** A logging daemon that ingests `/var/log/`, a backup agent that touches `/var/lib/`, a system-management agent with `CAP_SYS_PTRACE`. They all run on the host you've hardened; if they're compromised, your hardening's blast radius shrinks.

- **The user who reads the manual.** This document tells you the attacker classes by name and what each class can do. An adversary who reads this document gets a tidy attack surface inventory. That's the price of writing the threat model down.

---

## 12. References

**Project material**
- `CLAUDE.md` — codebase overview, security considerations
- `README.md` §Security Issues / CVE-2018-19358
- `docs/vision.md` — design goals, KeePassXC compatibility (#34, #45)
- `/root/.claude/plans/create-a-plan-on-cozy-marshmallow.md` §Threat Model, §Security Theater Audit, §Memory Hygiene, §Contraindications, §TPM 2.0 from Java
- `Tpm2KeyMaterialProvider` Javadoc (TPM threat coverage with MAC prerequisite)
- `Tpm2SealedBlob` Javadoc (file-mode 0600 enforcement, wire format)
- `EnvVarKeyMaterialProvider` Javadoc (loud SECURITY WARNING)
- `ThreatCoverage` record (`Level` enum)
- `HardenedCollectionInterface` `@apiNote` (callback escape warning)

**Specifications and standards**
- [freedesktop.org Secret Service API 0.2](https://specifications.freedesktop.org/secret-service/0.2/)
- [JEP 452: Key Encapsulation Mechanism API](https://openjdk.org/jeps/452)
- [JEP 496: Quantum-Resistant Module-Lattice-Based KEM](https://openjdk.org/jeps/496)
- [NIST FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST SP 800-38D — AES-GCM](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [RFC 5869 — HKDF](https://datatracker.ietf.org/doc/html/rfc5869)
- [TCG TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)

**Linux man pages**
- `systemd.exec(5)`, `systemd.unit(5)`, `systemd-cryptenroll(1)`
- `apparmor.d(5)`, `aa-status(8)`, `apparmor_parser(8)`
- `selinux(8)`, `audit2allow(1)`, `restorecon(8)`
- `dbus-daemon(1)`, `dbus-broker(1)`
- `polkit(8)`, `pkaction(1)`, `pkexec(1)`
- `cryptsetup(8)`, `crypttab(5)`
- `prctl(2)`, `seccomp(2)`, `capabilities(7)`, `namespaces(7)`, `cgroups(7)`
- `udev(7)`, `udev.conf(5)`

**Distribution-format documentation**
- [Debian Policy Manual](https://www.debian.org/doc/debian-policy/) and [systemd packaging docs](https://www.freedesktop.org/software/systemd/man/daemon.html#Notification%20Protocol)
- [Fedora Packaging Guidelines](https://docs.fedoraproject.org/en-US/packaging-guidelines/)
- [Docker Security](https://docs.docker.com/engine/security/) and [seccomp profile](https://docs.docker.com/engine/security/seccomp/)
- [Flatpak Sandbox Permissions](https://docs.flatpak.org/en/latest/sandbox-permissions.html) and [xdg-desktop-portal](https://flatpak.github.io/xdg-desktop-portal/)
- [Snapcraft Interface Reference](https://snapcraft.io/docs/supported-interfaces) — `tpm`, `dbus`, `secret-service`
- [NixOS Manual — Modules](https://nixos.org/manual/nixos/stable/index.html#sec-writing-modules)

**External hardening guides**
- [Arch Linux Security wiki](https://wiki.archlinux.org/title/Security)
- [Lennart Poettering — systemd security overview](https://0pointer.de/blog/projects/security.html)
- [Mozilla Observatory — security headers](https://observatory.mozilla.org/) (web context, but the threat-modelling discipline applies)
- [tpm2-software project](https://tpm2-software.github.io/) — `tpm2-tools`, `tpm2-pkcs11`, `tpm2-abrmd`
- [KeePassXC Secret Service documentation](https://keepassxc.org/docs/KeePassXC_GettingStarted.html)











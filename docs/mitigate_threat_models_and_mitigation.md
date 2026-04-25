# Threat Models and Mitigation

**Audience:** operators, packagers, and downstream library consumers shipping a JVM application that depends on `de.swiesend:secret-service` and (optionally) `secret-service-hardened` / `secret-service-hardened-tpm2`.
**Not audience:** end users of a desktop password manager built on top of this library.

This document collects, in one place, every threat the library acknowledges and every Linux-side mechanism a deployer can apply against it. The tables and recipes are deliberately concrete — copy-paste ready — because the security material elsewhere in the project (CLAUDE.md, README §CVE-2018-19358, `docs/vision.md`, every provider's `ThreatCoverage` rationale string) is correct but scattered.

It is structured as **threats first, then defenses, then deployment recipes**:

1. [Introduction & scope](#1-introduction--scope)
2. [Threat catalogue](#2-threat-catalogue) — attacker classes and concrete threats
3. [Defense mechanism inventory](#3-defense-mechanism-inventory) — every Linux-side guard
4. [D-Bus policy in detail](#4-d-bus-policy-in-detail)
5. [Secret Service backend choice — gnome-keyring vs KeePassXC](#5-secret-service-backend-choice)
6. [LUKS / full-disk encryption](#6-luks--full-disk-encryption)
7. [Distribution-format matrix](#7-distribution-format-matrix)
8. [Recommendation matrix](#8-recommendation-matrix-by-deployment-scenario)
9. [Concrete sample configurations](#9-concrete-sample-configurations)
10. [Honest anti-checklist](#10-honest-anti-checklist)
11. [References](#11-references)

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

This is the row where hybrid post-quantum (X25519 + ML-KEM-768, see `HybridKem`) matters. For a purely local keyring with no off-host sync, class D is `NOT_APPLICABLE`.

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

**How to apply.** Ship a small policy module that confines the application to a `secret_service_app_t` domain and grants it `tpm_device_t` access. See §9.3 for the skeleton.

**Limitations.** Policy authoring is non-trivial; misconfigured policy is silently denied (check `audit2allow`). SELinux is bypassed by a kernel-level adversary.

### 3.5 MAC: AppArmor

**What it does.** Path-based access control: profiles list which file paths a binary can read/write/execute and which capabilities it has. Default on Ubuntu, Debian, openSUSE, SUSE.

**Threat coverage.** Same as SELinux for our use case — **A: REAL** with a tight profile, **B: REAL**.

**How to apply.** Drop a profile in `/etc/apparmor.d/usr.local.bin.secret-service-app`. See §9.2 for a sample. AppArmor profiles are cheaper to write than SELinux modules but path-based, so a renamed binary or symlinked path bypasses them.

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

**Key directives for our use case** (see §9.1 for a full unit):

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

**How to apply.** See §9.8 for a sample rule.

**Limitations.** udev runs as root with no MAC awareness; rules are advisory inputs to the device-node permission decision, not security boundaries.

### 3.13 xdg-desktop-portal `org.freedesktop.portal.Secret`

**What it does.** A sandbox-friendly indirection for Secret Service: instead of letting a Flatpak'd app talk to the session bus directly, the portal mediates and prompts the user for consent.

**Threat coverage.** Class B (sandboxed app → host secrets), class A in the limited sense that the portal can require interactive user confirmation.

**How to apply.** *Not a substitute for this library; an alternative path.* If your application is Flatpak-distributed, consider using the portal directly (via `Gio.DBusProxy` or equivalent) instead of the freedesktop Secret Service interface this library implements. See §7.5 for the Flatpak/TPM tension.

**Limitations.** The portal exposes Secret Service-shaped operations only; advanced operations (custom collections, attribute search) are not supported. The hardened wrapper layer this library provides cannot run inside the portal-sandboxed mode because the portal hides the underlying daemon.

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

## 7. Distribution-format matrix

Each format gets the same shape: *what hardening it provides automatically*, *what it makes possible*, *what it prevents*, *TPM access story*, *D-Bus access story*, *threat-class delta vs an unpackaged JAR run by hand*.

### 7.1 Plain binary (`tar.gz` + shell installer)

**Auto-provides.** Nothing.
**Makes possible.** Every Linux primitive: systemd unit, AppArmor profile, SELinux module, MAC labels, capability tweaks, polkit rules. The packager writes them by hand.
**Prevents.** Nothing — the installer can do anything.
**TPM access.** Native; the binary opens `/dev/tpmrm0` directly subject to udev rules.
**D-Bus access.** Native; reads `$DBUS_SESSION_BUS_ADDRESS` directly.
**Class delta vs unpackaged JAR.** Identical until the operator wires up systemd + MAC. Best for **headless server daemons** because no packaging mediates between you and the distro's hardening framework.

### 7.2 Distribution package (`.deb` / `.rpm`)

**Auto-provides.** Conventional install paths, declarative dependency on `systemd`, `apparmor` / `selinux-policy`, `dbus-daemon`. Package post-install scripts wire up the service.
**Makes possible.** Ship a systemd unit, tmpfiles.d entry, sysusers.d entry, AppArmor profile, SELinux policy module, polkit rule, dbus policy file, all in one package. The platform-native way to deliver everything in §3.
**Prevents.** Largely nothing, but conventions push you toward standard paths and discoverable hardening.
**TPM access.** Native; package can include a udev rule (§9.8) that pins `/dev/tpmrm0` ownership.
**D-Bus access.** Native; package can include a session-bus policy fragment.
**Class delta.** Same as plain binary in capability, but **lower operational risk** — distro QA covers half the hardening work, and `apparmor_parser` / `restorecon` run automatically on install. Recommended for **Linux server distributions**.

### 7.3 OCI containers (Docker / Podman / Kubernetes)

**Auto-provides.** Default Docker security profile: namespaces (user, mount, network, PID, IPC), seccomp default profile (~50 syscalls denied), capability drop to a small default set, cgroup device deny-all. Read-only root if `--read-only`.
**Makes possible.** Layer everything from §3 via container-native flags: `--cap-drop=ALL --cap-add=IPC_LOCK`, `--security-opt=seccomp=…`, `--security-opt=no-new-privileges`, `--read-only`, custom AppArmor profile via `--security-opt=apparmor=…`.
**Prevents.** Direct access to host devices and IPC unless explicitly opted in.
**TPM access.** Requires `--device=/dev/tpmrm0` plus, on systems where the TPM is in the `tss` group, mapping the container's UID into a host group with TPM access. This **erodes namespace isolation** for the device cgroup specifically.
**D-Bus access.** Requires `--volume=$XDG_RUNTIME_DIR/bus:/run/user/1000/bus` (host-bus into container) or running an in-container dbus-daemon. Either way, the container is no longer fully sandboxed for IPC.
**Class delta.** Strong against B in the multi-tenant case; class A is *unchanged* (a same-UID attacker on the host still bypasses container boundaries via `nsenter` / `docker exec` / kubelet API). **Not great when the workload needs the TPM**: each device pin-through is a hole in the sandbox.

### 7.4 AppImage

**Auto-provides.** Nothing. AppImage is a self-extracting squashfs that runs as the user. Zero sandboxing.
**Makes possible.** The user can apply external sandboxing (Firejail, bubblewrap), but that's manual.
**Prevents.** Nothing.
**TPM access.** Native — same as a plain binary the user runs.
**D-Bus access.** Native.
**Class delta.** Strictly worse than `tar.gz` + systemd unit: there's no install path, so there's no place for the packager to drop a unit file or a MAC profile. The user runs an unconfined binary.
**Recommendation: avoid AppImage for hardened deployments.** AppImage is a great UX for "click to run" desktop apps; it is not a security-conscious distribution format for a daemon that handles secrets.

### 7.5 Flatpak

**Auto-provides.** Strong sandbox: bubblewrap-based namespaces, seccomp filter, restricted filesystem view (only `~/.var/app/<id>/`), no host network unless declared, no devices unless declared. Portal-mediated access to host resources.
**Makes possible.** Per-app capability declarations in the manifest (`finish-args`): which buses, which directories, which devices.
**Prevents.** Direct talking to the host session bus unless `--socket=session-bus` is declared. Direct device access unless `--device=…` is declared.
**TPM access.** **`/dev/tpmrm0` is not exposed by any Flatpak portal.** A Flatpak'd application that wants TPM access must declare `--device=all` (or `--device=tpm` if available, which is non-standard) — and that **breaks the sandbox** for the device cgroup, undoing much of Flatpak's benefit. The honest options under Flatpak:
  1. Don't use the TPM provider; fall back to `EnvVarKeyMaterialProvider` with the loud warning. Class A: NONE; class B: depends.
  2. Use `xdg-desktop-portal-secret` instead of this library's hardened wrapper. The portal mediates secret access by prompting the user; the application never sees the underlying daemon.
**D-Bus access.** `--talk-name=org.freedesktop.portal.Secret` is the sandbox-friendly path. `--talk-name=org.freedesktop.secrets` opens the host's Secret Service daemon directly and is **discouraged** by Flatpak guidelines.
**Class delta.** Strong against A and B for *non-TPM* workloads. The TPM tension means hardened wrapper + Flatpak is not a natural pairing.
**Recommendation:** if you must distribute a secret-handling app via Flatpak, use the **portal**, accept that the TPM provider is unavailable, and rely on the portal's interactive prompts (close-to-class-A-PARTIAL).

### 7.6 Snap

**Auto-provides.** AppArmor confinement (strict / classic / devmode), seccomp filter, namespace isolation. Mediated host access via "interfaces" — slot-based capabilities the user (or store policy) connects.
**Makes possible.** Plug into typed interfaces: `tpm` (yes, this exists), `dbus` (system or session, with name restrictions), `home`, `removable-media`, etc.
**Prevents.** Anything not declared in the snapcraft manifest.
**TPM access.** **Better than Flatpak here**: there is a `tpm` interface (slot on `core`, plug in the snap). `snap connect <app>:tpm` enables it; the store can auto-connect on install if the developer declares it.
**D-Bus access.** `dbus` plug with `name: org.freedesktop.secrets`, `interface: org.freedesktop.Secret.Service`. More restrictive than Flatpak's `--talk-name`.
**Class delta.** Strong against A, B, C (LUKS still relevant). The TPM access path is straightforward — no manifest contortions.
**Recommendation:** Snap is a **good fit** if you're targeting Ubuntu / Ubuntu Core where Snap is native; arguably better than Flatpak for TPM-using applications because `tpm` interface is a first-class concept.

### 7.7 Nix derivation / NixOS module

**Auto-provides.** Reproducible build, content-addressed store, `/nix/store` is read-only. NixOS modules wire up systemd units declaratively.
**Makes possible.** A NixOS module can declare the package + systemd unit + AppArmor profile + udev rules + dbus policy in one Nix expression. Closest to "distribution format and policy in one place."
**Prevents.** Nothing in particular at the runtime level — the binary still runs as a normal Linux process. Reproducibility helps against supply-chain attacks (recompile-from-source verification).
**TPM access.** Native; the NixOS module can declare `services.tpm2.enable = true` and add the user to `tss`.
**D-Bus access.** NixOS module can drop session/system policy fragments via `services.dbus.packages = [ pkgs.… ]`.
**Class delta.** Equivalent to `.deb`/`.rpm` for a NixOS deployer, with the supply-chain bonus.
**Recommendation:** if you're already on NixOS, package as a Nix derivation + module. Otherwise, `.deb`/`.rpm` is the more portable choice.

### 7.8 Format vs class-delta summary

| Format | Class A | Class B | Class C | Notes |
|---|---|---|---|---|
| Plain binary | depends on operator | depends on operator | depends on operator | Operator owns it all |
| `.deb`/`.rpm` | **REAL with MAC profile** | **REAL with policy fragment** | depends on LUKS | Distro-native, recommended for daemons |
| OCI container | unchanged (host bypass) | REAL between containers | depends on host | Good for multi-tenant; tension with TPM |
| AppImage | NONE | NONE | NONE | Avoid for secret-handling |
| Flatpak | PARTIAL via portal | REAL | depends on LUKS | TPM tension; use portal not direct bus |
| Snap | PARTIAL with strict confinement | REAL | depends on LUKS | Best sandbox + TPM combination |
| Nix / NixOS | matches `.deb`/`.rpm` | matches `.deb`/`.rpm` | matches `.deb`/`.rpm` | Plus reproducibility |

---

## 8. Recommendation matrix (by deployment scenario)

Each row picks one column for backend, distribution format, MAC framework, D-Bus posture, and LUKS expectation, with a one-sentence rationale.

| Scenario | Backend | Format | MAC | D-Bus | LUKS | Hardened provider |
|---|---|---|---|---|---|---|
| **Headless Linux daemon** (CI runner, service account, autonomous agent) | own keyring under dedicated UID | `.deb`/`.rpm` + systemd | AppArmor or SELinux | session-bus restricted to service UID | required for at-rest defense | `Tpm2KeyMaterialProvider` |
| **Multi-tenant container host / k8s** | per-tenant gnome-keyring inside namespace | OCI container | per-tenant AppArmor/SELinux label, tight seccomp | bind-mounted from host with caveats | host-level LUKS | `Tpm2KeyMaterialProvider` with explicit `--device=/dev/tpmrm0` |
| **Linux desktop power-user app** (Cryptomator-shape) | **KeePassXC** | `.deb`/`.rpm` (avoid Flatpak for TPM) | distro default (AppArmor on Ubuntu/Debian, SELinux on Fedora) | per-user policy | required | `Tpm2KeyMaterialProvider` if the user has a TPM, else file-based |
| **Sandboxed desktop app** (Flatpak / Snap) | portal (`xdg-desktop-portal-secret`) on Flatpak; KeePassXC on Snap with TPM interface | Snap preferred over Flatpak when TPM matters | sandbox MAC | portal-mediated | required | Snap-only; Flatpak with portal cannot use TPM |
| **Cross-platform desktop app** | OS-native keychain (out of scope) | n/a | n/a | n/a | platform-default disk encryption | n/a — this library is Linux-only |
| **Developer workstation / local CI** | gnome-keyring | plain binary or `.jar` | none | none | optional | `EnvVarKeyMaterialProvider` with the loud warning; document the gap |

### Rationale for each row

- **Headless Linux daemon**: the deployer owns the host, can write systemd units and MAC profiles, and the threat model is dominated by C (offline backup theft) and B (sidecar / colocated services). Hardened wrapper + TPM is a natural fit; the daemon's UID isolates it from interactive user sessions.

- **Multi-tenant container host**: each tenant gets its own namespace; class B between tenants is the dominant threat. OCI containers handle B by construction; TPM access requires explicit per-container device pinning, which is acceptable for trusted tenants but doesn't extend across namespaces. Class A (host-level admin) is unchanged — that's the host operator's job.

- **Linux desktop power-user app**: KeePassXC's interactive prompt is the only realistic class-A defense available without operator-installed MAC. `.deb`/`.rpm` over Flatpak because the TPM tension under Flatpak (§7.5) is real. LUKS expected because the dominant threat for a laptop is "stolen device."

- **Sandboxed desktop app**: if you're targeting Flatpak, embrace the portal — don't fight the sandbox. If you're targeting Snap and want the TPM, Snap's `tpm` interface (§7.6) is the cleaner path. Don't try to ship the same binary on both with full TPM support; the constraints are different.

- **Cross-platform desktop app**: this library doesn't help you on Windows/macOS. Use the platform's OS keychain (Windows Credential Manager, macOS Keychain) directly via OS-native APIs.

- **Developer workstation / local CI**: be honest. The wrapper buys little here against the developer themselves; the value is in proving the API works before deploying to the headless-daemon row above. Document the gap so a developer doesn't ship the dev configuration to production.

---

## 9. Concrete sample configurations

Each snippet is a drop-in starting point for a `secret-service-app` daemon under user `secretsvc` with the TPM-sealed pepper at `/var/lib/secret-service-app/pepper.tpm2blob`. Adjust paths and names for your binary. **Verify each snippet** with the command at the top of the section before deploying.

### 9.1 systemd unit (`/etc/systemd/system/secret-service-app.service`)

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

### 9.2 AppArmor profile (`/etc/apparmor.d/usr.bin.java.secret-service-app`)

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

### 9.3 SELinux policy module (`secret_service_app.te`)

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

### 9.4 D-Bus session-bus policy (`/usr/share/dbus-1/session.d/org.example.secret-service-app.conf`)

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

### 9.5 Dockerfile + `docker-compose.yml`

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

### 9.6 Flatpak manifest (`org.example.SecretServiceApp.yml`)

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

### 9.7 Snap recipe (`snap/snapcraft.yaml`)

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

### 9.8 udev rule (`/etc/udev/rules.d/99-secret-service-tpm.rules`)

```
# Verify with: udevadm control --reload && udevadm test /sys/class/tpm/tpm0
# Pin the TPM resource manager device to the tss group at mode 0660.
# Stricter alternative: GROUP="secretsvc", MODE="0660" — denies all other UIDs.
KERNEL=="tpmrm0", SUBSYSTEM=="tpm", GROUP="tss", MODE="0660"
KERNEL=="tpm0",   SUBSYSTEM=="tpm", GROUP="tss", MODE="0660"
```

After install: `udevadm control --reload && udevadm trigger`. Verify with `ls -la /dev/tpmrm0`.

### 9.9 JVM launcher (`/usr/bin/secret-service-app`)

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

## 10. Honest anti-checklist

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

## 11. References

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











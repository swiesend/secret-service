# Defense mechanism inventory

*Part of the [Security & deployment guide](index.md).*


Each entry: **what it does → which threat classes it addresses (and at what `Level`) → how to apply it to a JVM Secret Service consumer → limitations.**

## LUKS / dm-crypt full-disk encryption

**What it does.** Encrypts a block device under a key sealed in a LUKS header. The kernel decrypts on the fly while the device is unlocked; bytes on the disk are useless without the LUKS key.

**Threat coverage.** **C: REAL**; A, B and D are unaffected — the per-class reasoning and the
comparison against the wrapper's own TPM use live in [full-disk encryption](full-disk-encryption.md),
which is the single source for it.

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

**Limitations.** A running machine with LUKS unlocked is class-C-equivalent to one without it, and
"LUKS is unlocked by my TPM at boot" is not the same as "my application secret is sealed in my TPM".
Both points, plus swap/hibernation and filesystem-snapshot exposure, are covered in
[full-disk encryption](full-disk-encryption.md).

## POSIX DAC (file modes, ownership, umask)

**What it does.** Per-file owner/group/other read/write/execute bits, enforced by every syscall.

**Threat coverage.** A: NONE (same UID is the file owner) · **B: REAL** when modes are right · **C: REAL** as a defense-in-depth on top of LUKS · D: NOT_APPLICABLE.

**How to apply.** The library already enforces this for the TPM sealed-blob file (`Tpm2SealedBlob.writeTo` creates the file mode 0600 from the outset; `Tpm2SealedBlob.readFrom` refuses to load over-permissive files). Mirror the discipline for any pepper file your `KeyMaterialProvider` reads. Set a strict umask (`umask 077`) in the systemd unit's `UMask=` directive so transient files inherit owner-only permissions.

**Limitations.** Class A bypasses DAC entirely (they *are* the owner). DAC against B requires that the application user differs from the attacker's UID — not always the case in containerised deployments where everything runs as one UID.

## POSIX capabilities

**What it does.** Splits root's privileges into ~40 fine-grained capabilities (`CAP_NET_BIND_SERVICE`, `CAP_IPC_LOCK`, etc.) that can be granted to non-root processes or removed from a privileged one.

**Threat coverage for our use case.**
- **`CAP_IPC_LOCK`** to allow `mlockall(MCL_CURRENT | MCL_FUTURE)` from a non-root JVM — defense-in-depth against C (no swap leakage) and partial against A (no ptrace from a process that lacks `CAP_SYS_PTRACE`).
- **Drop `CAP_SYS_PTRACE`** in the bounding set so the JVM cannot ptrace others (and, more importantly, so anything the JVM spawns inherits the absence).
- **Drop `CAP_DAC_OVERRIDE`** so even if exploited the JVM can't read files it doesn't own.

**How to apply.** systemd `AmbientCapabilities=CAP_IPC_LOCK` + `CapabilityBoundingSet=CAP_IPC_LOCK` + `NoNewPrivileges=true`. Or `setcap cap_ipc_lock+ep /usr/lib/jvm/.../bin/java`.

**Limitations.** Capabilities apply to syscalls; they do not restrict what the JVM does inside its own address space.

## MAC: SELinux

**What it does.** Type Enforcement: every process has a domain, every file/device a type, and the policy declares which domains may do what to which types. The kernel enforces, irrespective of UID. Default on RHEL, Fedora, CentOS Stream, AlmaLinux, Rocky.

**Threat coverage.** **A: REAL** when policy is tight (denies `ptrace`, denies `/dev/tpmrm0` open from outside the application's domain) · **B: REAL** · C: NOT_APPLICABLE (offline) · D: NOT_APPLICABLE.

**How to apply.** Ship a small policy module that confines the application to a `secret_service_app_t` domain and grants it `tpm_device_t` access. See [SELinux policy module (`secret_service_app.te`)](sample-configurations.md#selinux-policy-module-secret_service_appte) for the skeleton.

**Limitations.** Policy authoring is non-trivial; misconfigured policy is silently denied (check `audit2allow`). SELinux is bypassed by a kernel-level adversary.

## MAC: AppArmor

**What it does.** Path-based access control: profiles list which file paths a binary can read/write/execute and which capabilities it has. Default on Ubuntu, Debian, openSUSE, SUSE.

**Threat coverage.** Same as SELinux for our use case — **A: REAL** with a tight profile, **B: REAL**.

**How to apply.** Drop a profile in `/etc/apparmor.d/usr.local.bin.secret-service-app`. See [AppArmor profile (`/etc/apparmor.d/usr.bin.java.secret-service-app`)](sample-configurations.md#apparmor-profile-etcapparmordusrbinjavasecret-service-app) for a sample. AppArmor profiles are cheaper to write than SELinux modules but path-based, so a renamed binary or symlinked path bypasses them.

**Limitations.** Path-based ⇒ symlink/rename hazards, and bind-mounts can shift things out of profile coverage. A kernel-level adversary bypasses AppArmor.

## seccomp-bpf

**What it does.** A BPF program filters every syscall the process makes; non-matching syscalls return `EPERM` or kill the process.

**Threat coverage.** Hardens A and B further by removing dangerous syscalls (`ptrace`, `process_vm_readv`, `kcmp`, `mount`, `unshare`, `clone3` with namespace flags, …). Most useful when the attacker is exploiting an in-JVM bug to spawn code; less useful against the canonical `ptrace`-from-outside attacker.

**How to apply.** systemd `SystemCallFilter=@system-service` is the easy default — that allowlist excludes most dangerous syscalls. For a JVM, the wide default syscall surface (futex, file I/O, threading, GC) means a *block-list* (`SystemCallFilter=~ptrace process_vm_readv kcmp`) is more practical than a precise allowlist.

**Limitations.** seccomp filters the JVM, not what attaches *to* the JVM. A separate process with `CAP_SYS_PTRACE` is unaffected.

## Linux namespaces

**What it does.** Per-process kernel-resource isolation. Six namespaces matter here:

- **user** — UID/GID remapping; the process can be `root` inside, unprivileged outside
- **mount** — own filesystem view
- **network** — own network stack (no D-Bus session bus reachable unless explicitly mounted in)
- **pid** — own process tree (no `/proc/<pid>` visible)
- **ipc** — own SysV IPC, shared memory, message queues
- **uts** — own hostname

**Threat coverage.** Foundation for all sandboxing: containers, Flatpak, Snap, systemd `Private*=` directives all stack on namespaces. Helps A (the namespaced process can't see its host's `/proc`), helps B (different network and IPC namespaces hide D-Bus addresses).

**How to apply.** Indirectly via systemd `PrivateTmp=`, `PrivateNetwork=`, `PrivateUsers=`, `ProtectProc=invisible`, etc. — see [systemd unit hardening](#systemd-unit-hardening).

**Limitations.** A namespaced JVM that needs to talk to the *host*'s session bus must have that bus's socket bind-mounted in, which negates the network/IPC namespace benefit for that path.

## cgroups v2 (device controller)

**What it does.** The `device` controller in cgroup v2 (eBPF-based) explicitly allows or denies access to specific device nodes per cgroup.

**Threat coverage.** Useful complement to MAC for `/dev/tpmrm0`: cgroup denies `open(2)` regardless of UID or selinux/apparmor verdict. Defense-in-depth.

**How to apply.** systemd `DeviceAllow=/dev/tpmrm0 rw` + `DevicePolicy=closed` (closed = deny everything except explicit allows).

**Limitations.** Container runtimes manage their own cgroup hierarchies; OCI's default device cgroup denies most things, and you must explicitly opt the TPM in via `--device=/dev/tpmrm0`.

## Memory hygiene (mlockall, no swap, no core dumps, no attach)

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
# --enable-native-access lets the library's FFM mlock call run without a warning (see below)
Environment="JAVA_TOOL_OPTIONS=--enable-native-access=de.swiesend.secretservice.hardened -XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError"
```

Plus, in application code: opt into memory locking with `HardenedCollection.builder(...).lockMemory(true)`. The library then calls `mlockall(MCL_CURRENT | MCL_FUTURE)` through the JDK Foreign Function & Memory API (best-effort, off by default because it locks the whole process). For it to take effect you need (a) `--enable-native-access=de.swiesend.secretservice.hardened` on the JVM command line — otherwise the restricted native call still runs but the JVM prints a native-access warning — and (b) an adequate `RLIMIT_MEMLOCK` (`LimitMEMLOCK=infinity` above, or `CAP_IPC_LOCK`). Whether the lock actually took is reported by `coll.status().memoryLocked()` — never a hardcoded value, so you can assert on it in a health check.

**Limitations.** `mlockall` doesn't help against live RAM extraction (cold-boot, JTAG). Attach-mechanism disable doesn't block `ptrace` — that's MAC's job.

## systemd unit hardening

**What it does.** systemd exposes the kernel's namespace/cgroup/seccomp/MAC primitives as declarative directives in the unit file. The richest single-tool way to harden a daemon on Linux.

**Threat coverage.** Composes the above mechanisms — coverage matches whichever primitives you enable.

**Key directives for our use case** (see [systemd unit (`/etc/systemd/system/secret-service-app.service`)](sample-configurations.md#systemd-unit-etcsystemdsystemsecret-service-appservice) for a full unit):

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

## Secure Boot, Measured Boot, IMA-EVM

**What it does.** Establishes a chain of trust from firmware → bootloader → kernel → initrd that the TPM measures into PCRs. PCR values then bind sealed objects to a known-good boot state.

**Threat coverage.** **C: REAL** (a tampered boot path produces different PCRs, the seal won't open). Partial against the firmware-tamper "evil maid" if the chain is unbroken.

**How to apply.** Distribution-specific (Fedora `sbverify`, Ubuntu `mokutil`, …). Required upstream of the TPM PCR-policy mode this library reserves but doesn't yet ship (`Tpm2SealedBlob.PolicyKind.PCR`).

**Limitations.** Operationally heavy — kernel updates, initrd regeneration, and bootloader changes all shift PCR values, breaking sealed objects. Plan a rotation strategy.

## udev rules for `/dev/tpmrm0`

**What it does.** Sets ownership, group, mode, and tags on device nodes when they appear.

**Threat coverage.** Defense-in-depth on top of MAC: confining `/dev/tpmrm0` to a specific group (or the application's UID) reduces class B's TPM access.

**How to apply.** See [udev rule (`/etc/udev/rules.d/99-secret-service-tpm.rules`)](sample-configurations.md#udev-rule-etcudevrulesd99-secret-service-tpmrules) for a sample rule.

**Limitations.** udev runs as root with no MAC awareness; rules are advisory inputs to the device-node permission decision, not security boundaries.

## xdg-desktop-portal `org.freedesktop.portal.Secret`

**What it does.** A sandbox-friendly indirection for Secret Service: instead of letting a Flatpak'd app talk to the session bus directly, the portal mediates and prompts the user for consent.

**Threat coverage.** Class B (sandboxed app → host secrets), class A in the limited sense that the portal can require interactive user confirmation.

**How to apply.** *Not a substitute for this library; an alternative path.* If your application is Flatpak-distributed, consider using the portal directly (via `Gio.DBusProxy` or equivalent) instead of the freedesktop Secret Service interface this library implements. See [Flatpak](desktop-deployment.md#flatpak) for the Flatpak/TPM tension.

**Limitations.** The portal exposes Secret Service-shaped operations only; advanced operations (custom collections, attribute search) are not supported. The hardened wrapper layer this library provides cannot run inside the portal-sandboxed mode because the portal hides the underlying daemon.

## Unseal-password delivery (TPM provider)

**What it does.** With `Tpm2KeyMaterialProvider` the pepper is never stored — at rest there is only the TPM-wrapped blob, useless without the physical chip plus the unseal password (wrong guesses hardware-rate-limited by the DA lockout). The remaining design decision is how the *unseal password* reaches the process at startup; the choice determines how much of the TPM's class-C guarantee survives operational reality.

**Threat coverage.** The password is one of two factors, so its handling never has to carry class C alone: even a leaked password is useless off-host. Delivery choice mainly affects whether class B can read it (file modes) and whether a human is in the loop against class A.

**How to apply.** Ranked for a desktop (full reasoning in [Where does the unseal password live on a desktop?](../usage/tpm2.md#where-does-the-unseal-password-live-on-a-desktop)): (1) interactive prompt — nothing persisted, human-in-the-loop, no autostart; (2) login keyring — autostart-friendly, and the offline thief still lacks the TPM, so class C survives; class A was already `PARTIAL`; (3) systemd `LoadCredentialEncrypted=` for services (user-scoped credentials need systemd ≥ 256); (4) a 0600 file as the floor. Never argv (see the `Tpm2Provisioner` history) and never env vars (`/proc/<pid>/environ`, [Class A — same-UID live process](threat-catalogue.md#class-a-same-uid-live-process)). Do **not** park the password in a KeePassXC database: a locked `.kdbx` fails your startup closed, and if KeePassXC is also the Secret Service backend the password co-locates with the ciphertexts it protects.

**Limitations.** None of these mediate class A — a same-UID process reads the password wherever the legitimate process can (or the unsealed pepper from the JVM heap, [Class A — same-UID live process](threat-catalogue.md#class-a-same-uid-live-process)). Same-UID confinement remains the job of MAC policy on `/dev/tpmrm0` ([MAC: SELinux](#mac-selinux), [MAC: AppArmor](#mac-apparmor), [udev rules for `/dev/tpmrm0`](#udev-rules-for-devtpmrm0)).

---

# Threat catalogue

*Part of the [Security & deployment guide](index.md).*


The library names four attacker classes. The table below is the *canonical* shape — concrete threats further down expand each row.

| # | Attacker | Has keyring? | Same UID? | `/proc/<pid>` access? | Host disk? |
|---|---|---|---|---|---|
| **A** | Same-UID process on live host (canonical CVE-2018-19358) | yes | **yes** | **yes** | yes |
| **B** | Cross-UID process on same host (sandboxed app, other user) | yes (via D-Bus) | no | no | no |
| **C** | Offline disk/backup thief (stolen laptop, exfiltrated `~/.local/share/keyrings`) | yes (cold) | no | no | yes (cold) |
| **D** | Network adversary with harvest-now-decrypt-later ambition | no | no | no | no |

## Class A — same-UID live process

The hardest attacker to defend against, because they share the trust domain that contains both the ciphertext *and* most of the wrapping material. Concrete attack vectors:

- **JVM heap inspection**: `ptrace(2)` + `process_vm_readv(2)` on the running JVM, `/proc/<pid>/mem`, kernel-`ptrace`-via-`PTRACE_PEEKDATA`. Reads the unsealed pepper, the cached DEK, and any plaintext sitting in the `withSecret` callback window.
- **JVM attach API**: `jstack`, `jmap`, `jcmd`, custom JVMTI agent. Same UID can attach to a JVM that hasn't passed `-XX:+DisableAttachMechanism`.
- **Environment / cmdline scrape**: `/proc/<pid>/environ` reveals env-var peppers; `/proc/<pid>/cmdline` reveals plaintext password CLI flags. (This is why `Tpm2Provisioner` takes the pepper and password from stdin, an environment variable or a file descriptor rather than from `argv` — see [TPM 2.0 usage](../usage/tpm2.md#provision-a-sealed-pepper).)
- **Direct daemon access**: open the session bus (`$DBUS_SESSION_BUS_ADDRESS`) and just *ask* the Secret Service daemon for the unlocked items — no exploit needed; the daemon's design assumes same-UID is trusted.
- **Direct TPM access**: open `/dev/tpmrm0` and issue TPM 2.0 commands. The TPM authenticates possession of secrets and platform state, *not* caller identity. Knowing the seal password — or extracting it from JVM heap — yields the unsealed pepper.
- **Kernel keyring**: read user/session keyrings via `keyctl(2)` if the application uses the kernel keyring as a transport.
- **Side channels**: `/proc/<pid>/status` (peak memory), `/proc/<pid>/io` (bytes read), `/sys/fs/cgroup/<…>/memory.stat`, sched_yield timing — useful for inferring activity, rarely for extracting plaintext directly.

This class is the most common local-machine attacker — and the one no in-process encryption can defend against.

## Class B — cross-UID process on same host

Sandboxed app, multi-user system, sidecar container running as a different UID. Concrete vectors:

- **Loose file modes** on `~/.local/share/keyrings/*.keyring`, the pepper file, or `pepper.tpm2blob`. Group-readable or other-readable lets B exfiltrate.
- **Leaked `DBUS_SESSION_BUS_ADDRESS`**: if the victim's session bus address is reachable from B (shared `/run/user/<uid>` mount, accidentally bind-mounted into a sidecar), B can connect and ask for items.
- **Container volume cross-talk**: shared volumes between sidecars in a Pod, anonymous volumes that survive container teardown.
- **`/dev/tpmrm0` permissions**: the udev default usually puts the device into the `tss` group with mode 0660. Anyone in `tss`, regardless of UID, can talk to the TPM. If your application user and the attacker user are both in `tss`, B is effectively a TPM client.

## Class C — offline disk/backup thief

The disk is at rest; the attacker has bytes but no live process. Concrete vectors:

- **Stolen laptop / decommissioned drive / disposed SSD**.
- **Exfiltrated `rsync`** of `~`, container snapshot, ZFS/Btrfs snapshot, LVM snapshot.
- **Cloud-synced backup** that contains `~/.local/share/keyrings`, the pepper file, the `pepper.tpm2blob`, *and* the env-var-style configuration that names the seal password.
- **Swap-file recovery / hibernation image**: `/var/lib/swap` or `/swapfile` if not encrypted. Hibernation writes the entire RAM (including unlocked secrets) to disk.
- **Core dumps**: `/var/lib/systemd/coredump`, `/proc/sys/kernel/core_pattern` redirects, `coredumpctl dump`. JVM heap dump on OOM (`-XX:+HeapDumpOnOutOfMemoryError`) lands plaintext on disk in clear.
- **Filesystem journal / undelete**: ext4 journal or NTFS USN journal can retain blocks of recently-deleted files; forensic recovery from "I deleted the keyring" is realistic.

## Class D — network harvest-now-decrypt-later

Ciphertext that ever leaves the host, archived for future quantum decryption.

- **Backup uploaded to cloud storage** that the provider (or an attacker who breaches the provider) retains for years.
- **IMAP-delivered secrets** routed through a long-retention mail provider.
- **Sync protocols** that ship the keyring file across the network.
- **Audit log replication** that captures encrypted secrets in transit.

This is the row where hybrid post-quantum (X25519 + ML-KEM-768, see `HybridKem`) matters. The wrapper's PQ mode (`Builder.enablePostQuantum(true)`) wires the ML-KEM shared secret into HKDF DEK derivation and stores the KEM ciphertext in the envelope's `kem_ct` field. `rotateEpoch()` destroys the previous epoch's keypair via the `EpochKeystore`, so pre-rotation envelopes captured by an HNDL attacker become unrecoverable: a real class-D defense, not just a label. For a purely local keyring with no off-host sync, class D remains `NOT_APPLICABLE`.

## Cross-cutting threats (don't fit one class cleanly)

- **Supply-chain attack**: malicious update of a transitive dep — `bcprov-jdk18on`, `TSS.Java`, `dbus-java-core`. Reads plaintext directly; out of scope of OS guards but worth naming.
- **CI build-log leakage**: `mvn -X` printing env vars, GitHub Actions secret echo, Jenkins log retention. Class C-shaped but with the build infrastructure as the disk.
- **Evil maid**: firmware tamper, BIOS implant, bootloader replacement before measured boot. TPM PCR policy is a partial defense if Secure Boot + IMA-EVM are in the chain; otherwise NONE.
- **DMA attack**: Thunderbolt / FireWire / PCIe device with bus-master access reads RAM directly. IOMMU + kernel `iommu=force` is the answer; out of scope here.
- **Cold-boot attack**: RAM contents survive a power cycle for seconds to minutes if the chip is cooled. Defeated by `mlockall` only against swap, not against this.
- **Kernel exploit**: a kernel-level adversary trivially bypasses every userspace MAC framework. All defenses in [Defense mechanism inventory](defense-mechanisms.md) assume the kernel is trusted.

---

# Honest anti-checklist

*Part of the [Security & deployment guide](index.md).*


Things nothing in this document defends against. List them here so a downstream consumer cannot claim they were misled.

- **Malicious code running inside the JVM.** Compromised dependency, deserialization gadget, classloader attack, JNI native exploit. Once the attacker is in your JVM, plaintext is in the heap during the `withSecret` callback window. No OS-level guard helps. Defenses are inside the JVM (dependency vetting, SBOM scanning, SLSA provenance) and outside the scope of this document.

- **Live RAM extraction.** Cold-boot attack, JTAG, `kdump` on a malicious kernel, DMA via Thunderbolt/PCIe. `mlockall` only stops swap-resident plaintext from leaking — it does nothing against an attacker with hardware access to RAM.

- **Firmware-level adversaries.** BIOS implants, UEFI rootkits, evil-maid attacks on the bootloader. TPM PCR policy is a partial defense *only when* Secure Boot + IMA-EVM + measured boot are in the chain end-to-end. Without those, the TPM is a fancy file lock.

- **Kernel-level adversaries.** Anyone with a `CAP_SYS_ADMIN`-equivalent or kernel-module-load capability bypasses every userspace MAC framework. SELinux, AppArmor, seccomp, namespaces all assume the kernel is trusted.

- **Policy bypass via legitimate user.** Phishing, social engineering, "click here to disable the protections," sudo-prompt fatigue. The user can always undo the operator's hardening. Out of scope.

- **Application callback misbehaviour.** A `withSecret` body that logs the plaintext, sends it to a HTTP endpoint, or stores it in a String field. The library's `@apiNote` warning documents this risk; OS guards don't help.

- **Uncontrolled child processes.** A daemon that spawns helper processes that inherit memory or environment. Capabilities-bounding doesn't follow exec'd children unless `NoNewPrivileges=true` and `AmbientCapabilities=` are correctly set.

- **Time of check / time of use.** Even with all guards in place, the window between unsealing the pepper and using it for AEAD is plaintext-resident. Every guard in [Defense mechanism inventory](defense-mechanisms.md) reduces the attacker's options during that window; none eliminates the window.

- **Unrelated services on the same host.** A logging daemon that ingests `/var/log/`, a backup agent that touches `/var/lib/`, a system-management agent with `CAP_SYS_PTRACE`. They all run on the host you've hardened; if they're compromised, your hardening's blast radius shrinks.

- **The user who reads the manual.** This document tells you the attacker classes by name and what each class can do. An adversary who reads this document gets a tidy attack surface inventory. That's the price of writing the threat model down.

---

## References

**Project material**
- `README.md` §Security Issues / CVE-2018-19358
- [Roadmap](../roadmap.md) — design goals and history
- [Architecture diagrams](../architecture/index.md) — mechanisms with correctness evidence
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

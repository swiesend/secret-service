# Mitigation matrices and sample configurations

*Part of the [Security & deployment guide](index.md).*


This section is the cross-cutting reference: the format-vs-class summary, the backend stacking summary, and — most useful as a quick lookup — the **mitigation-vs-environment matrix** that lets a downstream consumer pick a row (their environment) and read off which guards apply, partially apply, or are unavailable. Sample configurations follow as subsections [systemd unit (`/etc/systemd/system/secret-service-app.service`)](#systemd-unit-etcsystemdsystemsecret-service-appservice)–[JVM launcher (`/usr/bin/secret-service-app`)](#jvm-launcher-usrbinsecret-service-app) and are referenced from [Desktop App consumer scenarios](desktop-deployment.md) and [CI Tool consumer scenarios](ci-deployment.md).

## Distribution format vs threat-class summary

| Format | Class A | Class B | Class C | Notes |
|---|---|---|---|---|
| Plain `tar.gz` ([Plain binary archive (`tar.gz` / `zip`)](desktop-deployment.md#plain-binary-archive-targz-zip)) / fat JAR ([Self-contained JAR (`java -jar yourapp.jar`)](desktop-deployment.md#self-contained-jar-java-jar-yourappjar)) | NONE | NONE | depends on user's LUKS | Operator owns the entire hardening story |
| jpackage `.deb`/`.rpm` ([jpackage-built `.deb` / `.rpm`](desktop-deployment.md#jpackage-built-deb-rpm)) | **REAL** with shipped AppArmor profile + KeePassXC | **REAL** with shipped D-Bus policy | **REAL** with TPM provider + LUKS | Distro-native; recommended for desktop apps |
| AppImage ([AppImage](desktop-deployment.md#appimage)) | NONE | NONE | depends on user's LUKS | Avoid for secret-handling |
| Flatpak ([Flatpak](desktop-deployment.md#flatpak)) — portal-only | PARTIAL — interactive portal | REAL — namespace + portal | depends on host LUKS | TPM unavailable; library mostly bypassed |
| Snap ([Snap](desktop-deployment.md#snap)) — strict confinement | PARTIAL — AppArmor + seccomp | REAL — namespace + AppArmor | REAL with TPM provider | Best Linux sandbox + TPM combination |
| Nix / NixOS ([Nix / NixPkgs / Home Manager](desktop-deployment.md#nix-nixpkgs-home-manager)) | matches `.deb`/`.rpm` | matches `.deb`/`.rpm` | matches `.deb`/`.rpm` | Plus reproducibility |
| OCI container ([OCI container (Docker, Podman, k8s) — the dominant CI format in 2026](ci-deployment.md#oci-container-docker-podman-k8s-the-dominant-ci-format-in-2026)) | NONE — host bypass | REAL — namespace | REAL with BuildKit secret mounts | Dominant in CI; TPM tension |
| `.deb`/`.rpm` self-hosted runner ([Distribution package (`.deb` / `.rpm`) for self-hosted runner](ci-deployment.md#distribution-package-deb-rpm-for-self-hosted-runner)) | **REAL** with hardened systemd unit | **REAL** with policy fragment | **REAL** with TPM provider | Best CI runner posture |

## Backend stacking summary

| Stack | Class A | Class B | Class C |
|---|---|---|---|
| gnome-keyring alone | NONE | depends on file modes | NONE if pepper colocated |
| KeePassXC alone | PARTIAL — interactive prompt | PARTIAL | PARTIAL — Argon2 KDF |
| gnome-keyring + hardened (TPM) | PARTIAL — needs MAC | REAL with file mode 0600 | **REAL** |
| **KeePassXC + hardened (TPM)** | **PARTIAL → REAL** stacked | **REAL** | **REAL** — two layers |

## Mitigation-vs-environment matrix

The grid below maps each mitigation listed in [Defense mechanism inventory](defense-mechanisms.md) (plus the application-layer additions from [Secret Service backend choice](backend-choice.md)/[Desktop App consumer scenarios](desktop-deployment.md)/[CI Tool consumer scenarios](ci-deployment.md)) against the deployment environments downstream consumers actually ship into. Read it like a lookup table: pick your row (environment), read off which mitigations apply.

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
| `mlockall(MCL_CURRENT|FUTURE)` via `lockMemory(true)` (FFM) | ◐ needs cap | ✓ | ◐ | ✗ | ✓ | ✓ | ◐ |
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
| AEAD envelope — AES-256-GCM / ChaCha20-Poly1305 (hardened wrapper) | ✓ | ✓ | ✓ | ◐ via portal-only path | ✓ | ✓ | ✓ |
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
- **EnvVarKeyMaterialProvider in desktop / multi-user:** any process running as the user reads `/proc/<pid>/environ`; the provider's Javadoc warning calls this out and the builder refuses it without `acknowledgeSameUidExposure(true)`.

**How to use this matrix.** Pick your environment column. Each ✓ row is a guard you should adopt; each ◐ row is a guard worth adopting once you understand the footnote; each ✗ row is unavailable — if your threat model requires the class that mitigation addresses (cross-reference [Defense mechanism inventory](defense-mechanisms.md)), you need to change environments.

## systemd unit (`/etc/systemd/system/secret-service-app.service`)

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

## AppArmor profile (`/etc/apparmor.d/usr.bin.java.secret-service-app`)

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

## SELinux policy module (`secret_service_app.te`)

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

## D-Bus session-bus policy (`/usr/share/dbus-1/session.d/org.example.secret-service-app.conf`)

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

## Dockerfile + `docker-compose.yml`

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

## Flatpak manifest (`org.example.SecretServiceApp.yml`)

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

## Snap recipe (`snap/snapcraft.yaml`)

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

## udev rule (`/etc/udev/rules.d/99-secret-service-tpm.rules`)

```
# Verify with: udevadm control --reload && udevadm test /sys/class/tpm/tpm0
# Pin the TPM resource manager device to the tss group at mode 0660.
# Stricter alternative: GROUP="secretsvc", MODE="0660" — denies all other UIDs.
KERNEL=="tpmrm0", SUBSYSTEM=="tpm", GROUP="tss", MODE="0660"
KERNEL=="tpm0",   SUBSYSTEM=="tpm", GROUP="tss", MODE="0660"
```

After install: `udevadm control --reload && udevadm trigger`. Verify with `ls -la /dev/tpmrm0`.

## JVM launcher (`/usr/bin/secret-service-app`)

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

# Desktop App consumer scenarios

*Part of the [Security & deployment guide](index.md).*


You are building a Linux desktop application that depends on `de.swiesend:secret-service` to read or write user secrets via the Secret Service daemon. Your users run a typical Linux desktop with `gnome-keyring-daemon` or KeePassXC providing the bus. The threats you must care about are dominated by **class A** (the CVE-2018-19358 same-UID attacker — a malicious `.desktop` file, a compromised browser extension, a curl|sh script the user ran an hour ago) and **class C** (the laptop gets stolen). Class B and D apply at the margins.

Step by step, by distribution format. For each: *what your users get out of the box*, *what you must add*, *what your library configuration should look like*, and *what to verify before shipping*.

## Plain binary archive (`tar.gz` / `zip`)

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

## Self-contained JAR (`java -jar yourapp.jar`)

**What this looks like.** A single `yourapp.jar` (Maven Shade / shadowJar / jlink runtime image). User runs `java -jar yourapp.jar`.

**What your users get.** Even less than [Plain binary archive (`tar.gz` / `zip`)](#plain-binary-archive-targz-zip) — no launcher means no place for `ulimit -c 0` or `-XX:+DisableAttachMechanism` unless the user reads your README and types them in by hand.

**Library configuration.** Same as [Plain binary archive (`tar.gz` / `zip`)](#plain-binary-archive-targz-zip). Enable memory locking with `HardenedCollection.builder(...).lockMemory(true)` so memory hygiene at least partially holds without operator help — this uses the JDK FFM `mlockall`, so add `--enable-native-access=de.swiesend.secretservice.hardened` and grant `CAP_IPC_LOCK` / a sufficient `RLIMIT_MEMLOCK`; see [Memory hygiene (mlockall, no swap, no core dumps, no attach)](defense-mechanisms.md#memory-hygiene-mlockall-no-swap-no-core-dumps-no-attach) for details.

**Class coverage.** Same as [Plain binary archive (`tar.gz` / `zip`)](#plain-binary-archive-targz-zip), *minus* the launcher-set JVM flags. Effectively no improvement over a vanilla `java -jar`.

**Pitfalls.**
- Shadow-JAR'ing `bcprov-jdk18on` (BouncyCastle) into your fat JAR can trip JCE provider signing requirements at runtime. Test on a vanilla JDK 25 install, not just your dev box. (BouncyCastle is optional and only needed for `Argon2KeyMaterialProvider`; the ML-KEM hybrid uses the stock SunJCE provider.)
- `java -jar` ignores `-XX` flags before the `-jar` argument unless the user types them.

**Ship-readiness check.**
```sh
mvn package
java -jar target/yourapp-3.0.0.jar --version  # smoke test on JDK 25
```

**Recommendation.** Use [jpackage-built `.deb` / `.rpm`](#jpackage-built-deb-rpm) (jpackage) instead of [Self-contained JAR (`java -jar yourapp.jar`)](#self-contained-jar-java-jar-yourappjar) for desktop apps — it gives you the launcher and the install path for free.

## jpackage-built `.deb` / `.rpm`

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
- `/etc/apparmor.d/usr.bin.yourapp` (see [AppArmor profile (`/etc/apparmor.d/usr.bin.java.secret-service-app`)](sample-configurations.md#apparmor-profile-etcapparmordusrbinjavasecret-service-app) — copy-paste, adjust the binary path).
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

## AppImage

**The single root cause.** AppImage has no install path. The user `chmod +x`-es a self-extracting squashfs that mounts at runtime in `/tmp/.mount_xxxxxx/` (a randomised path that changes every run) and unmounts when the process exits. **AppImage's defining feature — no install path — is exactly what every Linux security framework needs to attach a policy. For an app that handles secrets, that's the whole problem.**

**What this means concretely.**

- **No AppArmor / SELinux profile.** Both are path-based; the AppImage's binary lives at a randomised mount point, so you cannot ship a profile that confines it.
- **No D-Bus policy fragment.** Session-bus drop-in lives in `/usr/share/dbus-1/session.d/`; an AppImage isn't "installed" so there is nowhere to register one.
- **No systemd unit.** No place for the rich `Protect*=` / `Restrict*=` / `SystemCallFilter=` directives that [systemd unit hardening](defense-mechanisms.md#systemd-unit-hardening) leans on.
- **No udev rule.** No place to scope `/dev/tpmrm0` access to your binary specifically.
- **No package signing in practice.** AppImage's embedded GPG-signature option exists but almost no user or updater verifies it.

**Class coverage.** Same as [Plain binary archive (`tar.gz` / `zip`)](#plain-binary-archive-targz-zip) (plain `tar.gz`) *minus* the launcher script — some AppImage builders rewrite the entrypoint, so even the `-XX:+DisableAttachMechanism` flag from [Plain binary archive (`tar.gz` / `zip`)](#plain-binary-archive-targz-zip) is not guaranteed. NONE for A/B, depends-on-host for C.

**Asymmetry vs Flatpak / Snap (the other "single-file portable" formats).** AppImage's lack of a stable install path means it can talk to the TPM directly (no sandbox to break) — but it also means it has no other defenses. Flatpak and Snap make a tradeoff (give up some flexibility, gain a sandbox); AppImage makes neither half of that tradeoff.

**When AppImage is fine.** One-off troubleshooting tools, image/video editors, portable USB-stick apps, demos and pre-release builds, bridging old distros via bundled `glibc`. The "no install" property is a feature for those use-cases.

**When it is not.** Any app whose threat model includes class A or class B (per [Threat catalogue](threat-catalogue.md)). For those, AppImage gives you nothing the OS can attach guards to.

**Recommendation.** Avoid AppImage for secret-handling desktop apps. Use [jpackage-built `.deb` / `.rpm`](#jpackage-built-deb-rpm) (jpackage `.deb`/`.rpm`) when class-A defense matters; [Snap](#snap) (Snap) when you also want strict-confinement plus first-class TPM via the `tpm` interface.

## Flatpak

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
2. **Drop Flatpak for this app.** If your threat model demands TPM, ship via [jpackage-built `.deb` / `.rpm`](#jpackage-built-deb-rpm) (`.deb`/`.rpm`) and document why Flatpak isn't on the menu.

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

## Snap

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

## Nix / NixPkgs / Home Manager

**What this looks like.** A Nix derivation that produces a `/nix/store/<hash>-yourapp/` tree. NixOS / Home-Manager users add it to their config; non-NixOS users `nix-env -iA`.

**What your users get.** Reproducible builds, content-addressed store, `/nix/store` is read-only by construction. NixOS modules can declare a complete deployment (package + AppArmor profile + udev rule + D-Bus policy) in one Nix expression. Closest thing to "distribution and policy in one place."

**Library configuration.** Same as [jpackage-built `.deb` / `.rpm`](#jpackage-built-deb-rpm) — TPM provider is recommended, AppArmor profile shipped via the module's `security.apparmor.policies` option.

**Class coverage.** Equivalent to [jpackage-built `.deb` / `.rpm`](#jpackage-built-deb-rpm) (`.deb`/`.rpm`) for a NixOS user, plus reproducibility (mitigates supply-chain class of attack against the build).

**Recommendation.** Ship a Nix flake alongside [jpackage-built `.deb` / `.rpm`](#jpackage-built-deb-rpm) for the NixOS minority. Don't make Nix your only Linux distribution path — Nix-only desktop apps stay a niche.

## Quick decision tree for desktop apps

```
Does your app handle real user secrets?
├── No  → AppImage is fine; ignore the rest of this section.
└── Yes
    ├── Do you need TPM-sealed pepper?
    │   ├── Yes → “jpackage-built `.deb` / `.rpm`” (desktop-deployment.md) (.deb/.rpm) preferred; “Snap” (desktop-deployment.md) (Snap) viable.
    │   │        AVOID Flatpak (“Flatpak” (desktop-deployment.md)) — TPM tension.
    │   └── No  → “jpackage-built `.deb` / `.rpm`” (desktop-deployment.md) (.deb/.rpm) for OS integration; “Flatpak” (desktop-deployment.md) (Flatpak via
    │             portal) for sandboxed cross-distro reach.
    └── Are users primarily on Ubuntu / Ubuntu Core?
        └── Strongly consider “Snap” (desktop-deployment.md) (Snap) — best Linux sandbox + TPM.
```

The plain `tar.gz` ([Plain binary archive (`tar.gz` / `zip`)](#plain-binary-archive-targz-zip)) and self-contained JAR ([Self-contained JAR (`java -jar yourapp.jar`)](#self-contained-jar-java-jar-yourappjar)) remain useful for power-user releases and Java-savvy audiences but should not be your only Linux distribution channel for a secret-handling app.

---

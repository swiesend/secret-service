# D-Bus policy in detail

*Part of the [Security & deployment guide](index.md).*


D-Bus has two buses with different security postures. Knowing the difference matters because **Secret Service is on the session bus** — and the session bus's policy surface is fundamentally limited.

## System bus vs session bus

| | System bus | Session bus |
|---|---|---|
| Daemon address | `unix:path=/var/run/dbus/system_bus_socket` | `unix:path=$XDG_RUNTIME_DIR/bus` |
| Runs as | `messagebus` / `dbus-daemon` system user | The user themselves |
| Policy files | `/etc/dbus-1/system.d/*.conf` (admin), `/usr/share/dbus-1/system.d/*.conf` (vendor) | `/etc/dbus-1/session.d/*.conf`, `/usr/share/dbus-1/session.d/*.conf`, `~/.config/dbus-1/session.d/*.conf` |
| Default policy | Deny-by-default; vendors must explicitly allow access | Allow-by-default for the user's own UID; cross-UID access is rare |
| Used by | systemd, NetworkManager, polkit, udisks2 | gnome-shell, **gnome-keyring**, **KeePassXC**, pipewire |

**Secret Service is session-bus-only.** No `/etc/dbus-1/system.d/` configuration applies to it.

## Session-bus policy XML

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

## What you can policy-control

- **Deny cross-UID access entirely.** A `<policy user="malicious-uid"><deny send_destination="org.freedesktop.secrets"/></policy>` block stops class B from talking to the daemon.
- **Restrict to specific interfaces.** Allow `org.freedesktop.Secret.Service` but deny `org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface` so even legitimate clients can't reach the privileged GNOME-specific surface.
- **Restrict bus name ownership.** `<deny own="org.freedesktop.secrets"/>` for everyone except the daemon binary's UID prevents an attacker from squatting the bus name.
- **Block eavesdropping.** Deny `eavesdrop="true"` (rarely needed; only `dbus-monitor`-style tools care).

## What you cannot policy-control

- **Same-UID access (class A).** The session bus runs as the user; the user can rewrite `~/.config/dbus-1/session.d/*.conf`, restart the bus, or just connect with the right credentials. Session-bus policy is **not** a class-A defense.
- **Replacement of the daemon.** A class-A attacker can launch their own dbus-daemon and arrange for legitimate clients to connect to it. Defenses against that live in MAC, not in dbus-daemon's own policy.

**Headline:** session-bus policy buys you defense against class B (cross-UID via leaked `DBUS_SESSION_BUS_ADDRESS`) and against accidental cross-app interactions. It does not meaningfully constrain class A.

## Polkit interplay

Polkit (formerly PolicyKit) gates D-Bus method calls behind authorisation rules — typically prompting the user via an agent (`gnome-shell`, `pkexec`, `lxpolkit`). Standard freedesktop Secret Service does **not** require polkit; the daemon's own auth (collection unlock prompt) is internal.

The library's deferred-loaded `org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface` interacts with polkit on some distributions (mostly for the `unlockWithMasterPassword` admin operation). If you carry a polkit policy that restricts this interface, the library tolerates the deferred-load failure cleanly.

## KeePassXC's per-item ACL prompt

KeePassXC's Secret Service implementation is the only Secret Service backend that defends against **class A** without requiring MAC. When an unknown caller asks for an item, KeePassXC prompts the user interactively before exposing the secret. This is finer-grained than D-Bus policy can express (D-Bus matches on bus name / interface / member, not on bus-name → KeePass-database-item).

See [Secret Service backend choice](backend-choice.md) for the full backend comparison.

## dbus-broker

`dbus-broker` is the systemd-blessed replacement for the reference `dbus-daemon`. Default in Fedora ≥ 30, Arch, RHEL ≥ 9. It uses the **same policy XML format** as `dbus-daemon`, so everything in [Session-bus policy XML](#session-bus-policy-xml)–[What you cannot policy-control](#what-you-cannot-policy-control) applies identically. Faster, more memory-efficient, but the security surface is unchanged.

## Worked example: deny class-B sidecar from the session bus

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

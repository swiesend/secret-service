#!/usr/bin/env bash
set -euo pipefail

# Bring up the session bus (exports DBUS_SESSION_BUS_ADDRESS, defines wait_for_secrets).
source /providers/dbus-up.sh

LOG_DIR="${PROVIDER_LOG_DIR:-/workspace/target/provider-logs}"
# Probe writability, not just mkdir: a read-only /workspace mount fails at write time,
# not at mkdir, and falling back silently leaves an empty CI artifact with nothing
# saying why.
if ! ( mkdir -p "$LOG_DIR" && touch "$LOG_DIR/.probe" ) 2>/dev/null; then
    echo "WARNING: ${LOG_DIR} is not writable; logs go to /tmp and will NOT survive the"
    echo "         container, so the CI diagnostics artifact will be empty."
    LOG_DIR=/tmp
fi
rm -f "$LOG_DIR/.probe" 2>/dev/null || true
XVFB_LOG="$LOG_DIR/xvfb.log"
KPXC_LOG="$LOG_DIR/keepassxc.log"

# Diagnostics go under the mounted workspace, not /tmp. The container runs --rm, so a
# failing leg used to take its own explanation with it: the logs died with the
# container and the job showed only a timeout.
dump_diagnostics() {
    echo "----- versions -----"
    cat /image-keepassxc-version 2>/dev/null || echo "keepassxc: unknown"
    echo "display: ${DISPLAY:-unset}"
    echo "----- xvfb.log -----";      cat "$XVFB_LOG"  2>/dev/null || echo "(none)"
    echo "----- keepassxc.log -----"; cat "$KPXC_LOG" 2>/dev/null || echo "(none)"
}

# KeePassXC is a GUI application, so it needs an X server.
#
# Previously: "Xvfb :99 & sleep 2" — a fixed sleep that races. On a loaded runner
# KeePassXC could start against a server that was not yet accepting connections, and
# the failure surfaced 30 seconds later as "no collection exposed", which points at
# the database fixture rather than at the X server.
#
# koppor's CI draft (https://github.com/swiesend/secret-service/pull/43) used
# "xvfb-run --auto-servernum", which fixes both the race and the fixed display number.
# The mechanism does not survive this container: xvfb-run waits for Xvfb to report
# readiness by SIGUSR1 to its parent, and as PID 1 under Docker that handshake does
# not complete — verified, it hangs indefinitely rather than starting the command.
# So the idea is kept and the mechanism is not: pick a free display, then poll for the
# socket instead of sleeping.
start_x_server() {
    local n=99
    while [ -e "/tmp/.X${n}-lock" ] || [ -e "/tmp/.X11-unix/X${n}" ]; do
        n=$((n + 1))
        [ "$n" -gt 199 ] && { echo "ERROR: no free X display number."; return 1; }
    done
    export DISPLAY=":${n}"

    Xvfb "$DISPLAY" -screen 0 1024x768x16 > "$XVFB_LOG" 2>&1 &
    XVFB_PID=$!

    local waited=0
    until [ -e "/tmp/.X11-unix/X${n}" ]; do
        if ! kill -0 "$XVFB_PID" 2>/dev/null; then
            echo "ERROR: Xvfb exited during startup:"; cat "$XVFB_LOG" 2>/dev/null
            return 1
        fi
        sleep 1; waited=$((waited + 1))
        if [ "$waited" -ge 15 ]; then
            echo "ERROR: Xvfb did not accept connections on $DISPLAY within 15s:"
            cat "$XVFB_LOG" 2>/dev/null
            return 1
        fi
    done
    echo "Xvfb ready on $DISPLAY (after ${waited}s)"
}

start_x_server

DB="$HOME/test.kdbx"
PW="test"

# Use the committed fixture database: collection "test", password "test", with a
# group exposed over Secret Service (group exposure is stored inside the .kdbx and
# cannot be set via keepassxc-cli, so the database is checked in). Copy it to a
# writable location since KeePassXC may write back to it.
mkdir -p "$HOME"
cp /providers/keepassxc/test.kdbx "$DB"

# Whether KeePassXC asks for confirmation before releasing an item's secret.
#
# With confirmation ON, KeePassXC reports items as individually locked and prompts per
# item — the behaviour the freedesktop spec anticipates and the one gnome-keyring never
# exhibits. Nothing here answers the dialog; that would need xdotool and would be
# flaky. The suite instead asserts the library refuses cleanly when prompting is
# disabled, which needs no interaction and so stays deterministic.
CONFIRM_ACCESS_ITEM="${KPXC_CONFIRM_ACCESS_ITEM:-false}"

mkdir -p "$HOME/.config/keepassxc"
cat > "$HOME/.config/keepassxc/keepassxc.ini" << KPXCINI
[General]
ConfigVersion=2

[FdoSecrets]
Enabled=true
ShowNotification=false
ConfirmAccessItem=${CONFIRM_ACCESS_ITEM}
ConfirmDeleteItem=false
KPXCINI

# Poll the Service "Collections" property until KeePassXC exposes the database's
# group as a collection (the unlock + exposure lags behind bus registration).
wait_for_collection() {
    local timeout="${1:-30}" waited=0 out
    while true; do
        out="$(dbus-send --session --print-reply --dest=org.freedesktop.secrets \
            /org/freedesktop/secrets org.freedesktop.DBus.Properties.Get \
            string:org.freedesktop.Secret.Service string:Collections 2>/dev/null || true)"
        if echo "$out" | grep -q '/org/freedesktop/secrets/collection/'; then
            echo "Exposed collections:"
            echo "$out" | grep -o '/org/freedesktop/secrets/collection/[^"]*'
            return 0
        fi
        # Fail fast when the process is already gone, instead of waiting out the whole
        # timeout and then blaming the exposure.
        if ! kill -0 "$KPXC_PID" 2>/dev/null; then
            echo "ERROR: KeePassXC exited before exposing a collection."
            return 2
        fi
        sleep 1; waited=$((waited + 1))
        if [ "$waited" -ge "$timeout" ]; then
            echo "WARNING: no collection exposed after ${timeout}s; Collections reply was:"
            echo "$out"
            return 1
        fi
    done
}

cat /image-keepassxc-version 2>/dev/null || echo "KeePassXC version: unknown"
echo "FdoSecrets ConfirmAccessItem=${CONFIRM_ACCESS_ITEM}"

# Launch KeePassXC and unlock it through its own dialog.
#
# NOT --pw-stdin. That flag prints "Database password:" and then never completes the
# unlock in this container -- verified against a pipe, against stdin held open, and
# against a real PTY via script(1). The database stays locked, and the KeePassXC docs
# are explicit that there is one Collection per *opened database tab*, so nothing can
# ever be exposed. That single fact is why this leg has never tested anything.
#
# Typing into the dialog is what a user does and it demonstrably works. It costs a
# dependency on xdotool and a window to wait for, which is a fair price for a leg that
# actually exercises the provider.
#
# Keep the PID. The original "( ... & ) || true" detached into a subshell and discarded
# the launch result, so a KeePassXC that died on startup looked exactly like one that
# was merely slow -- every failure presented as a 45-second timeout.
keepassxc "$DB" > "$KPXC_LOG" 2>&1 &
KPXC_PID=$!

# Wait for the unlock dialog, then type the password into it.
unlock_database() {
    local waited=0 win=""
    until [ -n "$win" ]; do
        win="$(xdotool search --name "\[Locked\]" 2>/dev/null | head -1)"
        [ -n "$win" ] && break
        if ! kill -0 "$KPXC_PID" 2>/dev/null; then
            echo "ERROR: KeePassXC exited before showing its unlock dialog."
            return 1
        fi
        sleep 1; waited=$((waited + 1))
        if [ "$waited" -ge 30 ]; then
            echo "ERROR: no unlock window appeared within 30s."
            return 1
        fi
    done
    xdotool windowactivate --sync "$win" 2>/dev/null || true
    sleep 1
    xdotool type --delay 60 "$PW"
    sleep 1
    xdotool key Return
    echo "Typed the database password into the unlock dialog (after ${waited}s)."
}

if ! unlock_database; then
    dump_diagnostics
    exit 1
fi

if ! wait_for_secrets 45 "$KPXC_PID"; then
    echo "ERROR: KeePassXC did not register org.freedesktop.secrets."
    dump_diagnostics
    exit 1
fi
echo "KeePassXC Secret Service ready (provider: KeePassXC)"

# Wait for the fixture's group to be exposed as a collection.
#
# This is fatal, and that is a deliberate change. Without a collection every test in
# ProviderSystemTest skips through its Assumptions, so the leg passed while asserting
# nothing about KeePassXC — the exact failure mode that hides a broken provider. The
# leg is continue-on-error in system-tests.yml, so reporting the truth here colours one
# non-blocking job red instead of silently claiming coverage that does not exist.
# KPXC_REQUIRE_COLLECTION=false keeps the container usable for debugging. Exiting here
# would otherwise take the interactive case with it: "docker run ... bash" to inspect a
# provider that is failing to expose anything is exactly when you cannot afford the
# entrypoint to quit first.
REQUIRE_COLLECTION="${KPXC_REQUIRE_COLLECTION:-true}"

wait_for_collection 30 && collection_status=0 || collection_status=$?
if [ "$collection_status" -ne 0 ]; then
    dump_diagnostics
    echo
    if [ "$collection_status" -eq 2 ]; then
        # Died rather than timed out: pointing at the fixture here would repeat the
        # misattribution this script exists to remove.
        echo "KeePassXC exited during startup — see the log above, not the fixture."
    else
        echo "The database opened but exposes no collection, so every test would skip."
        echo "The exposed group is recorded in the database's own custom data under"
        echo "FDO_SECRETS_EXPOSED_GROUP, as a braced UUID -- {xxxxxxxx-xxxx-...} -- not"
        echo "the bare hex form. It is written by the KeePassXC GUI: Database Settings ->"
        echo "Secret Service Integration -> Expose entries under this group."
    fi
    if [ "$REQUIRE_COLLECTION" != "false" ]; then
        echo "Refusing to report a pass for a run that asserts nothing."
        echo "Set KPXC_REQUIRE_COLLECTION=false to continue anyway (debugging)."
        exit 1
    fi
    echo "KPXC_REQUIRE_COLLECTION=false — continuing without coverage."
fi

# Run the provided command, defaulting to the system-test profile.
if [ $# -eq 0 ]; then
    exec mvn -B test -Psystem-test
else
    exec "$@"
fi

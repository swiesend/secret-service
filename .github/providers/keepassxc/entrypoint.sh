#!/usr/bin/env bash
set -euo pipefail

# Bring up the session bus (exports DBUS_SESSION_BUS_ADDRESS, defines wait_for_secrets).
source /providers/dbus-up.sh

# A virtual display — KeePassXC is a GUI application.
export DISPLAY=":99"
Xvfb "$DISPLAY" -screen 0 1024x768x16 >/tmp/xvfb.log 2>&1 &
sleep 2

DB="$HOME/test.kdbx"
PW="test"

# Use the committed fixture database: collection "test", password "test", with a
# group exposed over Secret Service (group exposure is stored inside the .kdbx and
# cannot be set via keepassxc-cli, so the database is checked in). Copy it to a
# writable location since KeePassXC may write back to it.
mkdir -p "$HOME"
cp /providers/keepassxc/test.kdbx "$DB"

# Enable Secret Service integration (KeePassXC calls it "FdoSecrets").
mkdir -p "$HOME/.config/keepassxc"
cat > "$HOME/.config/keepassxc/keepassxc.ini" << 'KPXCINI'
[General]
ConfigVersion=2

[FdoSecrets]
Enabled=true
ShowNotification=false
ConfirmAccessItem=false
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
        sleep 1; waited=$((waited + 1))
        if [ "$waited" -ge "$timeout" ]; then
            echo "WARNING: no collection exposed after ${timeout}s; Collections reply was:"
            echo "$out"
            return 1
        fi
    done
}

echo "KeePassXC version: $(keepassxc --version 2>/dev/null || echo unknown)"

# Launch KeePassXC unlocked against the database; it then exposes the Secret Service.
( printf '%s\n' "$PW" | keepassxc --pw-stdin "$DB" >/tmp/keepassxc.log 2>&1 & ) || true

if ! wait_for_secrets 45; then
    echo "WARNING: KeePassXC did not register org.freedesktop.secrets — dumping logs:"
    cat /tmp/keepassxc.log || true
    exit 1
fi
echo "KeePassXC Secret Service ready (provider: KeePassXC)"

# Wait for the fixture's group to be exposed as a collection. Non-fatal: if it
# never appears the system suite skips, and the diagnostics above explain why.
if ! wait_for_collection 30; then
    echo "----- keepassxc.log -----"; cat /tmp/keepassxc.log || true
fi

# Run the provided command, defaulting to the system-test profile.
if [ $# -eq 0 ]; then
    exec mvn -B test -Psystem-test
else
    exec "$@"
fi

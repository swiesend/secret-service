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

# Create a database "test.kdbx" with a "test" entry (password: test).
mkdir -p "$HOME"
printf '%s\n%s\n' "$PW" "$PW" | keepassxc-cli db-create "$DB" --set-password >/dev/null 2>&1 || true
printf '%s\n' "$PW" | keepassxc-cli add "$DB" --username it --password-prompt "test/seed" >/dev/null 2>&1 || true

# Enable Secret Service integration in the KeePassXC config.
mkdir -p "$HOME/.config/keepassxc"
cat > "$HOME/.config/keepassxc/keepassxc.ini" << 'KPXCINI'
[General]
ConfigVersion=2

[SecretService]
Enabled=true
ShowNotification=false
ConfirmAccessItem=false
KPXCINI

# Launch KeePassXC unlocked against the database; it then exposes the Secret Service.
( printf '%s\n' "$PW" | keepassxc --pw-stdin "$DB" >/tmp/keepassxc.log 2>&1 & ) || true

if ! wait_for_secrets 45; then
    echo "WARNING: KeePassXC did not register org.freedesktop.secrets — dumping logs:"
    cat /tmp/keepassxc.log || true
    exit 1
fi
echo "KeePassXC Secret Service ready (provider: KeePassXC)"

# Run the provided command, defaulting to the system-test profile.
if [ $# -eq 0 ]; then
    exec mvn -B test -Psystem-test
else
    exec "$@"
fi

#!/usr/bin/env bash
set -euo pipefail

# Bring up the session bus (exports DBUS_SESSION_BUS_ADDRESS, defines wait_for_secrets).
source /providers/dbus-up.sh

# A virtual display — kwalletd is a desktop-session daemon.
export DISPLAY=":99"
Xvfb "$DISPLAY" -screen 0 1024x768x16 >/tmp/xvfb.log 2>&1 &
sleep 2

# Pre-seed kwalletrc so the default wallet ("kdewallet") is usable without an
# interactive dialog: blank-password, unencrypted wallet, Secret Service enabled.
mkdir -p "$HOME/.config"
cat > "$HOME/.config/kwalletrc" << 'KWALLETRC'
[Wallet]
Enabled=true
First Use=false
Use One Wallet=true
Default Wallet=kdewallet
Prompt on Open=false
Close When Idle=false
Leave Open=true

[org.freedesktop.secrets]
apiEnabled=true
KWALLETRC

# Start kwalletd5; it registers org.freedesktop.secrets when Secret Service is enabled.
kwalletd5 >/tmp/kwalletd5.log 2>&1 &

# Best-effort: create/open the default wallet so a collection is exposed.
# int open(QString wallet, qlonglong wId, QString appid)
( dbus-send --session --dest=org.kde.kwalletd5 --type=method_call --print-reply \
    /modules/kwalletd5 org.kde.KWallet.open \
    string:kdewallet int64:0 string:secret-service-it \
    >/dev/null 2>&1 || true ) &

if ! wait_for_secrets 45; then
    echo "WARNING: KWallet did not register org.freedesktop.secrets — dumping logs:"
    cat /tmp/kwalletd5.log || true
    exit 1
fi
echo "KWallet Secret Service ready (provider: KWallet)"

# Run the provided command, defaulting to the system-test profile.
if [ $# -eq 0 ]; then
    exec mvn -B test -Psystem-test
else
    exec "$@"
fi

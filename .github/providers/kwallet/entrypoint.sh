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

# Wait for a collection, as the keepassxc entrypoint does, and for the same reason: without one
# every test in ProviderSystemTest skips through its Assumptions, and the leg passed while it
# asserted nothing about KWallet. It is continue-on-error in system-tests.yml, so the truth colours
# one non-blocking job red instead of claiming coverage that does not exist.
#
# Headless, kwalletd5 creates no wallet: opening kdewallet above brings up its "new wallet"
# dialog, which nobody answers under Xvfb. KWALLET_REQUIRE_COLLECTION=false keeps the container
# usable for debugging.
REQUIRE_COLLECTION="${KWALLET_REQUIRE_COLLECTION:-true}"
collections=""
for _ in $(seq 1 15); do
    collections="$(dbus-send --session --print-reply --dest=org.freedesktop.secrets \
        /org/freedesktop/secrets org.freedesktop.DBus.Properties.Get \
        string:org.freedesktop.Secret.Service string:Collections 2>/dev/null \
        | grep -o '/org/freedesktop/secrets/collection/[^"]*' || true)"
    [ -n "$collections" ] && break
    sleep 1
done
if [ -n "$collections" ]; then
    echo "Exposed collections:"
    echo "$collections"
else
    echo "KWallet exposes no collection, so every test would skip. kwalletd5.log:"
    cat /tmp/kwalletd5.log || true
    if [ "$REQUIRE_COLLECTION" != "false" ]; then
        echo "Refusing to report a pass for a run that asserts nothing."
        echo "Set KWALLET_REQUIRE_COLLECTION=false to continue anyway (debugging)."
        exit 1
    fi
    echo "KWALLET_REQUIRE_COLLECTION=false — continuing without coverage."
fi

# Run the provided command, defaulting to the system-test profile on this container's own,
# throwaway wallet. ProviderSystemTest uses only the collection it is told to.
if [ $# -eq 0 ]; then
    exec mvn -B test -Psystem-test -Dsecret-service.system-test.collection=kdewallet
else
    exec "$@"
fi

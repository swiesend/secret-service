#!/usr/bin/env bash
set -euo pipefail

# Bring up the session bus (exports DBUS_SESSION_BUS_ADDRESS, defines wait_for_secrets).
source /providers/dbus-up.sh

# kwalletd's log goes under the mounted workspace, as keepassxc's does: the container runs --rm,
# and a log in /tmp died with it, so a leg that failed before Maven ran left no explanation.
LOG_DIR="${PROVIDER_LOG_DIR:-/workspace/target/provider-logs}"
# Probe writability, not just mkdir: a read-only /workspace mount fails at write time.
if ! ( mkdir -p "$LOG_DIR" && touch "$LOG_DIR/.probe" ) 2>/dev/null; then
    echo "WARNING: ${LOG_DIR} is not writable; logs go to /tmp and will NOT survive the"
    echo "         container, so the CI diagnostics artifact will be empty."
    LOG_DIR=/tmp
fi
rm -f "$LOG_DIR/.probe" 2>/dev/null || true

# No X server: nothing here answers a dialog, and with the wallet opened as at a login, kwalletd
# shows none.
export QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-offscreen}"
export XDG_RUNTIME_DIR=/tmp/xdg-runtime
mkdir -p -m 700 "$XDG_RUNTIME_DIR"

# The default wallet ("kdewallet"), kept open, with the Secret Service API enabled.
mkdir -p "$HOME/.config"
cat > "$HOME/.config/kwalletrc" << 'KWALLETRC'
[Wallet]
Enabled=true
First Use=false
Use One Wallet=true
Default Wallet=kdewallet
Prompt on Open=false
Close When Idle=false
Close on Screensaver=false
Leave Open=true

[org.freedesktop.secrets]
apiEnabled=true
KWALLETRC

# kwalletd starts as pam_kwallet starts it at a Plasma login: it creates kdewallet with the login
# password, an empty one here, and opens it. Opening kdewallet over D-Bus instead brings up the
# "new wallet" dialog, which nobody answers. It registers org.freedesktop.secrets itself.
KWALLETD="${KWALLETD:-kwalletd5}"
KWALLETD_LOG="$LOG_DIR/kwalletd.log"
pid="$(python3 /providers/kwallet/kwallet-up.py "$KWALLETD" "$KWALLETD_LOG")"

if ! wait_for_secrets 45 "$pid"; then
    echo "WARNING: KWallet did not register org.freedesktop.secrets — dumping logs:"
    cat "$KWALLETD_LOG" || true
    exit 1
fi
echo "KWallet Secret Service ready (provider: KWallet)"

# Wait for the collection, as the keepassxc entrypoint does, and for the same reason: without one
# every test in ProviderSystemTest skips through its Assumptions, and the leg would pass while it
# asserted nothing about KWallet. KWALLET_REQUIRE_COLLECTION=false keeps the container usable for
# debugging.
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
    echo "KWallet exposes no collection, so every test would skip. ${KWALLETD} log:"
    cat "$KWALLETD_LOG" || true
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

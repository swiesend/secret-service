#!/usr/bin/env bash
set -euo pipefail

# Bring up the session bus (exports DBUS_SESSION_BUS_ADDRESS, defines wait_for_secrets).
source /providers/dbus-up.sh

# The daemon's log goes under the mounted workspace, which the CI job collects when the leg fails.
LOG_DIR="${PROVIDER_LOG_DIR:-/workspace/target/provider-logs}"
if ! ( mkdir -p "$LOG_DIR" && touch "$LOG_DIR/.probe" ) 2>/dev/null; then
    echo "WARNING: ${LOG_DIR} is not writable; the daemon's log goes to /tmp and will not survive"
    echo "         the container."
    LOG_DIR=/tmp
fi
rm -f "$LOG_DIR/.probe" 2>/dev/null || true
OO7_LOG="$LOG_DIR/oo7-daemon.log"
PROMPTER_LOG="$LOG_DIR/prompter.log"
cat /image-oo7-version

# The daemon asks for the password of every unlock after a Lock, outside a graphical session
# through its CLI prompter, and the functional API locks and unlocks a collection for the user's
# permission. prompter.py serves the CLI prompter and answers with the login password.
python3 -I /providers/oo7/prompter.py test > "$PROMPTER_LOG" 2>&1 &
PROMPTER_PID=$!

# The daemon puts its login-helper socket under XDG_RUNTIME_DIR, which a login sets up.
export XDG_RUNTIME_DIR="/run/user/$(id -u)"
mkdir -p -m 700 "$XDG_RUNTIME_DIR"
# And its keyrings under ~/.local/share/keyrings. It drops CAP_DAC_OVERRIDE before it writes one,
# and Fedora's /root is read-only to its owner, so the directory is made here.
mkdir -p "$HOME/.local/share/keyrings"

# --login reads a password from stdin and unlocks the login keyring with it, creating the keyring
# on the first start, as pam_oo7 does at a login. The system tests use that collection, "login".
printf '%s' test | /usr/libexec/oo7-daemon --login --verbose > "$OO7_LOG" 2>&1 &
OO7_PID=$!

if ! wait_for_secrets 30 "$OO7_PID"; then
    echo "----- oo7-daemon.log -----"
    cat "$OO7_LOG" 2>/dev/null || echo "(none)"
    exit 1
fi
if ! kill -0 "$PROMPTER_PID" 2>/dev/null; then
    echo "ERROR: prompter.py exited:"
    cat "$PROMPTER_LOG" 2>/dev/null || echo "(no log)"
    exit 1
fi

# The daemon owns its bus name before it has set up the login keyring, and a test that looks for
# the collection too early finds only the in-memory "session" one.
waited=0
until dbus-send --session --print-reply --dest=org.freedesktop.secrets /org/freedesktop/secrets \
        org.freedesktop.DBus.Properties.Get string:org.freedesktop.Secret.Service string:Collections \
        2>/dev/null | grep -q '/org/freedesktop/secrets/collection/login"'; do
    sleep 1; waited=$((waited + 1))
    if [ "$waited" -ge 30 ]; then
        echo "ERROR: oo7-daemon exposes no login collection after 30s:"
        cat "$OO7_LOG" 2>/dev/null || echo "(no log)"
        exit 1
    fi
done
echo "oo7-daemon ready, with its login collection (after ${waited}s)"

# Run the provided command, defaulting to the system-test profile.
if [ $# -eq 0 ]; then
    exec mvn -B test -Psystem-test -Dsecret-service.system-test.collection=login
else
    exec "$@"
fi

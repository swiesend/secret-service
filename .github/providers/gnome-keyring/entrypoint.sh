#!/usr/bin/env bash
set -euo pipefail

# Bring up the session bus (exports DBUS_SESSION_BUS_ADDRESS, defines wait_for_secrets).
source /providers/dbus-up.sh

# Start gnome-keyring-daemon in unlocked mode (empty password) — no UI prompts in CI.
echo "" | gnome-keyring-daemon --unlock --components=secrets
wait_for_secrets 30
echo "gnome-keyring-daemon ready"

# Run the provided command, defaulting to the full regression test suite.
if [ $# -eq 0 ]; then
    exec mvn -B test
else
    exec "$@"
fi

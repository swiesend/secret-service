#!/usr/bin/env bash
set -euo pipefail

# Start D-Bus session bus
eval "$(dbus-launch --sh-syntax)"
export DBUS_SESSION_BUS_ADDRESS

# Start gnome-keyring-daemon in unlocked mode (empty password)
echo "" | gnome-keyring-daemon --unlock --components=secrets

# Run the provided command, defaulting to Maven test
if [ $# -eq 0 ]; then
    exec mvn -B test
else
    exec "$@"
fi

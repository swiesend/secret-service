#!/usr/bin/env bash
set -euo pipefail

# dbus-java-transport-native-unixsocket requires path-based unix sockets,
# not abstract sockets (which are the default on Linux).
# Create a custom D-Bus session config with path-based listening.
cat > /tmp/dbus-session-path.conf << 'DBUSCONF'
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>custom</type>
  <listen>unix:tmpdir=/tmp</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
DBUSCONF

# Start D-Bus daemon with path-based socket
DBUS_SESSION_BUS_ADDRESS=$(dbus-daemon --config-file=/tmp/dbus-session-path.conf --print-address --fork)
export DBUS_SESSION_BUS_ADDRESS
echo "D-Bus session bus: $DBUS_SESSION_BUS_ADDRESS"

# Start gnome-keyring-daemon in unlocked mode (empty password)
echo "" | gnome-keyring-daemon --unlock --components=secrets

# Run the provided command, defaulting to Maven test
if [ $# -eq 0 ]; then
    exec mvn -B test
else
    exec "$@"
fi

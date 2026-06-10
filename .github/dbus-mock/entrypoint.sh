#!/usr/bin/env bash
set -euo pipefail

# dbus-java-transport-native-unixsocket requires path-based unix sockets
# (unix:path=...), not abstract sockets (unix:abstract=...) which are
# the Linux default. Use an explicit socket path to guarantee this.

DBUS_SOCKET="/tmp/dbus-test-socket"
rm -f "$DBUS_SOCKET"

cat > /tmp/dbus-session.conf << DBUSCONF
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>custom</type>
  <listen>unix:path=${DBUS_SOCKET}</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
  <!-- Required for gnome-keyring-daemon service activation -->
  <standard_session_servicedirs/>
</busconfig>
DBUSCONF

# Start D-Bus daemon with explicit path-based socket
dbus-daemon --config-file=/tmp/dbus-session.conf --fork --print-pid
export DBUS_SESSION_BUS_ADDRESS="unix:path=${DBUS_SOCKET}"
echo "DBUS_SESSION_BUS_ADDRESS=$DBUS_SESSION_BUS_ADDRESS"

# Verify D-Bus is reachable
dbus-send --session --dest=org.freedesktop.DBus \
  --type=method_call --print-reply \
  /org/freedesktop/DBus org.freedesktop.DBus.ListNames \
  || { echo "ERROR: D-Bus not reachable"; exit 1; }

# Start gnome-keyring-daemon in unlocked mode (empty password)
echo "" | gnome-keyring-daemon --unlock --components=secrets
sleep 1

# Verify Secret Service is registered on the bus
dbus-send --session --dest=org.freedesktop.secrets \
  --type=method_call --print-reply \
  /org/freedesktop/secrets org.freedesktop.DBus.Peer.Ping \
  || { echo "ERROR: org.freedesktop.secrets not available"; exit 1; }
echo "gnome-keyring-daemon ready"

# Run the provided command, defaulting to Maven test
if [ $# -eq 0 ]; then
    exec mvn -B test
else
    exec "$@"
fi

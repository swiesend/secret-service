#!/usr/bin/env bash
# Shared session D-Bus bring-up for the provider test images.
#
# Source this from a provider entrypoint:  source /providers/dbus-up.sh
# It starts a path-based session bus, exports DBUS_SESSION_BUS_ADDRESS, and
# defines wait_for_secrets() which blocks until org.freedesktop.secrets is owned.
#
# dbus-java-transport-native-unixsocket requires path-based unix sockets
# (unix:path=...), not the Linux-default abstract sockets (unix:abstract=...),
# hence the explicit socket path below.

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
  <!-- Required for daemon service activation -->
  <standard_session_servicedirs/>
</busconfig>
DBUSCONF

dbus-daemon --config-file=/tmp/dbus-session.conf --fork --print-pid
export DBUS_SESSION_BUS_ADDRESS="unix:path=${DBUS_SOCKET}"
echo "DBUS_SESSION_BUS_ADDRESS=$DBUS_SESSION_BUS_ADDRESS"

# Verify the bus is reachable.
dbus-send --session --dest=org.freedesktop.DBus \
  --type=method_call --print-reply \
  /org/freedesktop/DBus org.freedesktop.DBus.ListNames \
  || { echo "ERROR: D-Bus not reachable"; exit 1; }

# Block until org.freedesktop.secrets is registered on the bus.
#
# Usage: wait_for_secrets [timeout_seconds] [provider_pid]
#
# Passing the provider's PID is optional and backward compatible. With it, a provider
# that dies during startup is reported when it dies instead of at the end of the
# timeout -- otherwise a daemon that aborted after one second is indistinguishable from
# one that is merely slow, and both present as the same generic timeout message.
#
# Returns 1 on timeout, 2 if the watched process exited, so callers can tell the two
# apart and avoid blaming the wrong thing.
wait_for_secrets() {
    local timeout="${1:-30}"
    local watch_pid="${2:-}"
    local waited=0
    while ! dbus-send --session --dest=org.freedesktop.DBus \
            --type=method_call --print-reply \
            /org/freedesktop/DBus org.freedesktop.DBus.GetNameOwner \
            string:org.freedesktop.secrets >/dev/null 2>&1; do
        if [ -n "$watch_pid" ] && ! kill -0 "$watch_pid" 2>/dev/null; then
            echo "ERROR: the provider (pid ${watch_pid}) exited before registering org.freedesktop.secrets"
            return 2
        fi
        sleep 1
        waited=$((waited + 1))
        if [ "$waited" -ge "$timeout" ]; then
            echo "ERROR: org.freedesktop.secrets not available after ${timeout}s"
            return 1
        fi
    done
    echo "org.freedesktop.secrets is available (after ${waited}s)"
}

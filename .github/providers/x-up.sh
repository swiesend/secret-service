#!/usr/bin/env bash
# Shared virtual X server bring-up for the provider images that show a window.
#
# Source this from a provider entrypoint:  source /providers/x-up.sh
# It defines start_x_server(), which starts Xvfb on a free display, exports DISPLAY, sets
# XVFB_PID, and returns once the server accepts connections. Set XVFB_LOG to the file for
# Xvfb's output before calling it.

# Previously: "Xvfb :99 & sleep 2" — a fixed sleep that races. On a loaded runner
# KeePassXC could start against a server that was not yet accepting connections, and
# the failure surfaced 30 seconds later as "no collection exposed", which points at
# the database fixture rather than at the X server.
#
# koppor's CI draft (https://github.com/swiesend/secret-service/pull/43) used
# "xvfb-run --auto-servernum", which fixes both the race and the fixed display number.
# The mechanism does not survive this container: xvfb-run waits for Xvfb to report
# readiness by SIGUSR1 to its parent, and as PID 1 under Docker that handshake does
# not complete — verified, it hangs indefinitely rather than starting the command.
# So the idea is kept and the mechanism is not: pick a free display, then poll for the
# socket instead of sleeping.
start_x_server() {
    local n=99
    while [ -e "/tmp/.X${n}-lock" ] || [ -e "/tmp/.X11-unix/X${n}" ]; do
        n=$((n + 1))
        [ "$n" -gt 199 ] && { echo "ERROR: no free X display number."; return 1; }
    done
    export DISPLAY=":${n}"

    Xvfb "$DISPLAY" -screen 0 1024x768x16 > "$XVFB_LOG" 2>&1 &
    XVFB_PID=$!

    local waited=0
    until [ -e "/tmp/.X11-unix/X${n}" ]; do
        if ! kill -0 "$XVFB_PID" 2>/dev/null; then
            echo "ERROR: Xvfb exited during startup:"; cat "$XVFB_LOG" 2>/dev/null
            return 1
        fi
        sleep 1; waited=$((waited + 1))
        if [ "$waited" -ge 15 ]; then
            echo "ERROR: Xvfb did not accept connections on $DISPLAY within 15s:"
            cat "$XVFB_LOG" 2>/dev/null
            return 1
        fi
    done
    echo "Xvfb ready on $DISPLAY (after ${waited}s)"
}

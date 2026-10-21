#!/usr/bin/env bash
set -euo pipefail

# gnome-keyring as at a desktop: its dialogs appear, and someone answers them.
#
# The gnome-keyring image has no display. gcr-prompter, which shows gnome-keyring's dialogs,
# cannot start there, so gnome-keyring dismisses every prompt at once: the unlock of a collection
# that only its dialog unlocks, as the login keyring after a lock, and the creation of a
# collection without a password. Here gcr-prompter shows each dialog on a virtual X server, and
# answer_dialogs types the password into it.

LOG_DIR="${PROVIDER_LOG_DIR:-/workspace/target/provider-logs}"
# Probe writability, not just mkdir: a read-only /workspace mount fails at write time.
if ! ( mkdir -p "$LOG_DIR" && touch "$LOG_DIR/.probe" ) 2>/dev/null; then
    echo "WARNING: ${LOG_DIR} is not writable; logs go to /tmp and will NOT survive the"
    echo "         container, so the CI diagnostics artifact will be empty."
    LOG_DIR=/tmp
fi
rm -f "$LOG_DIR/.probe" 2>/dev/null || true
XVFB_LOG="$LOG_DIR/xvfb.log"
KEYRING_LOG="$LOG_DIR/gnome-keyring.log"
DIALOG_LOG="$LOG_DIR/dialogs.log"

# The password of every keyring in the container: of the login keyring, created below, and of
# the collections that the tests create.
PASSWORD=test

# Through this directory a test holds the answerer back, as a user who is away: while "hold" is in
# it, answer_dialogs leaves the dialogs alone, and answers them once it is gone. The tests learn
# the directory from the environment, which only this container sets.
export SECRET_SERVICE_DIALOG_CONTROL=/tmp/dialog-control
mkdir -p "$SECRET_SERVICE_DIALOG_CONTROL"

# gcr-prompter shows its dialogs on an X server (defines start_x_server).
source /providers/x-up.sh
start_x_server

# Bring up the session bus (exports DBUS_SESSION_BUS_ADDRESS, defines wait_for_secrets).
source /providers/dbus-up.sh

# D-Bus starts gcr-prompter when gnome-keyring first needs it, with the bus's own environment.
# That has neither the display nor the bus's address, which a desktop's session bus passes on.
# Without the address, gcr-prompter started a bus of its own, through dbus-launch --autolaunch on
# the display, and waited for prompts there, while gnome-keyring waited for it.
dbus-update-activation-environment DISPLAY DBUS_SESSION_BUS_ADDRESS

# Creates the login keyring with the password, and unlocks it. In the foreground, so that its
# messages reach the log: once it has forked, gnome-keyring logs to syslog, which the container
# does not have. Among them its abort: gnome-keyring aborts when a client dismisses an unlock
# prompt while an unlock dialog is open.
printf '%s' "$PASSWORD" | gnome-keyring-daemon --foreground --unlock --components=secrets \
    > "$KEYRING_LOG" 2>&1 &
KEYRING_PID=$!
wait_for_secrets 30 "$KEYRING_PID"
echo "gnome-keyring-daemon ready"

# Types the password into each of the dialog's password fields, moving on with Tab, and presses
# Return, as the dialog's default button is the one that goes on.
type_password() {
    local field
    for field in $(seq 1 "$1"); do
        [ "$field" -eq 1 ] || xdotool key Tab || return 1
        xdotool type --delay 50 "$PASSWORD" || return 1
    done
    xdotool key Return
}

# Answers each of gnome-keyring's dialogs as a user who knows the password. One line per dialog.
# A dialog of another kind stays open and only its title is logged, so that the test that waits
# for it fails at its timeout with the reason in the log.
answer_dialogs() {
    local answered=" " visible win title fields
    while true; do
        if [ -e "$SECRET_SERVICE_DIALOG_CONTROL/hold" ]; then
            sleep 0.3
            continue
        fi
        # xdotool fails when it finds no window, which under set -e would end the loop.
        visible=" $(xdotool search --onlyvisible --class gcr-prompter 2>/dev/null | tr '\n' ' ' || true)"
        # Forgets the dialogs that have closed. gcr-prompter quits after ten idle seconds, and the
        # one that D-Bus starts next numbers its windows as the last one did.
        for win in $answered; do
            case "$visible" in *" $win "*) ;; *) answered="${answered/ $win / }" ;; esac
        done
        for win in $visible; do
            case "$answered" in *" $win "*) continue ;; esac
            answered="$answered$win "
            # Gives GTK the moment to finish the dialog and to focus its password field.
            sleep 0.5
            title="$(xdotool getwindowname "$win" 2>/dev/null || true)"
            case "$title" in
                "Unlock Keyring" | "Unlock Login Keyring") fields=1 ;;
                # The dialog for the password of a new collection has no title, and a second
                # field that confirms the password.
                "") fields=2 ;;
                *)
                    echo "left a dialog open: \"$title\" (window $win) at $(date +%T)"
                    continue
                    ;;
            esac
            xdotool windowfocus --sync "$win" 2>/dev/null || true
            if type_password "$fields"; then
                echo "answered \"$title\" (window $win) at $(date +%T)"
            else
                echo "could not type into \"$title\" (window $win) at $(date +%T)"
            fi
        done
        sleep 0.3
    done
}

answer_dialogs > "$DIALOG_LOG" 2>&1 &
echo "Answering gnome-keyring's dialogs (log: $DIALOG_LOG)."

# Run the provided command, defaulting to the system-test profile.
if [ $# -eq 0 ]; then
    exec mvn -B test -Psystem-test -Dsecret-service.system-test.dialogs-answered=true
else
    exec "$@"
fi

#!/usr/bin/env python3
"""Answers oo7-daemon's password prompts as a user who types the password, without a desktop.

oo7-daemon asks for a password whenever it unlocks a collection. Outside a graphical session it
asks org.freedesktop.secrets.CliPrompter: Prompt(label, description) answers whether the user
accepted, and a file descriptor from which the daemon reads the password up to its end. In a
container nothing serves that name, and every unlock after a Lock waited for an answer.

Usage: prompter.py PASSWORD
"""
import socket
import sys

import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

NAME = "org.freedesktop.secrets.CliPrompter"
password = sys.argv[1].encode()


class Prompter(dbus.service.Object):

    @dbus.service.method(NAME, in_signature="ss", out_signature="hb")
    def Prompt(self, label, description):
        print(f"prompter: answering the prompt for the keyring {label}", flush=True)
        ours, theirs = socket.socketpair()
        with ours:
            ours.sendall(password)
        # Closing our end marks the end of the password. UnixFd sends a duplicate of theirs.
        answer = dbus.types.UnixFd(theirs.fileno())
        theirs.close()
        return answer, True


DBusGMainLoop(set_as_default=True)
session = dbus.SessionBus()
name = dbus.service.BusName(NAME, session)
prompter = Prompter(session, "/org/freedesktop/secrets/CliPrompter")
print("prompter: ready", flush=True)
GLib.MainLoop().run()

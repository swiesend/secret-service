#!/usr/bin/env python3
"""Starts kwalletd, or KF6's ksecretd, as pam_kwallet starts it at a Plasma login, so that it
creates the default wallet, kdewallet, and opens it without a dialog.

pam_kwallet runs the daemon with PAM_KWALLET5_LOGIN set and `--pam-login <pipe> <socket>`. Into
the pipe it writes the PBKDF2-SHA512 hash of the login password: 56 bytes, 50000 iterations,
salted with the 56 bytes of kwalletd/kdewallet.salt. Through the socket it sends the session's
environment. kwalletd then opens kdewallet with the hash, and creates it if there is none.

The password is empty. When kwalletd opens the wallet again, after a Lock, it tries an empty
password before it shows its dialog, so the wallet unlocks without one.

Usage: kwallet-up.py DAEMON LOGFILE   Prints the daemon's pid.
"""
import hashlib
import os
import socket
import subprocess
import sys
import time

daemon, logfile = sys.argv[1:3]

data_home = os.environ.get("XDG_DATA_HOME", os.path.join(os.environ["HOME"], ".local", "share"))
salt_dir = os.path.join(data_home, "kwalletd")
os.makedirs(salt_dir, mode=0o700, exist_ok=True)
salt_path = os.path.join(salt_dir, "kdewallet.salt")
if not os.path.exists(salt_path):
    with open(salt_path, "wb") as f:
        f.write(os.urandom(56))
    os.chmod(salt_path, 0o600)
with open(salt_path, "rb") as f:
    salt = f.read()
password_hash = hashlib.pbkdf2_hmac("sha512", b"", salt, 50000, 56)

hash_read, hash_write = os.pipe()
socket_path = os.path.join(os.environ.get("XDG_RUNTIME_DIR", "/tmp"), "kwallet-pam.socket")
try:
    os.unlink(socket_path)
except FileNotFoundError:
    pass
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(socket_path)
server.listen(1)

env = dict(os.environ, PAM_KWALLET5_LOGIN=socket_path)
with open(logfile, "ab") as log:
    daemon_process = subprocess.Popen(
        [daemon, "--pam-login", str(hash_read), str(server.fileno())],
        env=env, pass_fds=(hash_read, server.fileno()),
        stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
        start_new_session=True)
os.close(hash_read)
server.close()

os.write(hash_write, password_hash)
os.close(hash_write)

# What pam_kwallet_init does when the session starts: send the environment, then hang up.
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
for _ in range(100):
    try:
        client.connect(socket_path)
        break
    except OSError:
        time.sleep(0.1)
client.sendall("".join(f"{key}={value}\n" for key, value in env.items() if "\n" not in value).encode())
client.close()
print(daemon_process.pid)

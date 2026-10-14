# Ubuntu 24.04 (noble) ships KDE Frameworks 5.115, the KWallet of Kubuntu 24.04 — kwalletd5
# gained freedesktop Secret Service API support in KF 5.97, so jammy (5.92) is too old.
# The kwalletd5 daemon binary is shipped in the libkf5wallet-bin package.
FROM ubuntu:24.04

# No X server: the entrypoint starts kwalletd as a Plasma login does, which opens the wallet
# without a dialog. python3 runs that login's handshake, kwallet-up.py.
ENV DEBIAN_FRONTEND=noninteractive

# Same as the keepassxc image: ubuntu:24.04 leaves LANG unset, so the JVM falls back to
# ANSI_X3.4-1968 and every non-ASCII character in the logs becomes "?".
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
RUN apt-get update && apt-get install -y --no-install-recommends \
        dbus \
        libkf5wallet-bin \
        libqca-qt5-2-plugins \
        libsecret-tools \
        python3 \
        openjdk-17-jdk-headless \
        maven \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64

COPY .github/providers/ /providers/
RUN chmod +x /providers/dbus-up.sh /providers/kwallet/entrypoint.sh

WORKDIR /workspace

ENTRYPOINT ["/providers/kwallet/entrypoint.sh"]

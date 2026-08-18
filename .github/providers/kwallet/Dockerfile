# Ubuntu 24.04 (noble) ships KDE Frameworks 5.115 — kwalletd5 gained
# freedesktop Secret Service API support in KF 5.97, so jammy (5.92) is too old.
# The kwalletd5 daemon binary is shipped in the libkf5wallet-bin package.
FROM ubuntu:24.04

# A virtual X server is required because kwalletd is a GUI-session daemon.
#
# NOTE: Headless KWallet bring-up is inherently fragile (wallet creation/unlock
# normally goes through an interactive dialog). This image is best-effort; the
# system-tests workflow runs the KWallet leg with continue-on-error.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        dbus \
        dbus-x11 \
        xvfb \
        libkf5wallet-bin \
        libsecret-tools \
        openjdk-25-jdk-headless \
        maven \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/java-25-openjdk-amd64

COPY .github/providers/ /providers/
RUN chmod +x /providers/dbus-up.sh /providers/kwallet/entrypoint.sh

WORKDIR /workspace

ENTRYPOINT ["/providers/kwallet/entrypoint.sh"]

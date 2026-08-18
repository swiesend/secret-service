# KeePassXC serves the freedesktop Secret Service API when "Secret Service
# Integration" is enabled and a group is exposed. KeePassXC is a GUI app, so a
# virtual X server is required.
#
# Use Ubuntu 24.04 (noble): it ships KeePassXC 2.7.x, whose FdoSecrets exposed-group
# metadata matches databases prepared by modern KeePassXC. Jammy's 2.6.6 has an
# older/experimental FdoSecrets and does not pick up the committed fixture's exposure.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        dbus \
        dbus-x11 \
        xvfb \
        keepassxc \
        libsecret-tools \
        openjdk-25-jdk-headless \
        maven \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/java-25-openjdk-amd64

COPY .github/providers/ /providers/
RUN chmod +x /providers/dbus-up.sh /providers/keepassxc/entrypoint.sh

WORKDIR /workspace

ENTRYPOINT ["/providers/keepassxc/entrypoint.sh"]

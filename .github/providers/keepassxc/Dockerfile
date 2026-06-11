FROM eclipse-temurin:17-jdk-jammy

# KeePassXC serves the freedesktop Secret Service API when "Secret Service
# Integration" is enabled and a group is exposed. KeePassXC is a GUI app, so a
# virtual X server is required.
#
# NOTE: Headless KeePassXC is best-effort. Exposing a group as a Secret Service
# collection is stored inside the .kdbx and is normally configured via the GUI;
# without it, the provider-agnostic suite will skip (Assumptions) while still
# verifying the library connects to KeePassXC's Secret Service. The system-tests
# workflow runs this leg with continue-on-error.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        dbus \
        dbus-x11 \
        xvfb \
        keepassxc \
        libsecret-tools \
        maven \
    && rm -rf /var/lib/apt/lists/*

COPY .github/providers/ /providers/
RUN chmod +x /providers/dbus-up.sh /providers/keepassxc/entrypoint.sh

WORKDIR /workspace

ENTRYPOINT ["/providers/keepassxc/entrypoint.sh"]

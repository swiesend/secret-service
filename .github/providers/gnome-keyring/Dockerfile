FROM eclipse-temurin:25-jdk-jammy

RUN apt-get update && apt-get install -y --no-install-recommends \
        dbus \
        dbus-x11 \
        gnome-keyring \
        libsecret-tools \
        maven \
    && rm -rf /var/lib/apt/lists/*

COPY .github/providers/ /providers/
RUN chmod +x /providers/dbus-up.sh /providers/gnome-keyring/entrypoint.sh

WORKDIR /workspace

ENTRYPOINT ["/providers/gnome-keyring/entrypoint.sh"]

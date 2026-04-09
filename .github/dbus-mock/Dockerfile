FROM eclipse-temurin:17-jdk-jammy

RUN apt-get update && apt-get install -y --no-install-recommends \
        dbus \
        dbus-x11 \
        gnome-keyring \
        libsecret-tools \
        maven \
    && rm -rf /var/lib/apt/lists/*

COPY .github/dbus-mock/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /workspace

ENTRYPOINT ["/entrypoint.sh"]

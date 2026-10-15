# The JDK to test on: 17, which the library targets, unless the build sets another, as the JDK 25
# job does.
ARG JDK=17
FROM eclipse-temurin:${JDK}-jdk-jammy

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

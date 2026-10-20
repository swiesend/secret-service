# gnome-keyring as in the gnome-keyring image, with its dialogs shown and answered: gcr-prompter,
# which gnome-keyring installs, shows them on a virtual X server, and xdotool types the password
# into them, as a user does. The gnome-keyring image stays as it is, for the required checks.
ARG JDK=17
FROM eclipse-temurin:${JDK}-jdk-jammy

RUN apt-get update && apt-get install -y --no-install-recommends \
        dbus \
        dbus-x11 \
        gnome-keyring \
        libsecret-tools \
        maven \
        xvfb \
        xdotool \
    && rm -rf /var/lib/apt/lists/*

COPY .github/providers/ /providers/
RUN chmod +x /providers/dbus-up.sh /providers/gnome-keyring-dialogs/entrypoint.sh

WORKDIR /workspace

ENTRYPOINT ["/providers/gnome-keyring-dialogs/entrypoint.sh"]

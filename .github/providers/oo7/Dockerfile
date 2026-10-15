# oo7 is GNOME's Secret Service provider in Rust, which replaces gnome-keyring as the default from
# Fedora 45 on. Fedora 45 ships oo7 0.7.0 beta. Its daemon unlocks the login keyring with a password
# that it reads from stdin, as a login does, and prompter.py answers its password prompts, so it
# needs neither a desktop nor an X server.
FROM fedora:45

# Without LANG the JVM falls back to ANSI_X3.4-1968, and every non-ASCII character in the logs
# becomes "?".
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
# Fedora 45 packages no JDK 17. The core module compiles with --release 17 on JDK 25 as well.
# python3-dbus and -gobject-base for prompter.py.
RUN dnf -y install --setopt=install_weak_deps=False \
        dbus-daemon \
        dbus-tools \
        oo7-daemon \
        libsecret \
        python3-dbus \
        python3-gobject-base \
        java-25-openjdk-devel \
        maven-openjdk25 \
    && dnf clean all

# Which oo7 the image got: the package is not pinned, as Fedora replaces a release's builds.
RUN printf 'oo7-daemon: %s\n' "$(rpm -q --qf '%{VERSION}-%{RELEASE}' oo7-daemon)" > /image-oo7-version

# dbus-java reads the machine id for every connection, and Fedora's container image leaves it
# empty, where Ubuntu's dbus package writes one. --ensure refuses the empty file.
RUN dbus-uuidgen > /etc/machine-id

COPY .github/providers/ /providers/
RUN chmod +x /providers/dbus-up.sh /providers/oo7/entrypoint.sh

WORKDIR /workspace

ENTRYPOINT ["/providers/oo7/entrypoint.sh"]

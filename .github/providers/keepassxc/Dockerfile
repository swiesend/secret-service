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
        openjdk-17-jdk-headless \
        maven \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64

# Record which KeePassXC the image actually got. The package is deliberately not
# version-pinned -- noble ships exactly one keepassxc, and pinning to a point release
# breaks the build the day the archive supersedes it -- so the version is captured
# instead, and the provider echoes it at startup. A behaviour change between KeePassXC
# releases then appears in the log beside the failure instead of being guessed at.
# dpkg-query, not "keepassxc --version": KeePassXC is a Qt GUI binary and needs a
# display even to print its version, so at build time it yields nothing useful.
RUN printf 'keepassxc: %s\n' "$(dpkg-query -W -f='${Version}' keepassxc)" > /image-keepassxc-version

# NOTE: "maven" hard-depends on default-jre-headless, so the image also carries a
# second, unused JRE (~46 MB) beyond the JDK named above. Splitting the apt calls does
# not avoid it -- measured: apt still selects default-jre-headless. Dropping it means
# installing the Apache Maven tarball instead of the distro package, trading ~46 MB for
# a checksum to maintain across three Dockerfiles. Judged not worth it; recorded so the
# next person does not re-run the same dead end.

COPY .github/providers/ /providers/
RUN chmod +x /providers/dbus-up.sh /providers/keepassxc/entrypoint.sh

WORKDIR /workspace

ENTRYPOINT ["/providers/keepassxc/entrypoint.sh"]

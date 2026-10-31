# KeePassXC 2.8, the first release on Qt 6, from its release AppImage: Ubuntu 24.04 ships 2.7.6,
# which the keepassxc image tests. This image differs from that one only in where KeePassXC comes
# from, and starts it with the same entrypoint.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# A UTF-8 locale, as in the keepassxc image: ubuntu:24.04 leaves the JVM at ANSI_X3.4-1968.
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
# libegl1 to libwayland-client0: the libraries that the AppImage links and does not bundle, which
# Ubuntu's keepassxc package brings into the other image.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        dbus \
        dbus-x11 \
        xvfb \
        libegl1 \
        libfontconfig1 \
        libharfbuzz0b \
        libopengl0 \
        libusb-1.0-0 \
        libwayland-client0 \
        libsecret-tools \
        xdotool \
        openjdk-17-jdk-headless \
        maven \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64

# The release AppImage, pinned by its SHA-256: a download that differs from the one checked
# against the KeePassXC release key fails the build. The release key is
# BF5A669F2272CF4324C1FDA8CFB4C2166397D0D2. 2.8.0-1 is the AppImage re-spun on 2026-10-23. A
# container has no FUSE, so the AppImage is extracted, and a wrapper starts it as the AppImage's
# own runtime does.
ARG KPXC_VERSION=2.8.0-1
ARG KPXC_SHA256=3ab1bfbb422272334b48057e6bfc984c839375d9a1cd9350c4ea62ca0b55ca5f
RUN cd /tmp \
    && curl -fsSL -o keepassxc.AppImage \
        "https://github.com/keepassxreboot/keepassxc/releases/download/${KPXC_VERSION%-*}/KeePassXC-${KPXC_VERSION}-x86_64.AppImage" \
    && echo "${KPXC_SHA256}  keepassxc.AppImage" | sha256sum -c - \
    && chmod +x keepassxc.AppImage \
    && ./keepassxc.AppImage --appimage-extract > /dev/null \
    && mv squashfs-root /opt/keepassxc \
    && rm keepassxc.AppImage \
    && printf '#!/bin/sh\nexport APPDIR=/opt/keepassxc APPIMAGE=/opt/keepassxc/AppRun\nexec /opt/keepassxc/AppRun "$@"\n' \
        > /usr/local/bin/keepassxc \
    && chmod +x /usr/local/bin/keepassxc

# The version the image got, which the entrypoint echoes at startup, as in the keepassxc image.
RUN printf 'keepassxc: %s (release AppImage)\n' "${KPXC_VERSION}" > /image-keepassxc-version

COPY .github/providers/ /providers/
RUN chmod +x /providers/dbus-up.sh /providers/keepassxc/entrypoint.sh

WORKDIR /workspace

ENTRYPOINT ["/providers/keepassxc/entrypoint.sh"]

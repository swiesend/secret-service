# Ubuntu 26.04 (resolute) ships KDE Frameworks 6.24, the KWallet of Kubuntu 26.04 LTS. In KF6 the
# Secret Service API is served by ksecretd, which the kwallet6 package ships.
FROM ubuntu:26.04

# As in the kwallet image: no X server, and python3 for the login handshake, kwallet-up.py.
ENV DEBIAN_FRONTEND=noninteractive

# Same as the kwallet image: without LANG the JVM falls back to ANSI_X3.4-1968, and every
# non-ASCII character in the logs becomes "?".
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
RUN apt-get update && apt-get install -y --no-install-recommends \
        dbus \
        kwallet6 \
        libqca-qt6-plugins \
        libsecret-tools \
        python3 \
        openjdk-17-jdk-headless \
        maven \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
# The kwallet image's entrypoint, with KF6's daemon.
ENV KWALLETD=ksecretd

COPY .github/providers/ /providers/
RUN chmod +x /providers/dbus-up.sh /providers/kwallet/entrypoint.sh

WORKDIR /workspace

ENTRYPOINT ["/providers/kwallet/entrypoint.sh"]

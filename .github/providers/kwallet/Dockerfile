FROM eclipse-temurin:17-jdk-jammy

# KWallet (KF5) can serve the freedesktop Secret Service API via kwalletd5.
# A virtual X server is required because kwalletd is a GUI-session daemon.
#
# NOTE: Headless KWallet bring-up is inherently fragile (wallet creation/unlock
# normally goes through an interactive dialog). This image is best-effort; the
# system-tests workflow runs the KWallet leg with continue-on-error.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        dbus \
        dbus-x11 \
        xvfb \
        kwalletd5 \
        kwallet-pam \
        qttools5-dev-tools \
        libsecret-tools \
        maven \
    && rm -rf /var/lib/apt/lists/*

COPY .github/providers/ /providers/
RUN chmod +x /providers/dbus-up.sh /providers/kwallet/entrypoint.sh

WORKDIR /workspace

ENTRYPOINT ["/providers/kwallet/entrypoint.sh"]

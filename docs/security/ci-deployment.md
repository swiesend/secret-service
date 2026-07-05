# CI Tool consumer scenarios

*Part of the [Security & deployment guide](index.md).*


You are building a tool that runs in a continuous-integration or build/deploy pipeline and depends on `de.swiesend:secret-service` to fetch credentials, signing keys, registry tokens, or similar build-time secrets. The environment is fundamentally different from [Desktop App consumer scenarios](desktop-deployment.md):

- **Headless** — no `$DBUS_SESSION_BUS_ADDRESS`, no `java.io.Console` for interactive prompts, no logged-in user. Most CI environments do not run a Secret Service daemon at all.
- **Ephemeral or daemonised** — either a one-shot job (GitHub Actions, GitLab CI, Jenkins agent, Buildkite) that lives for minutes and is then torn down, or a long-lived self-hosted runner / build agent serving many jobs.
- **Threat model dominated by:** class B (sidecar / cohabitating jobs leaking into yours), class C (job logs persisted by the platform, credential blobs left in build artifacts), and supply-chain attacks on the build itself. Class A is also relevant for self-hosted runners. Class D (HNDL) typically does not apply because secrets are short-lived.
- **Backends:** rarely a desktop keyring. Usually file-based providers reading credentials injected by the platform (env var, `--password-fd`, mounted file), or an external KMS / secret manager (HashiCorp Vault, AWS KMS, GCP Secret Manager) called via its own SDK — outside the scope of this library.

Step by step, by distribution format. The library can still help if you choose the right delivery shape.

## Release JAR (Maven Central / GitHub Releases)

**What this looks like.** You publish the JAR; downstream pipelines depend on it via Maven/Gradle, or download a release artifact. The CI tool that consumes the JAR is itself the deployment unit.

**What the consumer gets.** Whatever the host JDK provides. No isolation, no MAC, no JVM flags unless the consumer's wrapper script sets them. The library's discipline (zeroing, callback-only API) is the entire defense.

**Library configuration.** `EnvVarKeyMaterialProvider` reading the pepper from an env var the CI platform injects (`SECRET_SERVICE_PEPPER`), or a file-based provider reading from a mounted file. The TPM provider is rarely available in CI; if your self-hosted runner has a TPM, document it as an opt-in.

**Class coverage.**

| Class | Coverage |
|---|---|
| A | NONE — anything on the runner shares your trust domain |
| B | NONE — sibling jobs see your `/proc/<pid>/environ` |
| C | depends entirely on whether the runner persists job state |
| D | NOT_APPLICABLE for short-lived secrets |

**Pitfalls.**
- Build logs are the most underestimated class-C path. `mvn -X` echoes env vars; many CI platforms retain logs for 90+ days; some make logs public. Make sure the library never logs the pepper or DEK (it doesn't, but verify with `grep -ri pepper logs/`).
- Test code that prints `System.getenv()` for debugging finds its way into a release. Ban `System.out.println(env)` patterns at PR-review time.

**Ship-readiness check.**
```sh
mvn deploy -DperformRelease=true
# After release, simulate consumer integration:
mkdir -p /tmp/consumer && cd /tmp/consumer
echo '<dependency>...</dependency>' > pom.xml  # template
mvn dependency:tree | grep -i secret-service
```

## Distribution package (`.deb` / `.rpm`) for self-hosted runner

**What this looks like.** A self-hosted GitHub Actions runner, GitLab Runner, or Jenkins agent installed as a long-lived systemd service on a dedicated VM. Your tool is part of the runner's image or installed as a system package.

**What the consumer gets.** Real systemd hardening ([systemd unit hardening](defense-mechanisms.md#systemd-unit-hardening) directive set), AppArmor/SELinux integration ([MAC: SELinux](defense-mechanisms.md#mac-selinux)–[MAC: AppArmor](defense-mechanisms.md#mac-apparmor)), persistent state outside `~/.local/share/` (typically `/var/lib/<runner>/`).

**Sample systemd unit fragment for the runner agent.** This is more aggressive than [jpackage-built `.deb` / `.rpm`](desktop-deployment.md#jpackage-built-deb-rpm) because the daemon is fully headless and never needs to spawn child desktop processes:

```ini
[Service]
User=ci-runner
Group=ci-runner
SupplementaryGroups=tss
ExecStart=/usr/bin/java -jar /usr/lib/ci-runner/agent.jar
LimitCORE=0
LimitMEMLOCK=infinity
AmbientCapabilities=CAP_IPC_LOCK
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
DeviceAllow=/dev/tpmrm0 rw
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=true
LockPersonality=true
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @ptrace
SystemCallArchitectures=native
ReadWritePaths=/var/lib/ci-runner
```

**Library configuration.** `Tpm2KeyMaterialProvider` is realistic here because the runner VM has stable hardware. Provision via `Tpm2Provisioner --password-fd 3 3<<<"$RUNNER_PEPPER_PASSWORD"` from a one-shot install hook; the password lives in the cloud provider's instance metadata or a dedicated secret store, never on disk.

**Class coverage.** REAL for A/B/C with the unit above, the AppArmor profile from [AppArmor profile (`/etc/apparmor.d/usr.bin.java.secret-service-app`)](sample-configurations.md#apparmor-profile-etcapparmordusrbinjavasecret-service-app), and per-job UID isolation (one job → one ephemeral UID). Your CI orchestrator's job-level isolation does the heavy lifting; the systemd unit hardens the agent itself.

**Pitfalls.**
- Job-step processes inherit the agent's environment by default. Drop sensitive env vars before `Runtime.getRuntime().exec(...)` calls.
- `RestrictAddressFamilies=AF_UNIX` breaks runners that need network access for artifact upload; widen to `AF_UNIX AF_INET AF_INET6` as needed.

**Ship-readiness check.**
```sh
systemd-analyze verify ci-runner.service
systemd-analyze security ci-runner.service   # target ≥ "OK" / score ≤ 4.0
```

## OCI container (Docker, Podman, k8s) — the dominant CI format in 2026

**What this looks like.** A `Dockerfile` that bakes your tool + a runtime JDK; the image runs as a CI step (`docker run`, `kubernetes pod`, `tekton task`). One image = one job.

**What the consumer gets.** Default Docker security profile: namespaces, seccomp default, capability drop, cgroup device deny-all. Strong class-B defense between concurrent jobs by construction.

**The Secret Service tension in containers.** Your container does **not** have a session bus. The Secret Service daemon is on the *host*'s bus, which the container cannot reach unless you bind-mount `$XDG_RUNTIME_DIR/bus` — and doing so undoes most of the container's class-A/B defense. **In practice, CI containers should not use Secret Service at all.** Read your secrets from:

- An env var injected by the orchestrator (`docker run -e`, `kubernetes envFrom: secretRef`, GitHub Actions `env:`).
- A mounted file (`docker run -v /run/secrets/pepper:/run/secrets/pepper:ro`, k8s `secret` volume).
- An external secret manager via its SDK (Vault, AWS Secrets Manager).

Use this library's `Tpm2Availability.isAvailable()` preflight ([xdg-desktop-portal `org.freedesktop.portal.Secret`](defense-mechanisms.md#xdg-desktop-portal-orgfreedesktopportalsecret) of `secret-service-hardened-tpm2`) to detect "no TPM here, fall back to file-based provider" gracefully.

**The TPM tension in containers.** `--device=/dev/tpmrm0` works in plain Docker but is **forbidden in most managed CI** (GitHub-hosted runners, GitLab.com SaaS runners, CircleCI). On self-hosted Kubernetes you can device-plugin through, but it's per-cluster ops work. Plan for "no TPM" as the CI default.

**Sample Dockerfile.**

```dockerfile
FROM eclipse-temurin:21-jre-jammy
RUN useradd -r -m -u 10001 ci-tool
USER ci-tool
ENV JAVA_TOOL_OPTIONS="-XX:+DisableAttachMechanism -XX:-HeapDumpOnOutOfMemoryError"
COPY --chown=ci-tool:ci-tool target/ci-tool.jar /opt/ci-tool/ci-tool.jar
ENTRYPOINT ["java", "-jar", "/opt/ci-tool/ci-tool.jar"]
```

**Sample Kubernetes pod spec fragment.**

```yaml
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    seccompProfile: { type: RuntimeDefault }
  containers:
  - name: ci-tool
    image: ghcr.io/example/ci-tool:3.0.0
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities: { drop: ["ALL"] }
    env:
    - name: SECRET_SERVICE_PEPPER
      valueFrom:
        secretKeyRef: { name: ci-tool-secrets, key: pepper }
```

**Class coverage.**

| Class | Coverage |
|---|---|
| A (host-level admin) | NONE — `kubectl exec` / `nsenter` bypass |
| B (sibling pods/containers) | REAL — namespaces |
| C (image layers retain secrets) | REAL only if you use BuildKit secret mounts |
| D | NOT_APPLICABLE |

**Pitfalls.**
- **Never** `RUN echo $SECRET > /opt/.config` in a Dockerfile — the secret persists in a layer forever, even if a later layer deletes the file. Use `--mount=type=secret` (BuildKit).
- `kubectl logs` retains everything written to stdout. Configure SLF4J to send sensitive paths to a file appender that the runtime tears down with the pod.
- A `readOnlyRootFilesystem: true` container cannot write `/tmp` for the JVM; mount an `emptyDir { medium: Memory }` at `/tmp` so plaintext temp files at least never hit disk.

**Ship-readiness check.**
```sh
docker build --no-cache -t ci-tool:test .
docker run --rm --read-only --cap-drop=ALL --user=10001 ci-tool:test --version
trivy image ci-tool:test    # CVE scan
hadolint Dockerfile         # lint
```

## GitHub Actions / GitLab CI integration

**What this looks like.** You ship your CI tool as a reusable action (GH `action.yml` Docker or composite action, GitLab `include:` template). The platform's secret store injects credentials.

**Sample GitHub Actions Docker action (`action.yml`).**

```yaml
name: 'Run secret-service tool'
inputs:
  pepper:
    description: 'KeyMaterialProvider pepper'
    required: true
runs:
  using: 'docker'
  image: 'docker://ghcr.io/example/ci-tool:3.0.0'
  env:
    SECRET_SERVICE_PEPPER: ${{ inputs.pepper }}
```

**Caller workflow:**
```yaml
- uses: example/ci-tool@v3
  with:
    pepper: ${{ secrets.PEPPER }}     # GH Actions secret store
```

**Sample GitLab CI fragment.**

```yaml
variables:
  SECRET_SERVICE_PEPPER: $PEPPER     # injected from GitLab CI variables (masked, protected)

ci-tool-job:
  image: ghcr.io/example/ci-tool:3.0.0
  script:
    - java -jar /opt/ci-tool/ci-tool.jar fetch
```

**Library configuration.** `EnvVarKeyMaterialProvider` reading `SECRET_SERVICE_PEPPER`. The library's loud warning at construction is appropriate: env-var pepper is class-A theatre. In CI that's acceptable because the CI runner *is* the trust boundary — there is no other class-A actor to defend against. Document this loudly so a copy-pasted snippet does not migrate to a desktop deployment.

**Pitfalls.**
- **GH Actions auto-masks the literal value of `secrets.PEPPER`** in logs, but only the literal string. If your tool transforms it (`base64 -d`, splits, hashes) the *transformed* form is unmasked. Use the raw secret end-to-end.
- GitLab CI's "masked" variables only mask values that are 8+ characters and pass a charset check. A short or special-character pepper unmasks silently.
- Forks of public repos do **not** receive secrets in PR/MR builds (by default). Test paths that depend on secrets must run only on `push` to the main repo.

**Ship-readiness check.**
```sh
act -W .github/workflows/test.yml --secret-file .secrets   # local GHA dry-run
gitlab-runner exec docker ci-tool-job --env-file .env      # local GitLab CI dry-run
```

## Self-hosted long-running CI controller (Jenkins, Buildkite, Harness, …)

**What this looks like.** A controller process that schedules jobs, fetches credentials, signs artifacts. Typically runs as `systemd` on a dedicated VM behind a load balancer.

**What the consumer gets.** Same as [Distribution package (`.deb` / `.rpm`) for self-hosted runner](#distribution-package-deb-rpm-for-self-hosted-runner) (`.deb`/`.rpm` self-hosted runner), but the controller talks to a real secret manager (Vault / KMS / cloud-native) over the network rather than reading peppers from disk.

**Library configuration.** Implement a custom `KeyMaterialProvider` that delegates to your secret manager's SDK; cache the unsealed pepper for the JVM lifetime, zero on shutdown. The library's `KeyMaterialProvider` SPI is designed for exactly this.

**Class coverage.** REAL for A/B/C provided the secret-manager SDK does its part (TLS, audit log, credential rotation). The library's role shrinks to "expose `char[] getPepper()`."

**Pitfalls.**
- Your `getPepper()` implementation is now on the hot path: every `withSecret` call hits it. Cache aggressively, refresh on rotation events.
- Don't forget to zero the cached pepper on JVM shutdown — the library's `AutoCloseable` discipline applies to your custom provider too.

## Snap classic confinement (rare; ops-tool edge case)

**What this looks like.** A `snap install --classic ci-tool`. Classic confinement disables AppArmor mediation — the snap runs with full filesystem and device access.

**Recommendation.** Almost never appropriate for CI tools. Classic confinement exists for things like `snapcraft` itself or `kubectl` that need raw filesystem access. If your tool can run under `confinement: strict` ([Snap](desktop-deployment.md#snap)), do that instead. If you must use classic, the security posture is identical to a `tar.gz` ([Plain binary archive (`tar.gz` / `zip`)](desktop-deployment.md#plain-binary-archive-targz-zip)) with worse update semantics.

## Quick decision tree for CI tools

```
Is the CI environment ephemeral (one job, then torn down)?
├── Yes (typical GHA / GitLab.com / CircleCI)
│   ├── Use “OCI container (Docker, Podman, k8s) — the dominant CI format in 2026” (ci-deployment.md) (OCI container) + “GitHub Actions / GitLab CI integration” (ci-deployment.md) (action wrapper).
│   ├── EnvVarKeyMaterialProvider reading platform-injected secret.
│   └── DO NOT try to use Secret Service or TPM here; they are not present.
└── No — it's a long-lived runner / controller
    ├── Self-hosted runner on dedicated VM → “Distribution package (`.deb` / `.rpm`) for self-hosted runner” (ci-deployment.md) (.deb/.rpm + systemd hardening).
    ├── TPM available on the runner → Tpm2KeyMaterialProvider.
    └── Centralised controller talking to KMS/Vault → “Self-hosted long-running CI controller (Jenkins, Buildkite, Harness, …)” (ci-deployment.md) (custom KeyMaterialProvider).
```

The dominant honest path for CI is: **OCI container + platform-injected env-var pepper**. The hardened wrapper's class-A defense doesn't help against a CI platform compromise (the platform *is* class A in that environment). The wrapper's class-B defense via AEAD envelopes still matters when CI build artifacts are stored long-term — even if a later attacker exfiltrates them, the items are opaque.

---

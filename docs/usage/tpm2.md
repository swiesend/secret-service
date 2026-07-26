# TPM 2.0 usage

Samples for `secret-service-hardened-tpm2`: provisioning a TPM-sealed pepper, using it at runtime, choosing where the unseal password lives, and degrading gracefully when TSS.Java is absent.

## Provision a sealed pepper

One-shot operator command. Run once per host/installation. Requires `de.swiesend:secret-service-hardened-tpm2` plus `com.microsoft.azure:TSS.Java:1.0.0` on the runtime classpath.

### Default flow — random pepper, password from prompt

```bash
# Provisioner generates a fresh base64 random pepper internally; password prompted on tty
java -cp "secret-service-hardened-tpm2-3.0.0-alpha.jar:TSS.Java-1.0.0.jar:slf4j-api-2.0.17.jar:slf4j-simple-2.0.17.jar" \
     de.swiesend.secretservice.hardened.tpm2.Tpm2Provisioner \
     --out ~/.config/myapp/pepper.tpm2blob \
     --password-prompt
```

Output: a sealed-blob file at mode 0600. The pepper is generated inside the JVM and never leaves the TPM after sealing — this means **losing the TPM = losing the items**.

### Operator-supplied pepper (cross-host escrow path)

When you need recoverability across hardware loss, generate the pepper out-of-band, escrow it (paper, password manager, secret manager), then seal it on each host:

```bash
# Generate once; store in your password manager AND a paper backup.
PEPPER=$(openssl rand -base64 32)
PASSWORD=$(openssl rand -base64 24)

# Escrow BEFORE sealing.
echo "$PEPPER"   | pass insert -m myapp/pepper
echo "$PASSWORD" | pass insert -m myapp/seal-password

# Seal on this host -- pepper from --pepper-fd, password from --password-fd
# (different file descriptors so they don't both read from stdin):
{ printf '%s\n' "$PASSWORD"; } | java -cp "..." \
    de.swiesend.secretservice.hardened.tpm2.Tpm2Provisioner \
    --out /etc/myapp/pepper.tpm2blob \
    --password-stdin \
    --pepper-fd 3 3<<< "$PEPPER"

unset PEPPER PASSWORD
```

If the host's TPM later dies, re-provision on the new hardware with the same `$PEPPER` — items written under the same pepper remain readable (they get *re-encrypted* under a new TPM seal, but the underlying pepper is unchanged so all DEKs are unchanged).

### Headless CI provisioning

```bash
# pepper from a fixture in the platform's secret store, password from a different fixture
PEPPER="$CI_TPM_PEPPER" PASSWORD="$CI_TPM_PASSWORD" \
java -cp "..." Tpm2Provisioner \
  --out "$RUNNER_HOME/pepper.tpm2blob" \
  --password-env PASSWORD \
  --pepper-env PEPPER
```

### What lands on disk

A `~44-character` base64 pepper (default flow) or your supplied bytes (operator-supplied flow) sealed inside a TPM keyed-hash object; the public + private blobs serialised into the file format documented in `Tpm2SealedBlob.java`. The file is mode 0600; the TPM enforces dictionary-attack lockout on wrong-password attempts (typically 32 strikes → standby).

---

## Use the sealed pepper at runtime

```java
import de.swiesend.secretservice.functional.SecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.hardened.HardenedCollection;
import de.swiesend.secretservice.hardened.tpm2.Tpm2KeyMaterialProvider;
import java.io.Console;
import java.nio.file.Path;

Console console = System.console();
char[] sealPassword = console.readPassword("TPM unseal password: ");

try (Tpm2KeyMaterialProvider tpm = Tpm2KeyMaterialProvider.forPlatformTpm(
            Path.of(System.getProperty("user.home"), ".config/myapp/pepper.tpm2blob"),
            sealPassword);
     SecretService service = SecretService.create().orElseThrow();
     CollectionInterface base = service.collection("default", null).orElseThrow();
     HardenedCollection coll = HardenedCollection.builder(base, tpm).build()) {

    base.unlock();

    // Use coll.createItem / withSecret / matchesSecret normally.
    coll.createItem("api-token", "shhh").orElseThrow();
}
// Tpm2KeyMaterialProvider.close() zeros the cached pepper on exit.
// HardenedCollection.close() doesn't propagate to the TPM provider -- close them yourself.
```

`forPlatformTpm` opens `/dev/tpmrm0` via TSS.Java's `TpmFactory.platformTpm()`. Use `forSimulator(...)` for tests against `localhost:2321`. The constructor unseals once at startup; subsequent `getPepper()` calls return clones of the cached value.

`Builder` accepts `Tpm2KeyMaterialProvider` without `acknowledgeSecurityTheater(true)` because its `threatCoverage().sameUid()` is `PARTIAL` (real same-UID defense requires an external MAC policy; see the [defense mechanism inventory](../security/defense-mechanisms.md)).

For memory hygiene, pair the provider with `.lockMemory(true)` so the unsealed pepper cannot swap to disk (mlock via the JDK FFM API; add `--enable-native-access=de.swiesend.secretservice.hardened` and grant `CAP_IPC_LOCK` / a sufficient `RLIMIT_MEMLOCK`). See [Hardened usage → Cipher suite and JVM hardening](hardened.md#cipher-suite-and-jvm-hardening).

### Where does the unseal password live on a desktop?

First, the reframe: **with the TPM provider you don't store the pepper.** It exists at rest only as `pepper.tpm2blob` — TPM-wrapped material that is useless without (a) that physical chip (the seal is `fixedTPM`, non-migratable) and (b) the unseal password, with wrong guesses rate-limited by the TPM's dictionary-attack lockout. The blob needs ordinary hygiene only (mode 0600, which `Tpm2SealedBlob` enforces on write *and* read). The remaining question is how the *unseal password* reaches your process at startup. Ranked for a desktop:

1. **Prompt the user (strongest).** `Console.readPassword` / pinentry at launch, zero the `char[]` after constructing the provider (the [runtime example above](#use-the-sealed-pepper-at-runtime) does exactly this). Nothing persisted anywhere; suits high-value, interactively launched apps. Cost: no unattended autostart.
2. **The login keyring (pragmatic autostart).** Store the unseal password in the *default* collection, which unlocks at session start. Analyze it per threat class and it holds up: an offline thief (class C) gets keyring files + blob but **cannot unseal without the physical TPM** — the hardware factor fully survives; cross-UID (class B) is unchanged; a same-UID attacker (class A) can read the password over D-Bus, but class A was already `PARTIAL` for this provider, so nothing is lost. Keep it in a *different* collection than your hardened items.
3. **systemd credentials (background services).** `LoadCredentialEncrypted=` with `systemd-creds encrypt`, which can itself TPM-bind the credential. Caveat: user-scoped credentials (`systemd-creds --user`) need systemd ≥ 256; on 255 (e.g. Ubuntu 24.04) this works for system services only.
4. **A 0600 file (acceptable floor).** Protects cross-UID only; offline protection still comes from the TPM — unlike a raw pepper file, the password file alone is not the whole secret.
5. **Environment variable — never.** `/proc/<pid>/environ` is readable by every same-UID process, and env leaks into `systemctl show`, crash dumps, and children. The same reasoning that makes `EnvVarKeyMaterialProvider` CI/dev-only applies. (Command-line flags are worse still — the provisioner removed `--password <plaintext>` for this reason.)

**Why not store it in KeePassXC?** Tempting, but an anti-pattern here. (a) *Availability coupling*: a locked `.kdbx` at startup means your app fails closed — an unlock-ordering dependency that breaks autostart. (b) *Co-location*: only one provider owns `org.freedesktop.secrets` at a time, so if KeePassXC is your Secret Service backend, the password would sit in the same store as the ciphertexts it protects. (c) The one genuine thing KeePassXC adds — its human-in-the-loop access prompt — you get more simply via option 1.

**Access-control facts worth knowing.** `/dev/tpmrm0` ships `crw-rw---- tss tss`, so only root or `tss`-group members can talk to the TPM at all — grant a service `SupplementaryGroups=tss` rather than running it privileged. And device access is *not* read access: the TPM is an authorization oracle, not a readable store. Hierarchy seeds never leave the chip, unsealing requires the object's own auth value, and the NV generation counter is provisioned `AUTHREAD|AUTHWRITE`. What the TPM cannot do is tell your app apart from malware running as the same user — that is the `sameUid=PARTIAL` rating, and closing it takes a MAC policy confining `/dev/tpmrm0` to your binary ([MAC: SELinux](../security/defense-mechanisms.md#mac-selinux), [MAC: AppArmor](../security/defense-mechanisms.md#mac-apparmor), [udev rules](../security/defense-mechanisms.md#udev-rules-for-devtpmrm0)).

---

## Graceful fallback when TSS.Java is missing

Don't reference `Tpm2KeyMaterialProvider` directly from generic code paths — that triggers `NoClassDefFoundError` if the consumer didn't add TSS.Java. Use `Tpm2Availability.isAvailable()` first; it has no `tss.*` imports so it's safe to call even when the library is absent.

```java
import de.swiesend.secretservice.hardened.KeyMaterialProvider;
import de.swiesend.secretservice.hardened.providers.EnvVarKeyMaterialProvider;
import de.swiesend.secretservice.hardened.tpm2.Tpm2Availability;
import de.swiesend.secretservice.hardened.tpm2.Tpm2KeyMaterialProvider;

KeyMaterialProvider provider;
if (Tpm2Availability.isAvailable() && Files.exists(blobPath)) {
    char[] sealPw = System.console().readPassword("TPM unseal password: ");
    provider = Tpm2KeyMaterialProvider.forPlatformTpm(blobPath, sealPw);
} else {
    log.warn(Tpm2Availability.installationHint());   // names the Maven coordinates
    provider = new EnvVarKeyMaterialProvider();
}
```

`Tpm2Availability.isAvailable()` uses `Class.forName(name, false, classLoader)` to probe without forcing class initialisation — safe to call from any code path, even on systems with no TPM. `installationHint()` returns a human-readable string suitable for logging.

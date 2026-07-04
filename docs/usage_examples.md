# Usage examples

End-to-end code samples for `secret-service`, `secret-service-hardened`, and `secret-service-hardened-tpm2`. Companion to the API Javadoc and to [`threat_models_and_mitigation.md`](threat_models_and_mitigation.md).

> See [§1.1 Do I need this?](threat_models_and_mitigation.md#11-do-i-need-this) before reaching for the hardened layers — most consumers should depend only on `secret-service`.

## Contents

1. [Core: read & write a secret](#1-core-read--write-a-secret)
2. [Core: legacy `SimpleCollection`](#2-core-legacy-simplecollection)
3. [Hardened: minimal opt-in wrapper](#3-hardened-minimal-opt-in-wrapper)
4. [Hardened: password verification with `matchesSecret`](#4-hardened-password-verification-with-matchessecret)
5. [Hardened: batch read with fail-fast `withSecrets`](#5-hardened-batch-read-with-fail-fast-withsecrets)
6. [Hardened: enable post-quantum + rotate epoch](#6-hardened-enable-post-quantum--rotate-epoch)
7. [Hardened: implement a custom `KeyMaterialProvider`](#7-hardened-implement-a-custom-keymaterialprovider)
8. [TPM 2.0: provision a sealed pepper](#8-tpm-20-provision-a-sealed-pepper)
9. [TPM 2.0: use the sealed pepper at runtime](#9-tpm-20-use-the-sealed-pepper-at-runtime)
10. [TPM 2.0: graceful fallback when TSS.Java is missing](#10-tpm-20-graceful-fallback-when-tssjava-is-missing)

---

## 1. Core: read & write a secret

Plain Secret Service over D-Bus, transport-encrypted by default. JDK 25.

```java
import de.swiesend.secretservice.functional.SecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import java.util.Map;
import java.util.Optional;

try (SecretService service = SecretService.create().orElseThrow();
     CollectionInterface collection = service.collection("default", null).orElseThrow()) {

    collection.unlock();

    // Write
    String path = collection
            .createItem("github-token", "ghp_xxxxxxxxxxxxxxxx",
                        Map.of("application", "myapp"))
            .orElseThrow();

    // Read inside a callback; the char[] is zeroed on exit.
    Optional<String> token = collection.withSecret(path, chars -> new String(chars));
    token.ifPresent(t -> System.out.println("token starts with " + t.substring(0, 4) + "…"));
}
```

The `CollectionInterface` is `AutoCloseable`; closing it releases the D-Bus session and clears any cached state. Items are encrypted on the wire between this client and the daemon (gnome-keyring or KeePassXC) but the daemon stores plaintext.

---

## 2. Core: legacy `SimpleCollection`

Backward-compatible adapter for projects that have not migrated to the functional API. Throws checked `IOException` / `IllegalArgumentException` instead of returning `Optional`.

```java
import de.swiesend.secretservice.simple.SimpleCollection;
import java.util.Map;

try (SimpleCollection coll = new SimpleCollection()) {
    String path = coll.createItem("github-token", "ghp_xxxxxxxxxxxxxxxx",
                                  Map.of("application", "myapp"));
    char[] secret = coll.getSecret(path);
    try {
        // use the secret
    } finally {
        java.util.Arrays.fill(secret, '\0');
    }
}
```

Internally `SimpleCollection` shares a static D-Bus connection (cleaned up by a JVM shutdown hook). Use the functional API in §1 for new code.

---

## 3. Hardened: minimal opt-in wrapper

Adds AES-256-GCM application-layer envelopes on top of any `CollectionInterface`. JDK 25 + `de.swiesend:secret-service-hardened`.

```java
import de.swiesend.secretservice.functional.SecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.hardened.HardenedCollection;
import de.swiesend.secretservice.hardened.providers.EnvVarKeyMaterialProvider;
import de.swiesend.secretservice.hardened.providers.NoTotpKeyMaterialProvider;

try (SecretService service = SecretService.create().orElseThrow();
     CollectionInterface base = service.collection("default", null).orElseThrow();
     HardenedCollection coll = HardenedCollection.builder(
             base,
             new NoTotpKeyMaterialProvider(new EnvVarKeyMaterialProvider()))
             .acknowledgeSecurityTheater(true)   // env-var pepper is class-A theatre; required for CI/dev
             .build()) {

    base.unlock();

    String path = coll.createItem("api-token", "shhh-very-secret").orElseThrow();
    String value = coll.withSecret(path, String::new).orElseThrow();
    // The daemon stores AEAD ciphertext, NOT the plaintext "shhh-very-secret".
}
```

`SECRET_SERVICE_PEPPER` must be set in the environment (`EnvVarKeyMaterialProvider` fails closed if absent). For production, replace with a `Tpm2KeyMaterialProvider` (§9) or a custom provider (§7).

`acknowledgeSecurityTheater(true)` is required because `EnvVarKeyMaterialProvider` reports `sameUid=NONE`. Removing it for production is the deliberate moment to switch to a stronger provider.

---

## 4. Hardened: password verification with `matchesSecret`

The plaintext-free, constant-time comparison primitive. Use this whenever the question is "does this match what the user typed?".

```java
char[] candidate = readUserInput();   // e.g. JPasswordField.getPassword()
boolean ok = coll.matchesSecret(itemPath, candidate).orElse(false);
// candidate is zeroed by the library before returning, regardless of match outcome.
if (ok) {
    grantAccess();
} else {
    showLoginError();
}
```

The plaintext never reaches caller code; the comparison runs in time proportional to the smaller of the two lengths regardless of where bytes differ. Compare to the wrong way:

```java
// DO NOT DO THIS — plaintext escapes to caller code; Arrays.equals is variable-time.
boolean ok = coll.withSecret(itemPath, chars -> Arrays.equals(chars, candidate))
                 .orElse(false);
```

---

## 5. Hardened: batch read with fail-fast `withSecrets`

Returns `Optional.empty()` if **any** item fails to decrypt — no silently truncated map. Foreign (non-hardened) items in the same collection are filtered out before iteration.

```java
Optional<Integer> count = coll.withSecrets(map -> {
    map.forEach((path, secret) -> {
        // each `secret` is a char[] zeroed on exit
        System.out.println(path + " → length " + secret.length);
    });
    return map.size();
});
count.ifPresentOrElse(
    n -> System.out.println(n + " items processed"),
    () -> System.err.println("at least one item failed to decrypt; nothing exposed"));
```

---

## 6. Hardened: enable post-quantum + rotate epoch

Wires X25519 + ML-KEM-768 hybrid into HKDF DEK derivation. Uses native ML-KEM-768 from the stock SunJCE provider (JDK 24+, JEP 496) via `javax.crypto.KEM` — no third-party crypto provider needed.

```java
HardenedCollection coll = HardenedCollection.builder(base, provider)
        .enablePostQuantum(true)                 // ML-KEM-768 wired into HKDF
        .acknowledgeSecurityTheater(true)        // only if the provider is theater-rated
        .build();

// Write items; their envelopes carry kem_id=0x01 and a ~1090-byte kem_ct.
coll.createItem("token", "value-1").orElseThrow();
coll.createItem("token-b", "value-2").orElseThrow();

// Periodically (e.g. every 24h or 7d) rotate the epoch. Each item is rewrapped
// under a fresh epoch keypair, then the OLD keypair is destroyed in the
// EpochKeystore -- yielding real forward secrecy:
//   pre-rotation envelopes captured by an HNDL attacker are unrecoverable.
boolean ok = coll.rotateEpoch();
```

`enablePostQuantum(true)` falls back to X25519-only when no ML-KEM provider is available; the wrapper tells you via the startup INFO log:

```
HardenedCollection initialised: provider=Tpm2KeyMaterialProvider,
  threatCoverage=[sameUid=PARTIAL, crossUid=REAL, offline=REAL, networkHndl=NOT_APPLICABLE],
  acknowledgedTheater=false, totpMode=NO_TOTP, epoch=...
```

---

## 7. Hardened: implement a custom `KeyMaterialProvider`

Bring your own pepper source — typical use cases: HashiCorp Vault, AWS Secrets Manager, Linux kernel keyring, a hardware token via PKCS#11. Implement four methods:

```java
import de.swiesend.secretservice.hardened.KeyMaterialProvider;
import de.swiesend.secretservice.hardened.ThreatCoverage;
import java.util.Optional;

public final class VaultKeyMaterialProvider implements KeyMaterialProvider {
    private final char[] cachedPepper;

    public VaultKeyMaterialProvider(VaultClient vault, String path) {
        // Fetch once at startup; cache for the JVM lifetime.
        this.cachedPepper = vault.read(path).getValue().toCharArray();
    }

    @Override public char[] getPepper() {
        return cachedPepper.clone();   // caller zeros the clone; cache stays put
    }

    @Override public Optional<byte[]> getTotpSeed() {
        return Optional.empty();       // no TOTP factor in this implementation
    }

    @Override public Mode mode() {
        return Mode.NO_TOTP;
    }

    @Override public ThreatCoverage threatCoverage() {
        return new ThreatCoverage(
                // Class A: depends entirely on Vault's auth + your client's MAC
                ThreatCoverage.Level.PARTIAL,
                ThreatCoverage.Level.REAL,
                ThreatCoverage.Level.REAL,
                ThreatCoverage.Level.NOT_APPLICABLE,
                "Pepper fetched from Vault at startup; cached in JVM heap. Same-UID "
                        + "attacker reads JVM memory unless additional MAC is in place.");
    }
}
```

Then plug it in:

```java
KeyMaterialProvider provider = new VaultKeyMaterialProvider(vault, "secret/myapp/pepper");
HardenedCollection coll = HardenedCollection.builder(base, provider).build();
```

`Builder` rejects providers whose `threatCoverage().sameUid()` is `NONE` unless `.acknowledgeSecurityTheater(true)` is set. `PARTIAL` and `REAL` providers go through without ceremony.

---

## 8. TPM 2.0: provision a sealed pepper

One-shot operator command. Run once per host/installation. Requires `de.swiesend:secret-service-hardened-tpm2` plus `com.microsoft.azure:TSS.Java:1.0.0` on the runtime classpath.

### 8.1 Default flow — random pepper, password from prompt

```bash
# Provisioner generates a fresh base64 random pepper internally; password prompted on tty
java -cp "secret-service-hardened-tpm2-3.0.0-alpha.jar:TSS.Java-1.0.0.jar:slf4j-api-2.0.17.jar:slf4j-simple-2.0.17.jar" \
     de.swiesend.secretservice.hardened.tpm2.Tpm2Provisioner \
     --out ~/.config/myapp/pepper.tpm2blob \
     --password-prompt
```

Output: a sealed-blob file at mode 0600. The pepper is generated inside the JVM and never leaves the TPM after sealing — this means **losing the TPM = losing the items**.

### 8.2 Operator-supplied pepper (cross-host escrow path)

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

### 8.3 Headless CI provisioning

```bash
# pepper from a fixture in the platform's secret store, password from a different fixture
PEPPER="$CI_TPM_PEPPER" PASSWORD="$CI_TPM_PASSWORD" \
java -cp "..." Tpm2Provisioner \
  --out "$RUNNER_HOME/pepper.tpm2blob" \
  --password-env PASSWORD \
  --pepper-env PEPPER
```

### 8.4 What lands on disk

A `~44-character` base64 pepper (default flow) or your supplied bytes (operator-supplied flow) sealed inside a TPM keyed-hash object; the public + private blobs serialised into the file format documented in `Tpm2SealedBlob.java`. The file is mode 0600; the TPM enforces dictionary-attack lockout on wrong-password attempts (typically 32 strikes → standby).

---

## 9. TPM 2.0: use the sealed pepper at runtime

```java
import de.swiesend.secretservice.functional.SecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.hardened.HardenedCollection;
import de.swiesend.secretservice.hardened.providers.NoTotpKeyMaterialProvider;
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
     HardenedCollection coll = HardenedCollection.builder(
             base, new NoTotpKeyMaterialProvider(tpm)).build()) {

    base.unlock();

    // Use coll.createItem / withSecret / matchesSecret normally.
    coll.createItem("api-token", "shhh").orElseThrow();
}
// Tpm2KeyMaterialProvider.close() zeros the cached pepper on exit.
// HardenedCollection.close() doesn't propagate to the TPM provider -- close them yourself.
```

`forPlatformTpm` opens `/dev/tpmrm0` via TSS.Java's `TpmFactory.platformTpm()`. Use `forSimulator(...)` for tests against `localhost:2321`. The constructor unseals once at startup; subsequent `getPepper()` calls return clones of the cached value.

`Builder` accepts `Tpm2KeyMaterialProvider` without `acknowledgeSecurityTheater(true)` because its `threatCoverage().sameUid()` is `PARTIAL` (real same-UID defense requires an external MAC policy; see §3 of `threat_models_and_mitigation.md`).

---

## 10. TPM 2.0: graceful fallback when TSS.Java is missing

Don't reference `Tpm2KeyMaterialProvider` directly from generic code paths — that triggers `NoClassDefFoundError` if the consumer didn't add TSS.Java. Use `Tpm2Availability.isAvailable()` first; it has no `tss.*` imports so it's safe to call even when the library is absent.

```java
import de.swiesend.secretservice.hardened.KeyMaterialProvider;
import de.swiesend.secretservice.hardened.providers.EnvVarKeyMaterialProvider;
import de.swiesend.secretservice.hardened.providers.NoTotpKeyMaterialProvider;
import de.swiesend.secretservice.hardened.tpm2.Tpm2Availability;
import de.swiesend.secretservice.hardened.tpm2.Tpm2KeyMaterialProvider;

KeyMaterialProvider provider;
if (Tpm2Availability.isAvailable() && Files.exists(blobPath)) {
    char[] sealPw = System.console().readPassword("TPM unseal password: ");
    provider = new NoTotpKeyMaterialProvider(
            Tpm2KeyMaterialProvider.forPlatformTpm(blobPath, sealPw));
} else {
    log.warn(Tpm2Availability.installationHint());   // names the Maven coordinates
    provider = new NoTotpKeyMaterialProvider(new EnvVarKeyMaterialProvider());
}
```

`Tpm2Availability.isAvailable()` uses `Class.forName(name, false, classLoader)` to probe without forcing class initialisation — safe to call from any code path, even on systems with no TPM. `installationHint()` returns a human-readable string suitable for logging.

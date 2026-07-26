# Hardened usage

Samples for the opt-in `secret-service-hardened` artifact: application-layer AEAD envelopes (AES-256-GCM or ChaCha20-Poly1305), `matchesSecret`, batch reads, post-quantum + epoch rotation, and custom `KeyMaterialProvider`s. Read [Do I need this?](../security/index.md#do-i-need-this) first — most consumers need only the [core artifact](core.md).

## Minimal opt-in wrapper

Adds application-layer AEAD envelopes on top of any `CollectionInterface`. JDK 25 + `de.swiesend:secret-service-hardened`.

```java
import de.swiesend.secretservice.functional.SecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.hardened.HardenedCollection;
import de.swiesend.secretservice.hardened.providers.EnvVarKeyMaterialProvider;

try (SecretService service = SecretService.create().orElseThrow();
     CollectionInterface base = service.collection("default", null).orElseThrow();
     HardenedCollection coll = HardenedCollection.builder(
             base,
             new EnvVarKeyMaterialProvider())
             .acknowledgeSecurityTheater(true)   // env-var pepper is class-A theatre; required for CI/dev
             .build()) {

    base.unlock();

    String path = coll.createItem("api-token", "shhh-very-secret").orElseThrow();
    String value = coll.withSecret(path, String::new).orElseThrow();
    // The daemon stores AEAD ciphertext, NOT the plaintext "shhh-very-secret".
}
```

`SECRET_SERVICE_PEPPER` must be set in the environment (`EnvVarKeyMaterialProvider` fails closed if absent). For production, replace with a [`Tpm2KeyMaterialProvider`](tpm2.md) or a [custom provider](#implement-a-custom-keymaterialprovider).

`acknowledgeSecurityTheater(true)` is required because `EnvVarKeyMaterialProvider` reports `sameUid=NONE`. Removing it for production is the deliberate moment to switch to a stronger provider.

### Cipher suite and JVM hardening

The AEAD is selectable; AES-256-GCM is the default, ChaCha20-Poly1305 is available (both recorded in the authenticated envelope, so items stay readable regardless of the current default):

```java
import de.swiesend.secretservice.hardened.AeadId;

HardenedCollection coll = HardenedCollection.builder(base, provider)
        .aead(AeadId.CHACHA20_POLY1305)  // default is AeadId.AES_256_GCM
        .lockMemory(true)                // best-effort mlockall so pepper/DEK buffers cannot swap
        .build();

// status().memoryLocked() reports whether the lock actually took (never a hardcoded value):
boolean locked = coll.status().memoryLocked();
```

`lockMemory(true)` calls `mlockall` through the JDK Foreign Function & Memory API. It is off by default (it locks the whole process). For it to work, launch with `--enable-native-access=de.swiesend.secretservice.hardened` (otherwise the call still runs but the JVM prints a native-access warning) and ensure an adequate `RLIMIT_MEMLOCK` (`ulimit -l`, or `LimitMEMLOCK=infinity` / `CAP_IPC_LOCK` under systemd). See the [memory-hygiene inventory](../security/defense-mechanisms.md#memory-hygiene-mlockall-no-swap-no-core-dumps-no-attach).

---

## Password verification with `matchesSecret`

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

## Batch read with fail-fast `withSecrets`

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

## Enable post-quantum + rotate epoch

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
  acknowledgedTheater=false, epoch=...
```

---

## Implement a custom `KeyMaterialProvider`

Bring your own pepper source — typical use cases: HashiCorp Vault, AWS Secrets Manager, Linux kernel keyring, a hardware token via PKCS#11. Implement two methods — `getPepper()` and `threatCoverage()` — and, if you cache material, override `close()` to scrub it:

```java
import de.swiesend.secretservice.hardened.KeyMaterialProvider;
import de.swiesend.secretservice.hardened.ThreatCoverage;
import java.util.Arrays;

public final class VaultKeyMaterialProvider implements KeyMaterialProvider {
    private final char[] cachedPepper;

    public VaultKeyMaterialProvider(VaultClient vault, String path) {
        // Fetch once at startup; cache for the JVM lifetime.
        this.cachedPepper = vault.read(path).getValue().toCharArray();
    }

    @Override public char[] getPepper() {
        return cachedPepper.clone();   // caller zeros the clone; cache stays put
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

    @Override public void close() {
        Arrays.fill(cachedPepper, '\0');   // HardenedCollection.close() propagates to here
    }
}
```

Then plug it in:

```java
KeyMaterialProvider provider = new VaultKeyMaterialProvider(vault, "secret/myapp/pepper");
HardenedCollection coll = HardenedCollection.builder(base, provider).build();
```

`Builder` rejects providers whose `threatCoverage().sameUid()` is `NONE` unless `.acknowledgeSecurityTheater(true)` is set. `PARTIAL` and `REAL` providers go through without ceremony.

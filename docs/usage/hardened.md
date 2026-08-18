# Hardened usage

Samples for the opt-in `secret-service-hardened` artifact: application-layer AEAD envelopes (AES-256-GCM or ChaCha20-Poly1305), `matchesSecret`, batch reads, post-quantum + epoch rotation, and custom `KeyMaterialProvider`s. Read [Do I need this?](../security/index.md#do-i-need-this) first — most consumers need only the [core artifact](core.md).

## Minimal opt-in wrapper

Adds application-layer AEAD envelopes on top of any `CollectionInterface`. JDK 25 + `de.swiesend:secret-service-hardened`.

```java
import de.swiesend.secretservice.functional.SecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import de.swiesend.secretservice.hardened.HardenedCollection;
import de.swiesend.secretservice.hardened.providers.EnvVarKeyMaterialProvider;

try (ServiceInterface service = SecretService.create().orElseThrow();
     SessionInterface session = service.openSession().orElseThrow();
     CollectionInterface base = session.collection("default", Optional.empty()).orElseThrow();
     HardenedCollection coll = HardenedCollection.builder(
             base,
             new EnvVarKeyMaterialProvider())
             .acknowledgeSameUidExposure(true)   // see "What you are acknowledging" below
             .build()) {

    // No explicit unlock -- createItem/withSecret/getItems unlock the collection themselves.

    String path = coll.createItem("api-token", "shhh-very-secret").orElseThrow();
    // The daemon stores AEAD ciphertext, NOT the plaintext "shhh-very-secret".

    // Consume the plaintext INSIDE the callback; it is zeroed as soon as the callback returns.
    // Do not return it -- `String::new` would copy it into an immutable String that survives
    // the zeroing and lingers in the heap until GC.
    coll.withSecret(path, chars -> { httpClient.authorize(chars); return null; });

    // Verifying a secret needs no plaintext at all -- this is constant-time and copy-free:
    boolean ok = coll.matchesSecret(path, typedByUser).orElse(false);
}
```

`SECRET_SERVICE_PEPPER` must be set in the environment (`EnvVarKeyMaterialProvider` fails closed if absent). For production, replace with a [`Tpm2KeyMaterialProvider`](tpm2.md) or a [custom provider](#implement-a-custom-keymaterialprovider).

#### What you are acknowledging

`acknowledgeSameUidExposure(true)` is required because `EnvVarKeyMaterialProvider` reports `sameUid=NONE`. It is not a formality — you are accepting a specific, bounded loss:

| | |
|---|---|
| **What you give up** | Any process running as *your OS user* can read the pepper — from `/proc/<pid>/environ`, from a file it can open, or out of this JVM's heap — and decrypt every item. Against that attacker the hardened layer adds nothing. |
| **What you keep** | Everything else is untouched and real: an attacker who steals the keyring file offline, a different UID on the same host, and the D-Bus daemon itself all still see only AEAD ciphertext. The flag narrows the claim you may make; it does not weaken the ciphertext. |
| **When it's fine** | CI, tests, local development — wherever the same-UID attacker is out of scope by construction. |
| **What to use instead** | A provider that resists same-UID access. [`Tpm2KeyMaterialProvider`](tpm2.md) seals the pepper in hardware and rates same-UID `PARTIAL` — the honest ceiling, since a same-UID attacker can still ask the TPM to unseal as your process does, but cannot carry the pepper away. |

Building without the flag throws `SameUidExposureException` with the same explanation. Removing it for production is the deliberate moment to switch to a stronger provider.

A WARN is logged for every collection built with the flag set. Test suites that construct many collections can silence it with `.suppressSameUidExposureWarning(true)` — that changes nothing about the exposure, and should not be used to quieten a production deployment, where the warning is the only runtime signal that the condition exists.

### Cipher suite and JVM hardening

The AEAD is selectable ([why, and when to pick which](../architecture/index.md#why-these-primitives)); AES-256-GCM is the default, ChaCha20-Poly1305 is available (both recorded in the authenticated envelope, so items stay readable regardless of the current default):

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
        .acknowledgeSameUidExposure(true)        // only if the provider reports sameUid=NONE
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

/** Whatever your secret store exposes; only the one call matters here. */
interface VaultClient {
    String read(String path);
}

public final class VaultKeyMaterialProvider implements KeyMaterialProvider {
    private final char[] cachedPepper;

    public VaultKeyMaterialProvider(VaultClient vault, String path) {
        // Fetch once at startup; cache for the JVM lifetime.
        this.cachedPepper = vault.read(path).toCharArray();
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
        Arrays.fill(cachedPepper, '\0');   // called only if you opt in with .ownsProvider(true)
    }
}
```

Then plug it in:

<!-- docs-compile: skip references VaultKeyMaterialProvider and the caller's `vault` client, both defined above rather than in the library -->
```java
KeyMaterialProvider provider = new VaultKeyMaterialProvider(vault, "secret/myapp/pepper");
HardenedCollection coll = HardenedCollection.builder(base, provider).build();
```

`Builder` rejects providers whose `threatCoverage().sameUid()` is `NONE` (`ThreatCoverage.hasNoSameUidProtection()`) unless `.acknowledgeSameUidExposure(true)` is set — see [What you are acknowledging](#what-you-are-acknowledging). `PARTIAL` and `REAL` providers go through without ceremony.

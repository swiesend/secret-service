# Getting started

## Requirements

- **Linux** with a D-Bus session bus and a Secret Service provider (gnome-keyring, KeePassXC, or KWallet/ksecretd) owning `org.freedesktop.secrets`.
- **JDK 25** (all three artifacts target `--release 25`).
- Maven 3.6.0+ (or any build tool that consumes Maven coordinates).

## Coordinates

Three separately published jars, all released in lockstep at the same version. **Standard consumers add only `secret-service` and pay zero overhead from the optional layers.**

| Artifact | Adds | Extra runtime deps? |
|---|---|---|
| `de.swiesend:secret-service` | The classical Secret Service 0.2 client + transport encryption | hkdf, dbus-java, slf4j-api |
| `de.swiesend:secret-service-hardened` | Opt-in app-layer AES-256-GCM envelopes, `KeyMaterialProvider` SPI, hybrid X25519 + ML-KEM-768 (native SunJCE) | none beyond core (BouncyCastle is `provided/optional`, only for `Argon2KeyMaterialProvider`) |
| `de.swiesend:secret-service-hardened-tpm2` | TPM-sealed pepper provider + anti-rollback anchor | none beyond hardened (TSS.Java is `provided/optional`) |

**Most consumers want only the first row:**

```xml
<dependency>
    <groupId>de.swiesend</groupId>
    <artifactId>secret-service</artifactId>
    <version>3.0.0-alpha</version>
</dependency>
```

**Optional: app-layer encryption** — read [Do I need this?](security/index.md#do-i-need-this) first:

```xml
<dependency>
    <groupId>de.swiesend</groupId>
    <artifactId>secret-service-hardened</artifactId>
    <version>3.0.0-alpha</version>
</dependency>
```

**Optional: TPM-sealed pepper** (Linux + TPM 2.0 hardware required at runtime):

```xml
<dependency>
    <groupId>de.swiesend</groupId>
    <artifactId>secret-service-hardened-tpm2</artifactId>
    <version>3.0.0-alpha</version>
</dependency>
<!-- TSS.Java is required at runtime to actually open the TPM (provided/optional in our pom): -->
<dependency>
    <groupId>com.microsoft.azure</groupId>
    <artifactId>TSS.Java</artifactId>
    <version>1.0.0</version>
</dependency>
```

**Pinning all three with one BOM import:**

```xml
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>de.swiesend</groupId>
      <artifactId>secret-service-parent</artifactId>
      <version>3.0.0-alpha</version>
      <type>pom</type>
      <scope>import</scope>
    </dependency>
  </dependencies>
</dependencyManagement>
```

The 2.x line continues as a single artifact (`de.swiesend:secret-service:2.0.1-alpha`) for consumers who don't want the 3.x module split.

## First secret

```java
import de.swiesend.secretservice.functional.SecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import java.util.Optional;

try (ServiceInterface service = SecretService.create().orElseThrow()) {
    CollectionInterface collection = service.openSession()
            .flatMap(session -> session.collection("My Collection", Optional.empty()))
            .orElseThrow();

    String item = collection.createItem("My Item", "secret").orElseThrow();

    // withSecret zeroes the char[] after the callback returns — plaintext never escapes.
    collection.withSecret(item, secret -> {
        // use the secret here
        return true;
    });

    collection.deleteItem(item);
}
```

The functional API returns `Optional.empty()` on failure (no checked exceptions) and manages resources via `AutoCloseable`. Never build a `String` from a secret `char[]` — Strings are immutable and cannot be zeroed.

Continue with the **[core usage guide](usage/core.md)**, or the [hardened](usage/hardened.md) / [TPM 2.0](usage/tpm2.md) guides for the optional layers.

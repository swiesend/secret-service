# Secret Service

[![Maven Central](https://img.shields.io/maven-central/v/de.swiesend/secret-service.svg?label=Maven%20Central)](https://search.maven.org/search?q=g:%22de.swiesend%22%20AND%20a:%22secret-service%22)

A _Java_ library for storing secrets in a keyring over the _DBus_.

The library is conform to the freedesktop.org
[Secret Service API 0.2](https://specifications.freedesktop.org/secret-service/0.2) and thus compatible with Gnome linux systems.

The Secret Service itself is implemented by the [`gnome-keyring`](https://wiki.gnome.org/action/show/Projects/GnomeKeyring) and provided by the [`gnome-keyring-daemon`](https://wiki.gnome.org/Projects/GnomeKeyring/RunningDaemon).

This library can be seen as the functional equivalent to the [`libsecret`](https://wiki.gnome.org/Projects/Libsecret) C client library.

## Related

For KDE systems there is the [`kdewallet`](https://github.com/purejava/kdewallet) client library, kindly provided by [@purejava](https://github.com/purejava).

## Security Issues

> **Deployment guidance**: for the full threat model, OS-level mitigations (D-Bus policies, MAC, systemd hardening, LUKS), and per-distribution-format recommendations (`.deb`/`.rpm`, OCI, Flatpak, Snap, …), see [`docs/mitigate_threat_models_and_mitigation.md`](docs/mitigate_threat_models_and_mitigation.md).

### CVE-2018-19358 (Vulnerability)

There is an investigation on the behaviour of the Secret Service API, as other applications can easily read __any__ secret, if the keyring is unlocked (if a user is logged in, then the `login`/`default` collection is unlocked).
Available D-Bus protection mechanisms (involving the `busconfig` and `policy XML elements) are not used by default. But D-Bus protection mechanisms are not sufficient to protect against malicious attackers, because applications could identify themselves as different applications with various mechanisms.
The Secret Service API was never designed with a secure retrieval mechanism, as this problem is mainly a design problem in the Linux desktop itself, which does not provide _Sandboxing_ (like Flatpak, sandbox, containers) for applications by default.

The attack vector is known, see GnomeKeyring [SecurityFAQ](https://wiki.gnome.org/Projects/GnomeKeyring/SecurityFAQ), [SecurityPhilosophy](https://wiki.gnome.org/Projects/GnomeKeyring/SecurityPhilosophy) and [disputed](https://gitlab.gnome.org/GNOME/gnome-keyring/-/issues/5) because the behavior represents a design decision.

| Publisher | Url                                                                                                                                             | Base Score       | Vector | Published | Last Update | Status      |
|-----------|-------------------------------------------------------------------------------------------------------------------------------------------------|------------------|--------|-----------|-------------|-------------|
| NVD NIST  | [CVE-2018-19358](https://nvd.nist.gov/vuln/detail/CVE-2018-19358)                                                                               | __[7.8 HIGH]__   | CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 2018-11-18 | 2020-08-24 | active      |
| Cisco  | [GNOME Keyring Secret Service API Login Credentials Retrieval Vulnerability](https://tools.cisco.com/security/center/viewAlert.x?alertId=59179) | __[5.5 MEDIUM]__ | CVSS:3.0 |  |  | unpublished |
| Red Hat | [CVE-2018-19358](https://access.redhat.com/security/cve/cve-2018-19358)                                                                         | __[4.3 MEDIUM]__ | CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 2018-07-06 | 2023-04-06 | Red Hat Product Security determined that this flaw was not a security vulnerability, but a design problem in the Linux desktop |
| Suse | related issue [CVE-2008-7320](https://www.suse.com/security/cve/CVE-2008-7320.html)                                                             | [2.1 LOW]        | CVSS:2.0/AV:L/AC:L/Au:N/C:P/I:N/A:N | 2018-11-09 | 2023-07-03 | Resolved |

**Mitigation**

**Not recommended**
- Storing secrets in the `login`/`default` keyring, when there are potentially malicious applications installed by the user. This is often the case in not well maintained desktop environment.
- Implementing a `busconfig` for the D-Bus that enforces restrictions on the Secret Service API of the host system, knowing that these can be mitigated by providing a false sender/window/process id or dbus address.

**Recommended**
- [`easy`] Storing secrets in a non-default collection that is always locked. This is a compromise that is useful when the user is willing to be prompted for the collection password, when accessing a secret. One can lock the collection after retrieval, so that the secrets are only exposed for a brief moment.
- [`easy`] Using [KeePassXC](https://keepassxc.org/) as provider. The KeePassXC implementation of the Secret Service API mitigates unauthorized retrievals by providing several access control mechanisms.
  - [`easy`] Always locked collection: One can lock the collection after retrieval, so that the secrets are only exposed for a brief moment.
- [`easy`] Storing secrets in a file with proper permissions instead of using the Secret Service API.
  - [`moderate`] There are projects like [SOPS](https://github.com/getsops/sops) for secret-management to encrypt and edit files. But again oneself has to store the encryption keys securely.
  - [`easy`/`moderate`] Using disk encryption like [LUKS](https://gitlab.com/cryptsetup/cryptsetup) does not help against malicious applications, but at least against several scenarios with physical access. 
- [`moderate`/`advanced`] Deliver your application in a secure sandbox.

**KeePassXC**

Notification:
  - Show notification when passwords are retrieved by clients

Access Control:
  - Confirm when passwords are retrieved by clients.
  - Confirm when clients request entry deletion.
  - Prompt to unlock database before searching.
  - Management of an exposed database group, instead of the whole database.
  - Prohibiting the deletion of the database. Only entries can be deleted, but are moved to the "Recycle Bin" group by default.

Authorization:
  - Showing connected applications by PID and DBus Address.
  - Using a keyfile that has to be present when accessing the collection.

## Usage

The library provides two API layers, both using transport-encrypted secrets over the D-Bus.

### Coordinates (three independently published artifacts, same version)

Since `3.0.0-alpha` the project is a Maven reactor with **three separately published jars**, all released in lockstep at the same version number. **Standard consumers add only `secret-service` and pay zero overhead from the optional layers.**

| Artifact | JDK floor | Adds | Pulls extra runtime deps? |
|---|---|---|---|
| `de.swiesend:secret-service` | 17 | The classical Secret Service 0.2 client + transport encryption | hkdf, dbus-java, slf4j-api |
| `de.swiesend:secret-service-hardened` | 21 | Optional app-layer AES-256-GCM envelopes, `KeyMaterialProvider` SPI | none beyond core (BouncyCastle is `provided/optional` for opt-in PQ) |
| `de.swiesend:secret-service-hardened-tpm2` | 21 | TPM-sealed pepper provider | none beyond hardened (TSS.Java is `provided/optional`) |

**Most consumers want only the first row:**

```xml
<dependency>
    <groupId>de.swiesend</groupId>
    <artifactId>secret-service</artifactId>
    <version>3.0.0-alpha</version>
</dependency>
```

A `mvn dependency:tree` for that single declaration shows four transitive deps and nothing from the hardened or TPM modules. See [`docs/mitigate_threat_models_and_mitigation.md`](docs/mitigate_threat_models_and_mitigation.md) §7 to decide whether you also need the optional layers.

**Optional: app-layer encryption** (adds AES-256-GCM envelopes; requires JDK 21):

```xml
<dependency>
    <groupId>de.swiesend</groupId>
    <artifactId>secret-service-hardened</artifactId>
    <version>3.0.0-alpha</version>
</dependency>
```

**Optional: TPM-sealed pepper** (Linux + TPM 2.0 hardware required at runtime; requires JDK 21):

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

**Pinning all three at the same version with one BOM import:**

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

<dependencies>
  <dependency><groupId>de.swiesend</groupId><artifactId>secret-service</artifactId></dependency>
  <!-- add the hardened / hardened-tpm2 ones here; no <version> needed -->
</dependencies>
```

To swap out an incompatible `slf4j-api`, exclude it from `secret-service` (the only artifact that pulls it transitively).

### Legacy (`2.x.x`) coordinates

The 2.x line continues to ship as a single artifact for consumers who don't want the 3.x module split:

```xml
<dependency>
    <groupId>de.swiesend</groupId>
    <artifactId>secret-service</artifactId>
    <version>2.0.1-alpha</version>
</dependency>
```

### Functional API (Recommended)

The functional API uses instance-scoped connections, `Optional` returns, and `AutoCloseable` lifecycle management.

#### Basic Usage

```java
try (ServiceInterface service = SecretService.create()
        .orElseThrow(() -> new IOException("Secret service not available"))) {
    CollectionInterface collection = service
            .openSession()
            .flatMap(session -> session.collection("My Collection", Optional.empty()))
            .orElseThrow(() -> new IOException("Could not open collection"));

    // Store a secret
    String item = collection.createItem("My Item", "secret")
            .orElseThrow(() -> new IOException("Could not create item"));

    // Retrieve a secret safely using the callback API
    // The char[] is automatically zeroed after the callback returns.
    collection.withSecret(item, secret -> {
        // Use the secret here — it never escapes this scope.
        return Arrays.equals(secret, "secret".toCharArray());
    });

    // Clean up
    collection.deleteItem(item);
    collection.delete();
}
```

#### Secure Secret Access with Callbacks

The `withSecret()` and `withSecrets()` methods guarantee that decrypted secrets are zeroed from memory after the callback returns (or throws). This prevents sensitive data from lingering on the heap.

```java
try (ServiceInterface service = SecretService.create()
        .orElseThrow(() -> new IOException("Secret service not available"))) {
    CollectionInterface collection = service
            .openSession()
            .flatMap(session -> session.collection("My Collection", Optional.of("collection-password")))
            .orElseThrow(() -> new IOException("Could not open collection"));

    Map<String, String> attributes = Map.of("application", "my-app", "uuid", "42");
    String item = collection.createItem("API Key", "my-secret-api-key", attributes)
            .orElseThrow(() -> new IOException("Could not create item"));

    // Hash a secret without exposing it — only the hash escapes the callback.
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    Optional<byte[]> hash = collection.withSecret(item, secret -> {
        ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(secret));
        byte[] bytes = new byte[encoded.remaining()];
        encoded.get(bytes);
        try {
            return md.digest(bytes);
        } finally {
            Arrays.fill(bytes, (byte) 0);
            if (encoded.hasArray()) Arrays.fill(encoded.array(), (byte) 0);
        }
    });

    // Compare a secret against user input — only a boolean escapes.
    Optional<Boolean> matches = collection.withSecret(item, secret -> {
        return Arrays.equals(secret, userInput);
    });

    collection.deleteItem(item);
    collection.delete();
}
```

#### Standalone Collection (No Manual Session Management)

```java
// Opens its own D-Bus connection, session, and encryption — all cleaned up on close().
try (CollectionInterface collection = Collection.open("My Collection")
        .orElseThrow(() -> new IOException("Could not open collection"))) {
    String item = collection.createItem("My Item", "secret", Map.of("key", "value"))
            .orElseThrow(() -> new IOException("Could not create item"));

    // Find items by attributes
    List<String> found = collection.getItems(Map.of("key", "value")).orElse(List.of());

    collection.deleteItem(item);
    collection.delete();
}
```

### SimpleCollection API (Legacy)

The `SimpleCollection` API preserves the original 1.x interface for backward compatibility. It uses a static shared D-Bus connection with a JVM shutdown hook.

New code should prefer the functional API above.

```java
try (SimpleCollection collection = new SimpleCollection("My Collection", "super secret")) {
    // define unique attributes
    Map<String, String> attributes = new HashMap<>();
    attributes.put("uuid", "42");

    // create and forget
    collection.createItem("My Item", "secret", attributes);

    // find by attributes
    List<String> items = collection.getItems(attributes);
    String item = items.get(0);

    char[] actual = collection.getSecret(item);
    assertEquals("secret", new String(actual));
    Arrays.fill(actual, '\0'); // caller must clear manually

    collection.deleteItem(item);
    collection.delete();
}
// The D-Bus connection is closed at JVM shutdown, not by close().
// Call SimpleCollection.disconnect() to close it manually.
```

__Transport Encryption:__

Both APIs use transport encryption (DH key exchange + AES-128-CBC) automatically.
For details see: [Transfer of Secrets](https://specifications.freedesktop.org/secret-service/ch07.html),
[Transport Encryption Example](src/test/java/de/swiesend/secretservice/integration/IntegrationTest.java)

### Low-Level API

The low-level API gives access to all defined D-Bus `Methods`, `Properties` and `Signals` of the Secret Service interface:

* [Service](src/main/java/de/swiesend/secretservice/Service.java)
* [Collection](src/main/java/de/swiesend/secretservice/Collection.java)
* [Item](src/main/java/de/swiesend/secretservice/Item.java)
* [Session](src/main/java/de/swiesend/secretservice/Session.java)
* [Prompt](src/main/java/de/swiesend/secretservice/Prompt.java)

For the usage of the low-level API see the tests:

* [ServiceTest](src/test/java/de/swiesend/secretservice/integration/ServiceTest.java)
* [CollectionTest](src/test/java/de/swiesend/secretservice/integration/CollectionTest.java)
* [ItemTest](src/test/java/de/swiesend/secretservice/integration/ItemTest.java)
* [SessionTest](src/test/java/de/swiesend/secretservice/integration/SessionTest.java)
* [PromptTest](src/test/java/de/swiesend/secretservice/integration/PromptTest.java)

#### D-Bus Interfaces

The underlying introspected XML D-Bus interfaces are available as [resources](src/test/resources).

## Testing & Tools

All tests are integration tests that require a running session D-Bus and a Secret Service provider.

```bash
mvn test                                  # default suite (excludes @Tag("system-test"))
mvn test -Psystem-test                    # provider-agnostic system suite (ProviderSystemTest)
```

The CI test environments live under [`.github/providers/`](.github/providers) — one container per
provider (`gnome-keyring`, `kwallet`, `keepassxc`), each starting a path-based D-Bus via the shared
`dbus-up.sh`. The default regression workflow runs against gnome-keyring; the
[`system-tests`](.github/workflows/system-tests.yml) workflow runs the system suite across all three
providers (the KWallet/KeePassXC legs are best-effort and non-blocking).

```bash
docker build -f .github/providers/gnome-keyring/Dockerfile -t secret-service-test .
docker run --rm -v "$(pwd)":/workspace secret-service-test
```

### Standalone GUI

A standalone Swing GUI for manually exercising the library against a live provider lives in the
separate [`tools/gui`](tools/gui) project (kept out of the library jar and the test suite). Build the
core, then launch it:

```bash
mvn -DskipTests -Dgpg.skip=true install   # install the core artifact locally
mvn -f tools/gui/pom.xml exec:java         # launch the GUI
```

## Contributing

You are welcome to point out issues, file PRs and comment on the project.

Please keep in mind that this is a non-profit effort in my spare time and thus it may take some time until issues are addressed.

## Thank You

Special thanks goes out to
* [@purejava](https://github.com/purejava) for all the help!
* [@hypfvieh](https://github.com/hypfvieh) for providing and maintaining the [`dbus-java`](https://github.com/hypfvieh/dbus-java) library.
* [@infeo](https://github.com/infeo) for bug tracking like a king.
* [@overheadhunter](https://github.com/overheadhunter) for providing enhancements all over the place.
* [@jmehrens](https://github.com/jmehrens) for pointing out several issues and explaining them.
* [@aanno](https://github.com/aanno) for pointing out multiple issues.
* [@shocklateboy92](https://github.com/shocklateboy92) for making things spec compliant.
* [@invidian](https://github.com/invidian) for preparing KeePassXC support.

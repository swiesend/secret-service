# Core usage

End-to-end samples for the core `de.swiesend:secret-service` artifact — the classical Secret Service client with transport encryption. See [Getting started](../getting-started.md) for coordinates.

## Read & write a secret

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

## Legacy `SimpleCollection`

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

Internally `SimpleCollection` shares a static D-Bus connection (cleaned up by a JVM shutdown hook). Use the [functional API](#read-write-a-secret) for new code.

# Core usage

End-to-end samples for the core `de.swiesend:secret-service` artifact — the classical Secret Service client with transport encryption. See [Getting started](../getting-started.md) for coordinates.

## Read & write a secret

Plain Secret Service over D-Bus, transport-encrypted by default. JDK 25.

```java
import de.swiesend.secretservice.functional.SecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import java.util.Map;
import java.util.Optional;

try (ServiceInterface service = SecretService.create().orElseThrow();
     SessionInterface session = service.openSession().orElseThrow();
     CollectionInterface collection = session.collection("default", Optional.empty()).orElseThrow()) {

    // No explicit unlock: createItem, withSecret, getItems, search and friends unlock the
    // collection themselves. Use unlockWithUserPermission() only when you deliberately want
    // to force a prompt -- it locks first, so the user must re-authorise (CVE-2018-19358).

    // Write
    String path = collection
            .createItem("github-token", "ghp_xxxxxxxxxxxxxxxx",
                        Map.of("application", "myapp"))
            .orElseThrow();

    // Read inside a callback; the char[] is zeroed on exit. Use the plaintext here rather than
    // returning it -- `new String(chars)` copies it into an immutable String that outlives the
    // zeroing.
    collection.withSecret(path, chars -> {
        System.out.println("token starts with " + new String(chars, 0, 4) + "…");
        return null;
    });
}
```

Items are encrypted on the wire between this client and the daemon (gnome-keyring or KeePassXC), but **the daemon stores plaintext** — that is what the [hardened layer](hardened.md) changes.

**Secrets as `String`.** `createItem` takes a `CharSequence`, and a `String` literal cannot be zeroed
— it stays on the heap until GC. For real secrets prefer a `char[]`-backed `CharBuffer`, or the
`byte[]` overload on `TransportEncryption`.

---

## Find items

Two different tools. `getItems` matches attributes exactly; `search` does case-insensitive substring
matching against one field.

```java
// Exact attribute match -- all items with application=myapp
List<String> mine = collection.getItems(Map.of("application", "myapp")).orElseThrow();

// Substring match against the label
List<String> tokens = collection.search("token", SearchMode.BY_NAME);

// Fuzzy: tolerate a typo, up to an edit distance of 2
List<String> fuzzy = collection.search("tokne", SearchMode.BY_NAME, 2);
```

| `SearchMode` | Matches against |
|---|---|
| `BY_NAME` | the item's human-readable label |
| `BY_ATTRIBUTE_KEY` | any attribute key |
| `BY_ATTRIBUTE_VALUE` | any attribute value |
| `BY_OBJECT_ID` | the last path segment of the D-Bus path |
| `BY_OBJECT_PATH` | anywhere in the full D-Bus path |

**`getItems` distinguishes "nothing found" from "the search failed" — `search` does not.**
`Optional.of(List.of())` means the search succeeded and matched nothing; `Optional.empty()` means it
failed and you may infer nothing about the collection. `search` collapses both into an empty list, so
do not use it to decide whether something exists before deleting.

---

## Update and delete

```java
// Replace secret, label and attributes in one call. The password must be non-empty:
// updateItem cannot be used to change only the label.
boolean updated = collection.updateItem(path, "github-token (rotated)",
                                        "ghp_yyyyyyyyyyyyyyyy",
                                        Map.of("application", "myapp"));

boolean gone = collection.deleteItem(path);
boolean allGone = collection.deleteItems(List.of(path));
```

`deleteItems` returns the AND over each item — it does not stop at the first failure and does not tell
you *which* item failed. It also returns `false` for a null or empty list, i.e. a no-op reports as a
failure.

---

## Locking and prompts

Most calls unlock implicitly, so you rarely need this. When you do:

```java
boolean locked = collection.isLocked();
collection.lock();

// Force the user to re-authorise: this locks first, so the daemon must prompt (CVE-2018-19358).
boolean ok = collection.unlockWithUserPermission();
```

Two behaviours worth knowing before you rely on them:

- **`isLocked()` returns `true` when there is no connection** — "locked" and "cannot tell" are the
  same value.
- **`getSecrets()` / `withSecrets()` call `unlockWithUserPermission()` internally**, so they prompt
  even on an already-unlocked collection, and they **silently skip items they cannot read** — a short
  map is indistinguishable from a small collection. Prefer per-item `withSecret` when you need to know
  what failed.

Prompts default to a 120-second timeout. `disablePrompt()` suppresses the *generic* prompt path, but
not the per-item prompts raised by `createItem`, `lockItem` or `unlockItem`.

---

## Everything else at a glance

| Method | Returns | Meaning |
|---|---|---|
| `getSecret(path)` | `Optional<char[]>` | Raw array — **you** must zero it. Prefer `withSecret`. |
| `getSecrets()` / `withSecrets(cb)` | `Optional<Map<String,char[]>>` / `Optional<R>` | All items at once; prompts, and skips unreadable items |
| `getAttributes(path)` | `Optional<Map<String,String>>` | Empty if the item is missing *or* locked |
| `getItemLabel` / `setItemLabel` | `Optional<String>` / `boolean` | Per-item label |
| `getLabel()` | `Optional<String>` | **Cached** at open time — stale if changed out of band |
| `setLabel(label)` | `boolean` | Renames the collection |
| `getId()` | `Optional<String>` | Last path segment, e.g. `default` |
| `lockItem` / `unlockItem` | `boolean` | Reports the item's *observed* state, not call success |
| `enablePrompt` / `disablePrompt` | `boolean` | Always `true`; only flips a flag |
| `clear()` | `boolean` | Zeroes the cached collection password; `true` even if none was held |
| `delete()` | `boolean` | Deletes the collection; **refuses the default collection** |
| `close()` | `void` | Clears cached state; closes the whole stack only if this object created the session |

The `CollectionInterface` is `AutoCloseable`, but note that closing does not invalidate the D-Bus
handles — a closed collection still answers calls.

**Provider quirk worth designing around:** gnome-keyring injects its own `xdg:schema` attribute
asynchronously, so reading attributes immediately after `createItem` can race. Compare by containment,
not equality.

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

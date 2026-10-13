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
    // collection themselves. To make the user re-authorise before a bulk read or a delete,
    // set a consent policy -- see "Locking and prompts" below.

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

// Make bulk reads and deletes wait for the provider's unlock dialog, as 3.x always did: the
// collection is locked first, so the daemon must prompt (CVE-2018-19358).
collection.setConsentPolicy(ConsentPolicy.legacy());
```

By default (`ConsentPolicy.none()`) the library asks nobody before `getSecrets()`, `withSecrets()`,
`deleteItem()` or `deleteItems()`; the provider still prompts on its own terms, for example to unlock a
locked keyring. `ConsentPolicy.none().require(Operation.DELETE_MANY, Requirement.PROVIDER_PROMPT)`
asks for one operation only. The provider's dialog names the keyring, not the operation, and while it
is open the keyring is locked for every other application too.

Two behaviours worth knowing before you rely on them:

- **`isLocked()` returns `true` when there is no connection** — "locked" and "cannot tell" are the
  same value.
- **`getSecrets()` / `withSecrets()` silently skip items they cannot read** — a short map is
  indistinguishable from a small collection. Prefer per-item `withSecret` when you need to know what
  failed.

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

## Migrating from `SimpleCollection`

`SimpleCollection` was removed in 4.0. It threw checked exceptions; the functional API answers `Optional.empty()` or `false` instead and logs the reason. Its static connection, closed by a JVM shutdown hook, becomes an ordinary `try`-with-resources scope.

| `SimpleCollection` (3.x) | Functional API (4.0) |
|---|---|
| `new SimpleCollection()` | `SecretService.create()`, then `service.openSession()` and `session.defaultCollection()` |
| `new SimpleCollection(label, password)` | `session.collection(label, Optional.of(password))` |
| `SimpleCollection.isAvailable()` | `SecretService.create().isPresent()` |
| `SimpleCollection.isGnomeKeyringAvailable()` | `service.isGnomeKeyringAvailable()` |
| `createItem(label, secret, attributes)` returning the path | `createItem(label, secret, attributes)` returning `Optional<String>` |
| `getSecret(path)` returning `char[]` | `withSecret(path, callback)`, which zeroes the secret afterwards; or `getSecret(path)` returning `Optional<char[]>` |
| `getSecrets()` | `withSecrets(callback)` |
| `getItems(attributes)`, `null` for a collection without items | `getItems(attributes)` returning `Optional<List<String>>`: an empty list means no items, `Optional.empty()` a failed search |
| `getLabel(path)`, `getAttributes(path)` | `getItemLabel(path)`, `getAttributes(path)`, both `Optional` |
| `updateItem(...)`, `deleteItem(path)`, `deleteItems(paths)`, `delete()`, `lock()`, `isLocked()`, `clear()` | the same names, returning `boolean` where `SimpleCollection` threw |
| `unlockWithUserPermission()`, which `getSecrets()` and the deletes also ran | `collection.setConsentPolicy(ConsentPolicy.legacy())`, which puts bulk reads and deletes behind the provider's dialog as 3.x did |
| `getTimeout()`, `setTimeout(timeout)` | `service.getTimeout()`, `service.setTimeout(timeout)` |
| the static connection and its shutdown hook | `close()` the service; to share a connection that you manage, pass `System.wrap(connection)` to `SecretService.create` |

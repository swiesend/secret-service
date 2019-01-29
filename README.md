# Secret Service

A Java library to interact with the Secret Service API over the D-Bus.

The library is conform to [version 0.2](https://specifications.freedesktop.org/secret-service/) of the `freedesktop.org`
Secret Service API to access user keyrings.

The Secret Service is implemented by the GNOME Keyring (`gnome-keyring`) or the KDE Wallet Manager (`ksecretservice`).

@see: [Secret Storage Specification](https://www.freedesktop.org/wiki/Specifications/secret-storage-spec/)

## Example

The library provides a simplified API, which sends only transport encrypted secrets over the D-Bus.

@see: [Transfer of Secrets](https://specifications.freedesktop.org/secret-service/ch07.html),
[Transport Encryption Example](src/test/java/org/freedesktop/secret/integration/IntegrationTest.java)

```java
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.secret.interfaces.Item;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Example {

    @Test
    @DisplayName("Create a password in the user's default collection ('/org/freedesktop/secrets/aliases/default').")
    void createPasswordInDefaultCollection() {
        SimpleCollection collection = new SimpleCollection();
        DBusPath itemID = collection.createPassword("My Item", "secret");
        String actual = collection.getPassword(itemID);
        assertEquals("secret", actual);

        // delete with user's permission trough a prompt, as password is unknown.
        collection.deletePassword(itemID);
    }

    @Test
    @DisplayName("Create a password in a non-default collection ('/org/freedesktop/secrets/collection/xxxx').")
    void createPasswordInNonDefaultCollection() {
        SimpleCollection collection = new SimpleCollection("My Collection", "super secret");
        DBusPath itemID = collection.createPassword("My Item", "secret");
        String actual = collection.getPassword(itemID);
        assertEquals("secret", actual);

        // delete without prompting, as collection's password is known.
        collection.deletePassword(itemID);
        collection.delete();
    }

    @Test
    @DisplayName("Create a password with additional attributes.")
    void createPasswordWithAttributes() {
        SimpleCollection collection = new SimpleCollection("My Collection", "super secret");

        Map<String, String> attributes = new HashMap();
        attributes.put("uuid", "42");

        DBusPath itemID = collection.createPassword("My Item", "secret", attributes);
        String actual = collection.getPassword(itemID);
        assertEquals("secret", actual);
        Item item = collection.getItem(itemID);
        assertEquals("42", item.getAttributes().get("uuid"));

        // delete without prompting, as collection's password is known.
        collection.deletePassword(itemID);
        collection.delete();
    }
}
```

The low level API implements gives access to all defined Methods, Properties and Signals of the Secret Service 
interface:

  * [Service](src/main/java/org/freedesktop/secret/Service.java)
  * [Collection](src/main/java/org/freedesktop/secret/Collection.java)
  * [Item](src/main/java/org/freedesktop/secret/Item.java)
  * [Session](src/main/java/org/freedesktop/secret/Session.java)
  * [Prompt](src/main/java/org/freedesktop/secret/Prompt.java)

For examples on API usage checkout the tests:

  * [ServiceTest](src/test/java/org/freedesktop/secret/ServiceTest.java)
  * [CollectionTest](src/test/java/org/freedesktop/secret/CollectionTest.java)
  * [ItemTest](src/test/java/org/freedesktop/secret/ItemTest.java)
  * [SessionTest](src/test/java/org/freedesktop/secret/SessionTest.java)
  * [PromptTest](src/test/java/org/freedesktop/secret/PromptTest.java)

## Security Issues

### CVE-2018-19358 (Vulnerability)

There is a current investigation on the behaviour on the GNOME Keyring:

* [CVE-2018-19358](https://nvd.nist.gov/vuln/detail/CVE-2018-19358)
* [GNOME Keyring Secret Service API Login Credentials Retrieval Vulnerability](https://tools.cisco.com/security/center/viewAlert.x?alertId=59179)

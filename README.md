# Secret Service

[![Maven Central](https://img.shields.io/maven-central/v/de.swiesend/secret-service.svg?label=Maven%20Central)](https://search.maven.org/search?q=g:%22de.swiesend%22%20AND%20a:%22secret-service%22)

A Java library for storing secrets in a keyring over the D-Bus.

The library is conforming to the freedesktop.org
[Secret Service API 0.2](https://specifications.freedesktop.org/secret-service/0.2) and thus compatible with Gnome linux systems.

The Secret Service itself is implemented by the [`gnome-keyring`](https://wiki.gnome.org/action/show/Projects/GnomeKeyring) and provided by the [`gnome-keyring-daemon`](https://wiki.gnome.org/Projects/GnomeKeyring/RunningDaemon).

This library can be seen as the functional equivalent to the [`libsecret`](https://wiki.gnome.org/Projects/Libsecret) C client library.

## Related

For KDE systems there is the [`kdewallet`](https://github.com/purejava/kdewallet) client library, kindly provided by [@purejava](https://github.com/purejava).

## Security Issues

### CVE-2018-19358 (Vulnerability)

There is a current investigation on the behaviour of the Secret Service API, as other applications can easily read __any__ secret, if the keyring is unlocked (if a user is logged in, then the `login`/`default` collection is unlocked). Available D-Bus protection mechanisms (involving the busconfig and policy XML elements) are not used by default. The Secret Service API was never designed with a secure retrieval mechanism.

* [CVE-2018-19358](https://nvd.nist.gov/vuln/detail/CVE-2018-19358) Base Score: __[7.8 HIGH]__, CVSS:3.0

## Usage

The library provides a simplified high-level API, which sends only transport encrypted secrets over the D-Bus.

### Dependency

Add the `secret-service` as dependency to your project. You may want to exclude the `slf4j-api` if you use an incompatible version. The current version requires at least _JDK 17_.

```xml
<dependency>
    <groupId>de.swiesend</groupId>
    <artifactId>secret-service</artifactId>
    <version>1.8.1-jdk17</version>
    <exclusions>
        <exclusion>
            <groupId>org.slf4j</groupId>
            <artifactId>slf4j-api</artifactId>
        </exclusion>
    </exclusions>
</dependency>
```

### High-Level API

```java
public class Example {

    @Test
    @DisplayName("Create a password in the user's default collection (/org/freedesktop/secrets/aliases/default).")
    public void createPasswordInDefaultCollection() throws IOException, AccessControlException, IllegalArgumentException {
        try (SimpleCollection collection = new SimpleCollection()) {
            String item = collection.createItem("My Item", "secret");

            char[] actual = collection.getSecret(item);
            assertEquals("secret", new String(actual));
            assertEquals("My Item", collection.getLabel(item));

            collection.deleteItem(item);
        } // clears automatically all session secrets in memory, but does not close the D-Bus connection.
    }

    @Test
    @DisplayName("Create a password in a non-default collection (/org/freedesktop/secrets/collection/xxx).")
    public void createPasswordInNonDefaultCollection() throws IOException, AccessControlException, IllegalArgumentException {
        try (SimpleCollection collection = new SimpleCollection("My Collection", "super secret")) {
            String item = collection.createItem("My Item", "secret");

            char[] actual = collection.getSecret(item);
            assertEquals("secret", new String(actual));
            assertEquals("My Item", collection.getLabel(item));

            collection.deleteItem(item);
            collection.delete();
        } // clears automatically all session secrets in memory, but does not close the D-Bus connection.
    }

    @Test
    @DisplayName("Create a password with additional attributes.")
    public void createPasswordWithAttributes() throws IOException, AccessControlException, IllegalArgumentException {
        try (SimpleCollection collection = new SimpleCollection("My Collection", "super secret")) {
            // define unique attributes
            Map<String, String> attributes = new HashMap();
            attributes.put("uuid", "42");

            // create and forget
            collection.createItem("My Item", "secret", attributes);

            // find by attributes
            List<String> items = collection.getItems(attributes);
            assertEquals(1, items.size());
            String item = items.get(0);

            char[] actual = collection.getSecret(item);
            assertEquals("secret", new String(actual));
            assertEquals("My Item", collection.getLabel(item));
            assertEquals("42", collection.getAttributes(item).get("uuid"));

            collection.deleteItem(item);
            collection.delete();
        } // clears automatically all session secrets in memory, but does not close the D-Bus connection.
    }

    // The D-Bus connection gets closed at the end of the static lifetime of `SimpleCollection` by a shutdown hook.

}
```

__Closing the D-Bus connection:__

The D-Bus connection is closed eventually at end of the static lifetime of `SimpleCollection` with a shutdown hook and not by auto-close. One can also close the D-Bus connection manually by calling `SimpleCollection.disconnect()`, but once disconnected it is not possible to reconnect.

__SimpleCollection-Interface:__

For Further methods and attributes checkout the [SimpleCollection-Interface](src/main/java/org/freedesktop/secret/simple/interfaces/SimpleCollection.java).

__Transport Encryption:__

For the details of the transport encryption see: [Transfer of Secrets](https://specifications.freedesktop.org/secret-service/ch07.html),
[Transport Encryption Example](src/test/java/org/freedesktop/secret/integration/IntegrationTest.java)

### Low-Level API

The low-level API gives access to all defined D-Bus `Methods`, `Properties` and `Signals` of the Secret Service interface:

* [Service](src/main/java/org/freedesktop/secret/Service.java)
* [Collection](src/main/java/org/freedesktop/secret/Collection.java)
* [Item](src/main/java/org/freedesktop/secret/Item.java)
* [Session](src/main/java/org/freedesktop/secret/Session.java)
* [Prompt](src/main/java/org/freedesktop/secret/Prompt.java)

For the usage of the low-level API see the tests:

* [ServiceTest](src/test/java/org/freedesktop/secret/ServiceTest.java)
* [CollectionTest](src/test/java/org/freedesktop/secret/CollectionTest.java)
* [ItemTest](src/test/java/org/freedesktop/secret/ItemTest.java)
* [SessionTest](src/test/java/org/freedesktop/secret/SessionTest.java)
* [PromptTest](src/test/java/org/freedesktop/secret/PromptTest.java)

#### D-Bus Interfaces

The underlying introspected XML D-Bus interfaces are available as [resources](src/test/resources).

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

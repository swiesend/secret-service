package de.swiesend.secretservice.functional.integration;

import de.swiesend.secretservice.functional.Collection;
import de.swiesend.secretservice.functional.SecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


public class Example {
    private static final Logger log = LoggerFactory.getLogger(Example.class);

    @Test
    @DisplayName("API 2.0 Example")
    public void endToEndTest() throws Exception {

        char[] password;
        try (ServiceInterface service = SecretService.create().get()) {
            CollectionInterface collection = service
                    .openSession()
                    //.flatMap(session -> session.collection("täst", Optional.of("test")))
                    .flatMap(session -> session.collection("täst", Optional.empty()))
                    //.flatMap(session -> session.defaultCollection())
                    .get();
            String collectionLabel = collection.getLabel().get();
            String collectionId = collection.getId().get();
            log.info(String.format("Collection {label: \"%s\", id: \"%s\"}", collectionLabel, collectionId));

            Map<String, String> attributes = Map.of("key", "value");
            String itemPath = collection.createItem("label", "password", attributes).get();
            log.info(String.format("Created Item {path: \"%s\"}", itemPath));
            password = collection.getSecret(itemPath).get();
            boolean deleteItemSuccess = collection.deleteItem(itemPath);
            assertTrue(deleteItemSuccess);

            /*for (String oneItemPath : collection.getItems(attributes).get()) {
                String label = collection.getItemLabel(oneItemPath).get();
                log.info(String.format("Delete Item {label: %s, attributes: %s, path: %s}", label, attributes, oneItemPath));
                collection.deleteItem(oneItemPath);
            }*/

            // WARN: be careful activating this on the default collection...
            if (collectionLabel == "test" || collectionLabel == "täst") {
                log.info(String.format("Deleting collection {label: \"%s\", id: \"%s\"} …", collectionLabel, collectionId));
                boolean success = collection.delete();
                if (success)
                    log.info(String.format("Deleted collection {label: \"%s\", id: \"%s\"}", collectionLabel, collectionId));
                else
                    log.warn(String.format("Could not delete collection {label: \"%s\", id: \"%s\"}", collectionLabel, collectionId));
            }

            // CollectionInterface col2 = service.openSession()
            //        .flatMap(session -> session.collection("test", "test"))
            //        .get();
        }
        assertEquals("password", new String(password));

        /*try (ServiceInterface service = SecretService.create().get()) {
            try (SessionInterface session = service.openSession().get()) {
                try (CollectionInterface collection = session.collection("test", "test").get()) {
                    String item = collection.createItem("label", "password", Map.of("key", "value")).get();
                    Optional<char[]> secret = collection.getSecret(item);
                    collection.delete();
                    password = secret.get();
                }
            }
        }
        assertEquals("password", new String(password));
        password = "".toCharArray();

        password = SecretService.create().flatMap(
                service -> service.openSession()).flatMap(
                session -> session.collection("test", "test")).flatMap(
                collection -> {
                    String item = collection.createItem("label", "password", Map.of("key", "value")).get();
                    Optional<char[]> secret = collection.getSecret(item);
                    collection.delete();
                    return secret;
                }).get();

        assertEquals("password", new String(password));*/


        /*try (ServiceInterface service = SecretService.create().get()){
            try (SessionInterface session = service.openSession().get()) {
                try (CollectionInterface collection = session.collection("test", "test").get()) {
                    String item = collection.createItem("label", "password", Map.of("key", "value")).get();
                    Optional<char[]> secret = collection.getSecret(item);
                    collection.delete();
                    secret;
                }
            }
        }*/
    }

    @Test
    public void collection() throws Exception {
        char[] secret = null;

        try (CollectionInterface collection = new Collection("test")) {
            Map<String, String> attributes = Map.of("key", "value");
            String item1 = collection.createItem("s1", "s1", attributes).orElseThrow();
            secret = collection.getSecret(item1).orElseThrow();

            String item2 = collection.createItem("s1", "s2", attributes).orElseThrow();
            collection.getItems(attributes)
                    .ifPresent(items -> {
                        for (String it : items) {
                            collection.getSecret(it).ifPresent(s ->
                                    assertTrue("s1".equals(new String(s)) || "s2".equals(new String(s)))
                            );
                        }
                    });
            assertTrue(collection.deleteItem(item1));
            assertTrue(collection.deleteItem(item2));
            assertTrue(collection.delete());
        }
        assertEquals("s1", new String(secret));
    }
}

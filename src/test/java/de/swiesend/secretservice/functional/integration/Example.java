package de.swiesend.secretservice.functional.integration;

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
            log.info(String.format("Collection {label: %s, id: %s}", collectionLabel, collectionId));

            Map<String, String> attributes = Map.of("key", "value");
            String item = collection.createItem("label", "password", attributes).get();
            password = collection.getSecret(item).get();

            for (String itemPath : collection.getItems(attributes).get()) {
                String label = collection.getItemLabel(itemPath).get();
                log.info(String.format("[%s] {label: %s, attributes: %s}", itemPath, label, attributes));
                collection.deleteItem(itemPath);
            }
            // WARN: be careful activating this on the default collection...
            if (collectionId != "default") {
                log.info("Non default collection. Deleting collection...");
                collection.delete();
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
}

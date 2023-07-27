package de.swiesend.secretservice.functional;

import de.swiesend.secretservice.functional.interfaces.AvailableServices;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

public class SecretServiceTest {

    private static final Logger log = LoggerFactory.getLogger(SecretServiceTest.class);

    private SecretService secretService = null;

    @BeforeEach
    void beforeEach() {
        secretService = (SecretService) SecretService.create().get();
    }

    @AfterEach
    void afterEach() throws Exception {
        secretService.close();
    }

    @Test
    @DisplayName("Fiddling around")
    public void fiddlingAround() throws Exception {

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
                // collection.delete();
            }

            // CollectionInterface col2 = service.openSession()
            //        .flatMap(session -> session.collection("test", "test"))
            //        .get();
        }
        assertEquals("password", new String(password));
        password = "".toCharArray();

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
    void create() {
        assertNotNull(secretService);
    }

    @Test
    void isOrgGnomeKeyringAvailable() {
        System system = System.connect().get();
        assertTrue(SecretService.isAvailable(system, new AvailableServices(system)));
    }

    // TODO: check if needed at all
    @Test
    void clear() {
    }

    @Test
    void openSession() {
        assertTrue(secretService.openSession().isPresent());
    }

    @Test
    void getSessions() {
        assertEquals(0, secretService.getSessions().size());
        SessionInterface s1 = secretService.openSession().get();
        SessionInterface s2 = secretService.openSession().get();
        List<SessionInterface> actualSessions = secretService.getSessions().stream().toList();
        assertEquals(2, actualSessions.size());
        List<UUID> actualSessionIds = actualSessions.stream().map(s -> s.getId()).toList();
        assertTrue(actualSessionIds.contains(s1.getId()));
        assertTrue(actualSessionIds.contains(s2.getId()));
    }

    @Test
    void getTimeout() {
    }

    @Test
    void setTimeout() {
    }

    @Test
    void close() {
    }

    @Test
    void getService() {
    }
}

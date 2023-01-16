package de.swiesend.secret.functional;

import de.swiesend.secret.functional.interfaces.CollectionInterface;
import de.swiesend.secret.functional.interfaces.ServiceInterface;
import de.swiesend.secret.functional.interfaces.SessionInterface;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SecretServiceTest {

    private static final Logger log = LoggerFactory.getLogger(SecretServiceTest.class);

    @Test
    @DisplayName("Fiddling around")
    public void fiddlingAround() throws Exception {

        char[] password;
        try (ServiceInterface service = SecretService.create().get()) {
            CollectionInterface collection = service.openSession().flatMap(session ->
                    session.collection("test", "test")).get();
            Map<String, String> attributes = Map.of("key", "value");
            String item = collection.createItem("label", "password", attributes).get();
            password = collection.getSecret(item).get();
            /*for (String i : collection.getItems(attributes).get()) {
                log.info("[" + collection.getLabel(item).get() + "]" + i);
                // collection.deleteItem(i);
            }*/
            // collection.delete();

            CollectionInterface col2 = service.openSession().flatMap(session ->
                    session.collection("test", "test")).get();
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

}

package de.swiesend.secret.functional;

import org.freedesktop.dbus.exceptions.DBusException;
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
    public void fiddlingAround() throws DBusException {

        char[] password = SecretService.create().flatMap(
                service -> service.openSession().flatMap(
                        session -> session.collection("test", "test").flatMap(
                                collection -> collection.createItem("label", "password", Map.of("key", "value")).flatMap(
                                        path -> collection.getSecret(path)
                                )
                        )
                )
        ).get();

        assertEquals("password", new String(password));
    }

}

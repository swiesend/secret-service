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

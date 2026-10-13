package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.Secret;
import de.swiesend.secretservice.TransportEncryption;
import de.swiesend.secretservice.functional.SecretService;
import de.swiesend.secretservice.functional.System;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code clear()} must erase the transport session key, so the session can neither encrypt nor
 * decrypt afterwards. The session is a real Diffie-Hellman exchange with the fake provider on a
 * private bus.
 */
class TransportKeyLifecycleTest {

    private final FakeProviderFixture harness = new FakeProviderFixture();

    @BeforeEach
    void requireDbus() {
        Assumptions.assumeTrue(FakeProviderFixture.dbusDaemonAvailable(),
                "dbus-daemon is not on the PATH");
    }

    @AfterEach
    void stop() {
        harness.stop();
    }

    private static TransportEncryption.EncryptedSession open(TransportEncryption transport) {
        return transport.initialize()
                .flatMap(TransportEncryption.InitializedSession::openSession)
                .flatMap(TransportEncryption.OpenedSession::generateSessionKey)
                .orElseThrow(() -> new IllegalStateException("could not open a transport-encrypted session"));
    }

    @Test
    void clearErasesTheSessionKey() throws Exception {
        harness.start(false);
        TransportEncryption transport = new TransportEncryption(harness.clientConnection());
        TransportEncryption.EncryptedSession session = open(transport);

        Secret sealed = session.encrypt("the-transported-secret").orElseThrow();
        Optional<char[]> plain = session.decrypt(sealed);
        assertTrue(plain.isPresent(), "the session works before clear()");
        Arrays.fill(plain.get(), '\0');
        SecretKey key = sessionKeyOf(transport);

        transport.clear();

        assertTrue(session.encrypt("the-transported-secret").isEmpty(),
                "a cleared session must not encrypt: its key is gone");
        assertTrue(session.decrypt(sealed).isEmpty(),
                "a cleared session must not decrypt: its key is gone");
        // Not only dropped: a key that clear() merely forgot would pass the two checks above, and
        // its bytes would stay on the heap.
        assertTrue(key.isDestroyed(), "clear() destroys the key");
        assertArrayEquals(new byte[TransportEncryption.AES_BITS / 8], bytesOf(key), "and its bytes are zero");
    }

    @Test
    void closingTheFunctionalSessionErasesTheKey() throws Exception {
        harness.start(false);
        try (ServiceInterface service = SecretService.create(
                Optional.of(System.wrap(harness.clientConnection()))).orElseThrow()) {
            SessionInterface session = service.openSession().orElseThrow();
            TransportEncryption.EncryptedSession encrypted = session.getEncryptedSession();
            assertTrue(encrypted.encrypt("the-transported-secret").isPresent(), "the precondition: the session encrypts");

            session.close();

            assertTrue(encrypted.encrypt("the-transported-secret").isEmpty(),
                    "closing the session erased its key, not only the D-Bus session");
        }
    }

    /** The transport's own key: a private field, read by reflection from within the module. */
    private static SecretKey sessionKeyOf(TransportEncryption transport) throws Exception {
        Field field = TransportEncryption.class.getDeclaredField("sessionKey");
        field.setAccessible(true);
        return (SecretKey) field.get(transport);
    }

    /** The bytes the key holds itself, which getEncoded() no longer hands out once destroyed. */
    private static byte[] bytesOf(SecretKey key) throws Exception {
        Field field = key.getClass().getDeclaredField("key");
        field.setAccessible(true);
        return ((byte[]) field.get(key)).clone();
    }
}

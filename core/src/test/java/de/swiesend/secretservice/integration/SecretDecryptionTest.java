package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.Secret;
import de.swiesend.secretservice.TransportEncryption;
import org.freedesktop.dbus.DBusPath;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A session decrypts the secrets that name it, and gives none for any other: a secret without a
 * value threw, and a secret that names another session was decrypted all the same, under a key
 * that it was not encrypted with. The sessions are real Diffie-Hellman exchanges with the fake
 * provider on a private bus.
 */
class SecretDecryptionTest {

    private static final String PLAIN = "the-transported-secret";

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

    private TransportEncryption.EncryptedSession open() {
        return new TransportEncryption(harness.clientConnection()).initialize()
                .flatMap(TransportEncryption.InitializedSession::openSession)
                .flatMap(TransportEncryption.OpenedSession::generateSessionKey)
                .orElseThrow(() -> new IllegalStateException("could not open a transport-encrypted session"));
    }

    @Test
    void aSecretOfTheSessionIsDecrypted() throws Exception {
        harness.start(false);
        TransportEncryption.EncryptedSession session = open();

        Secret sealed = session.encrypt(PLAIN).orElseThrow();

        assertEquals(session.getSession().getPath().getPath(), sealed.getSession().getPath());
        assertArrayEquals(PLAIN.toCharArray(), session.decrypt(sealed).orElseThrow());
    }

    @Test
    void aSecretThatNamesAnotherSessionIsNotDecrypted() throws Exception {
        harness.start(false);
        TransportEncryption.EncryptedSession session = open();
        Secret sealed = session.encrypt(PLAIN).orElseThrow();

        // The session's own ciphertext, so that only the name stands against it.
        Secret renamed = new Secret(new DBusPath(session.getSession().getPath().getPath() + "0"),
                sealed.getSecretParameters(), sealed.getSecretValue(), sealed.getContentType());

        assertTrue(session.decrypt(renamed).isEmpty());
    }

    @Test
    void aSecretOfAnotherSessionIsNotDecrypted() throws Exception {
        harness.start(false);
        TransportEncryption.EncryptedSession session = open();
        // A provider gives each session a path of its own; the fake does where it is told one.
        harness.fake().setOpenSessionPath(FakeSecretService.SESSION_PATH + "2");
        TransportEncryption.EncryptedSession other = open();

        // Without the check about one in 256 of these decrypts, to something else than the secret.
        for (int i = 0; i < 2048; i++) {
            Secret sealed = other.encrypt(PLAIN).orElseThrow();
            assertTrue(session.decrypt(sealed).isEmpty(), "a secret of the other session, attempt " + i);
        }
    }

    @Test
    void aSecretWithoutAValueIsNotDecrypted() throws Exception {
        harness.start(false);
        TransportEncryption.EncryptedSession session = open();
        Secret sealed = session.encrypt(PLAIN).orElseThrow();

        Secret empty = new Secret(sealed.getSession(), sealed.getSecretParameters(), null);

        Optional<char[]> plain = assertDoesNotThrow(() -> session.decrypt(empty));
        assertTrue(plain.isEmpty());
    }

    @Test
    void aSecretWithoutAnInitializationVectorIsNotDecrypted() throws Exception {
        harness.start(false);
        TransportEncryption.EncryptedSession session = open();
        Secret sealed = session.encrypt(PLAIN).orElseThrow();

        Secret bare = new Secret(sealed.getSession(), null, sealed.getSecretValue());

        Optional<char[]> plain = assertDoesNotThrow(() -> session.decrypt(bare));
        assertTrue(plain.isEmpty());
    }

    @Test
    void eachSecretHasAnInitializationVectorOfItsOwn() throws Exception {
        harness.start(false);
        TransportEncryption.EncryptedSession session = open();
        Set<String> vectors = new HashSet<>();

        for (int i = 0; i < 64; i++) {
            byte[] vector = session.encrypt(PLAIN).orElseThrow().getSecretParameters();
            assertEquals(TransportEncryption.AES_BITS / 8, vector.length);
            vectors.add(Arrays.toString(vector));
        }

        assertEquals(64, vectors.size());
    }
}

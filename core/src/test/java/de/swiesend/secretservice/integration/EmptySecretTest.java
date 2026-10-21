package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.Secret;
import de.swiesend.secretservice.TransportEncryption;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * The transport encryption encrypts an empty secret like any other, as it did in every release: a
 * collection may have an empty password.
 */
class EmptySecretTest {

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

    @Test
    void anEmptySecretIsEncryptedAndDecrypted() throws Exception {
        harness.start(false);
        try (TransportEncryption transport = new TransportEncryption(harness.clientConnection())) {
            TransportEncryption.EncryptedSession session = transport.initialize()
                    .flatMap(TransportEncryption.InitializedSession::openSession)
                    .flatMap(TransportEncryption.OpenedSession::generateSessionKey)
                    .orElseThrow(() -> new IllegalStateException("could not open a transport-encrypted session"));

            Secret sealed = session.encrypt(new byte[0], StandardCharsets.UTF_8)
                    .orElseThrow(() -> new AssertionError("an empty secret is encrypted"));
            assertArrayEquals(new char[0], session.decrypt(sealed).orElseThrow(), "and decrypted");
        }
    }
}

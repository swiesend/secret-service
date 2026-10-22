package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.ProviderBug;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Both sides of a session hash its Diffie-Hellman shared secret into the session's AES key.
 * gnome-keyring and KeePassXC hash all of the secret's 128 bytes, as the library does, and KWallet
 * hashes it without its leading zero bytes. When the top byte was zero, about once in 256, KWallet's
 * key was another than the library's: KWallet refused every secret of the session with "Can't find
 * session", and the library could not decrypt the secrets that KWallet sent.
 *
 * <p>Against {@link FakeSecretService}, which hashes as either does, and gives a session a secret
 * whose top byte is zero when told to.</p>
 */
class SharedSecretTest {

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

    /** The fake item's secret, read through a session opened now. */
    private Optional<String> readThroughANewSession(SessionInterface session) {
        return session.collection(FakeSecretService.COLLECTION_LABEL, Optional.empty())
                .flatMap(collection -> collection.getSecret(FakeSecretService.ITEM_PATH))
                .map(String::new);
    }

    @Test
    void everySessionWorksWhereThePublicKeyIsReadAsSigned() throws Exception {
        // KWallet up to 6.24 reads the key as a signed number: one whose top bit is set, about
        // every second key, arrives changed without its sign byte.
        harness.start(false);
        harness.fake().reproduce(ProviderBug.KWALLET_READS_THE_PUBLIC_KEY_AS_SIGNED);

        for (int i = 0; i < 16; i++) {
            try (SessionInterface session = harness.service().openSession().orElseThrow()) {
                assertEquals(Optional.of(FakeSecretService.SECRET_VALUE), readThroughANewSession(session),
                        "the secret, through session " + i);
            }
        }
    }

    @Test
    void aSessionWhoseSecretHasAZeroTopByteIsReplaced() throws Exception {
        harness.start(false);
        harness.fake().reproduce(ProviderBug.KWALLET_HASHES_THE_SHARED_SECRET_WITHOUT_LEADING_ZEROS);
        harness.fake().setZeroTopByteSecrets(1);
        int opened = harness.fake().openSessionCalls();
        int closed = harness.fake().closeSessionCalls();

        try (SessionInterface session = harness.service().openSession().orElseThrow()) {
            assertEquals(Optional.of(FakeSecretService.SECRET_VALUE), readThroughANewSession(session),
                    "the secret, under the key that KWallet has as well");
            assertEquals(2, harness.fake().openSessionCalls() - opened, "a second session");
            assertEquals(1, harness.fake().closeSessionCalls() - closed, "which replaces the first");
        }
    }

    @Test
    void theReplacementWorksWhereAllBytesAreHashed() throws Exception {
        harness.start(false);
        harness.fake().setZeroTopByteSecrets(1);
        int opened = harness.fake().openSessionCalls();

        try (SessionInterface session = harness.service().openSession().orElseThrow()) {
            assertEquals(Optional.of(FakeSecretService.SECRET_VALUE), readThroughANewSession(session));
            assertEquals(2, harness.fake().openSessionCalls() - opened,
                    "the library cannot tell how a provider hashes, and replaces the session here too");
        }
    }

    @Test
    void anyOtherSessionIsKept() throws Exception {
        harness.start(false);
        harness.fake().reproduce(ProviderBug.KWALLET_HASHES_THE_SHARED_SECRET_WITHOUT_LEADING_ZEROS);
        int opened = harness.fake().openSessionCalls();
        int closed = harness.fake().closeSessionCalls();

        try (SessionInterface session = harness.service().openSession().orElseThrow()) {
            assertEquals(Optional.of(FakeSecretService.SECRET_VALUE), readThroughANewSession(session));
            assertEquals(1, harness.fake().openSessionCalls() - opened);
            assertEquals(0, harness.fake().closeSessionCalls() - closed);
        }
    }

    @Test
    void theFourthSuchSessionInARowIsKept() throws Exception {
        harness.start(false);
        harness.fake().setZeroTopByteSecrets(4);
        int opened = harness.fake().openSessionCalls();
        int closed = harness.fake().closeSessionCalls();

        try (SessionInterface session = harness.service().openSession().orElseThrow()) {
            assertEquals(Optional.of(FakeSecretService.SECRET_VALUE), readThroughANewSession(session),
                    "where all bytes are hashed, as before");
            assertEquals(4, harness.fake().openSessionCalls() - opened, "no more than four sessions");
            assertEquals(3, harness.fake().closeSessionCalls() - closed);
        }
    }
}

package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.Service;
import de.swiesend.secretservice.Static;
import de.swiesend.secretservice.TransportEncryption;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.types.Variant;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The provider answers {@code OpenSession} with its public key and the session's path. The library
 * took the reply as it came: an output that is no byte array threw a {@code ClassCastException} or
 * an {@code IllegalStateException} out of {@code openSession()}, which answers with an empty
 * {@code Optional}, and the session that the provider had opened stayed open.
 *
 * <p>Against {@link FakeSecretService}, which answers with what a test gives it.</p>
 */
class OpenSessionReplyTest {

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

    /** Sessions that the provider still has open after a call that opened none for the caller. */
    private int leftOpenBy(Variant<?> output) throws Exception {
        FakeSecretService fake = harness.fake();
        int opened = fake.openSessionCalls();
        int closed = fake.closeSessionCalls();
        fake.setOpenSessionOutput(output);

        assertEquals(Optional.empty(), harness.service().openSession(), "no session");
        return (fake.openSessionCalls() - opened) - (fake.closeSessionCalls() - closed);
    }

    @Test
    void anOutputThatIsNoPublicKeyOpensNoSession() throws Exception {
        harness.start(false);

        // The empty string is the output of a plain session, which the library did not ask for.
        assertEquals(0, leftOpenBy(new Variant<>("")), "and the provider's session is closed");
        assertEquals(0, leftOpenBy(new Variant<>(42)));
    }

    @Test
    void aPublicKeyThatMakesTheSharedSecretKnownOpensNoSession() throws Exception {
        harness.start(false);
        BigInteger p = FakeSecretService.SECOND_OAKLEY_GROUP_PRIME;

        // The shared secret would be 0, 1, and 1 or p - 1: whoever reads the bus has the key.
        assertEquals(0, leftOpenBy(new Variant<>(new byte[]{0})));
        assertEquals(0, leftOpenBy(new Variant<>(new byte[]{1})));
        assertEquals(0, leftOpenBy(new Variant<>(p.subtract(BigInteger.ONE).toByteArray())));
        assertEquals(0, leftOpenBy(new Variant<>(new byte[0])), "nor does an empty key");
    }

    @Test
    void anOutputThatIsDeclaredAByteArrayAndHoldsNoBytesOpensNoSession() throws Exception {
        // dbus-java hands a byte array over as byte[] or as a list of bytes. Whatever else comes
        // under that signature is no key, and the session's path still reaches the caller, which
        // closes the session.
        harness.start(false);
        DBusConnection connection = harness.service().getService().getConnection();
        DBusPath session = new DBusPath("/org/freedesktop/secrets/session/crafted");
        for (Object output : new Object[]{"text", List.of("a", "b"), Arrays.asList((Byte) null)}) {
            Service service = new Service(connection) {
                @Override
                protected Optional<Object[]> send(String method, String signature, Object... arguments) {
                    return "OpenSession".equals(method)
                            ? Optional.of(new Object[]{new Variant<>(output, "ay"), session})
                            : super.send(method, signature, arguments);
                }
            };

            assertEquals(Optional.of(session), service.openSession(
                            Static.Algorithm.DH_IETF1024_SHA256_AES128_CBC_PKCS7, new Variant<>(new byte[]{2}))
                    .map(reply -> reply.b), "the low-level call hands the session's path on");
            assertEquals(Optional.empty(), new TransportEncryption(service).initialize()
                    .flatMap(TransportEncryption.InitializedSession::openSession), "and the key exchange opens no session");
        }
    }

    @Test
    void aReplyWithoutASessionsPathOpensNoSession() throws Exception {
        harness.start(false);
        harness.fake().setOpenSessionPath("/");

        assertEquals(Optional.empty(), harness.service().openSession());
    }

    @Test
    void aSessionOpensAgainOnceTheProviderAnswersWithItsKey() throws Exception {
        harness.start(false);
        leftOpenBy(new Variant<>(""));
        harness.fake().setOpenSessionOutput(null);

        try (SessionInterface session = harness.service().openSession().orElseThrow()) {
            char[] secret = session.collection(FakeSecretService.COLLECTION_LABEL, Optional.empty())
                    .flatMap(collection -> collection.getSecret(FakeSecretService.ITEM_PATH))
                    .orElseThrow();
            assertArrayEquals(FakeSecretService.SECRET_VALUE.toCharArray(), secret);
        }
    }
}

package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.Static;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The transport encryption's Diffie-Hellman group is the one the specification prescribes, and no
 * code in the JVM can change it: {@code Static.RFC_2409.SecondOakleyGroup.PRIME} is public, and an
 * array cannot be made read-only.
 */
class DhGroupTest {

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
    void changingThePublicPrimeChangesNoKeyExchange() throws Exception {
        harness.start(false);
        byte[] prime = Static.RFC_2409.SecondOakleyGroup.PRIME;
        byte original = prime[1];
        prime[1] ^= 0x01;
        try {
            SessionInterface session = harness.service().openSession().orElseThrow();
            try (CollectionInterface collection = session
                    .collection(FakeSecretService.COLLECTION_LABEL, Optional.empty()).orElseThrow()) {
                // The fake keeps its own copy of the group, as a provider does. Had the session used
                // the changed prime, the two sides would derive different keys.
                assertEquals(Optional.of(FakeSecretService.SECRET_VALUE),
                        collection.withSecret(FakeSecretService.ITEM_PATH, String::new));
            }
        } finally {
            prime[1] = original;
        }
    }
}

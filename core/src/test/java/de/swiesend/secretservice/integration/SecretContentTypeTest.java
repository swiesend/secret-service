package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * A secret's content type comes from the application that stored it. The library reads the secret
 * whatever that content type says.
 */
class SecretContentTypeTest {

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
    void aSecretWhoseCharsetIsUnknownIsRead() throws Exception {
        CollectionInterface collection = harness.start(false);
        harness.fake().setSecretContentType("text/plain; charset=x-no-such-charset");

        assertEquals(Optional.of(FakeSecretService.SECRET_VALUE),
                collection.withSecret(FakeSecretService.ITEM_PATH, String::new));
    }

    @Test
    void aSecretIsDecodedInTheCharsetItsContentTypeNames() throws Exception {
        // As an application on ISO-8859-1 stores one. Decoded as UTF-8, the umlauts would be lost.
        CollectionInterface collection = harness.start(false);
        harness.fake().setStoredSecret("pässwörd", StandardCharsets.ISO_8859_1, "text/plain; charset=iso-8859-1");

        assertEquals(Optional.of("pässwörd"), collection.withSecret(FakeSecretService.ITEM_PATH, String::new));
    }

    @Test
    void aSecretWithoutACharsetIsDecodedAsUtf8() throws Exception {
        // The specification's default, and what libsecret's "text/plain" means.
        CollectionInterface collection = harness.start(false);
        harness.fake().setStoredSecret("pässwörd", StandardCharsets.UTF_8, "text/plain");

        assertEquals(Optional.of("pässwörd"), collection.withSecret(FakeSecretService.ITEM_PATH, String::new));
    }
}

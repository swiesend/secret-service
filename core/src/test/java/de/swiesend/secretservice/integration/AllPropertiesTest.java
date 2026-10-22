package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.Static;
import de.swiesend.secretservice.handlers.MessageHandler;
import org.freedesktop.dbus.types.Variant;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * {@code MessageHandler.getAllProperties} sent {@code GetAll} with the signature of {@code Get}, two
 * strings for its one argument, and failed every time; it read the reply's map as a variant
 * besides.
 *
 * <p>Against {@link FakeSecretService}, whose items answer {@code GetAll}.</p>
 */
class AllPropertiesTest {

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
    void anItemsPropertiesAreReadInOneCall() throws Exception {
        harness.start(false);
        MessageHandler handler = new MessageHandler(harness.clientConnection());

        Variant<?> all = handler.getAllProperties(FakeSecretService.BUS_NAME, FakeSecretService.ITEM_PATH,
                Static.Interfaces.ITEM).orElseThrow();

        Map<?, ?> properties = (Map<?, ?>) all.getValue();
        assertEquals("fake-item", ((Variant<?>) properties.get("Label")).getValue());
        assertEquals(Boolean.FALSE, ((Variant<?>) properties.get("Locked")).getValue());
    }
}

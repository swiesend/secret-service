package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A prompt is shown over the window that the service's window handle names, the
 * {@code window_id} of {@code Prompt.Prompt}, and over none by default. The library sent the last
 * segment of the prompt's path, which names the prompt and no window.
 *
 * <p>Against {@link FakeSecretService}, which records the window_id of each prompt shown.</p>
 */
class WindowHandleTest {

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
    void aPromptIsShownOverNoWindowByDefault() throws Exception {
        CollectionInterface collection = harness.start(true);

        assertTrue(collection.unlockItem(FakeSecretService.ITEM_PATH));
        assertEquals(List.of(""), harness.fake().promptWindowIds(), "not the id of the prompt");
    }

    @Test
    void aPromptIsShownOverTheWindowThatTheServiceNames() throws Exception {
        CollectionInterface collection = harness.start(true);
        ServiceInterface service = harness.session().getService();
        assertEquals("", service.getWindowHandle());

        // Set after the collection is open: a prompt reads the handle when it is shown.
        service.setWindowHandle("x11:4a0000e");

        assertTrue(collection.unlockItem(FakeSecretService.ITEM_PATH));
        assertEquals(List.of("x11:4a0000e"), harness.fake().promptWindowIds());
        assertEquals("x11:4a0000e", service.getWindowHandle());
    }

    @Test
    void aWindowHandleIsNotNull() throws Exception {
        harness.start(false);
        ServiceInterface service = harness.session().getService();

        assertThrows(NullPointerException.class, () -> service.setWindowHandle(null));
        assertEquals("", service.getWindowHandle(), "a refused handle changes nothing");
    }
}

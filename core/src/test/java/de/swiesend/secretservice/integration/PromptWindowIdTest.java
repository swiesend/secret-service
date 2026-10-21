package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * {@code Prompt(window_id)} takes the caller's window, over which the provider shows its dialog:
 * KeePassXC reads it as an X11 window, oo7 as "x11:" or "wayland:" and a handle. The library sent
 * the last segment of the prompt's path, which names the prompt and no window.
 */
class PromptWindowIdTest {

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
    void aPromptIsShownWithAnEmptyWindowId() throws Exception {
        CollectionInterface collection = harness.start(true);
        harness.fake().setDismissPrompts(true);

        assertFalse(collection.unlockItem(FakeSecretService.ITEM_PATH),
                "the precondition: the user refused the prompt that unlocks the item");

        assertEquals(1, harness.fake().promptCalls().size(), "the library showed the prompt");
        assertEquals(List.of(""), harness.fake().promptWindowIds(),
                "with the empty window id, not the last part of the prompt's path");
    }
}

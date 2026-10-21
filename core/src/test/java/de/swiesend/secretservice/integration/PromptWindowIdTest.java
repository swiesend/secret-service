package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.Prompt;
import de.swiesend.secretservice.handlers.MessageHandler;
import org.freedesktop.dbus.DBusPath;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * {@code Prompt(window_id)} takes the caller's window, over which the provider shows its dialog:
 * KeePassXC reads it as an X11 window, oo7 as "x11:" or "wayland:" and a handle. The library sent
 * the last segment of the prompt's path, which names the prompt and no window.
 *
 * <p>The fake provider exports no Prompt object, so the call is recorded on the library's side.</p>
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
        harness.start(false);
        List<Object> windowIds = Collections.synchronizedList(new ArrayList<>());
        Prompt prompt = new Prompt(harness.service().getService()) {
            {
                msg = new MessageHandler(getConnection()) {
                    @Override
                    public Optional<Object[]> send(String service, String path, String iface, String method,
                                                   String signature, Object... args) {
                        if ("Prompt".equals(method)) windowIds.add(args[0]);
                        return Optional.of(new Object[0]);
                    }
                };
            }
        };
        try {
            prompt.prompt(new DBusPath(FakeSecretService.PROMPT_PATH));

            assertEquals(List.of(""), windowIds, "not \"fake\", the id of the prompt");
        } finally {
            prompt.getSignalHandler().disconnect();
        }
    }
}

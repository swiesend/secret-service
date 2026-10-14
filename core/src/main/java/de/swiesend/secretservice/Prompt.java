package de.swiesend.secretservice;

import de.swiesend.secretservice.handlers.Messaging;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.messages.DBusSignal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;

import static de.swiesend.secretservice.Static.DEFAULT_PROMPT_TIMEOUT;
import static de.swiesend.secretservice.Static.ObjectPaths.PROMPT;

public class Prompt extends Messaging implements de.swiesend.secretservice.interfaces.Prompt {

    public static final List<Class<? extends DBusSignal>> signals = Arrays.asList(Completed.class);

    private static final Logger log = LoggerFactory.getLogger(Prompt.class);

    public Prompt(Service service) {
        super(service.getConnection(), signals,
                Static.Service.SECRETS,
                "/",
                Static.Interfaces.PROMPT);
    }

    @Override
    public boolean prompt(String window_id) {
        objectPath = Static.ObjectPaths.prompt(window_id);
        return send("Prompt", "s", window_id).isPresent();
    }

    @Override
    public boolean prompt(DBusPath prompt) {
        // Read and addressed through a local: another thread's prompt() can change the objectPath
        // field, which stays set for getObjectPath() and dismiss().
        final String path = prompt.getPath();
        objectPath = path;

        String windowID = "";

        if (path.startsWith(PROMPT + "/")) {
            try {
                // NOTE: If the windowID starts with the prefix 'p' or 'u' followed by numerics only,
                //       then it comes from the gnome-keyring. KeePassXC generates random alphanumeric ids.
                windowID = path.substring(path.lastIndexOf("/") + 1);
            } catch (IndexOutOfBoundsException | NullPointerException e) {
                log.warn(String.format("No proper window ID. Continuing with window ID: \"%s\"", windowID));
            }
        } else {
            log.warn(String.format("No proper prompt path. Continuing with window ID: \"%s\"", windowID));
        }

        return msg.send(serviceName, path, interfaceName, "Prompt", "s", windowID).isPresent();
    }

    /**
     * Await the user interaction with the prompt.
     * <p>
     * A prompt can either be dismissed or be completed successfully.
     *
     * @param path    Objectpath of the prompt.
     * @param timeout Duration until the prompt times out.
     * @return Completed, or null if user input exceeds the timeout, or if {@code path} is "/", the
     *         Secret Service's answer when no prompt is needed: there is no prompt to wait for.
     * @see Completed
     */
    public Completed await(DBusPath path, Duration timeout) {
        if ("/".equals(path.getPath())) {
            // No prompt, so no result of one. The newest Completed signal this handler has seen
            // came from another prompt, perhaps another application's.
            return null;
        } else {
            return sh.await(
                    Completed.class,
                    path.getPath(),
                    () -> {
                        prompt(path);
                        // What the handler dismisses when nobody answers in time: this prompt.
                        return new Bound(path);
                    },
                    timeout
            );
        }
    }

    /**
     * Dismiss the prompt at {@code prompt}. Unlike {@link #dismiss()}, it does not depend on which
     * prompt this object was last asked to show.
     */
    public boolean dismiss(DBusPath prompt) {
        return msg.send(serviceName, prompt.getPath(), interfaceName, "Dismiss", "").isPresent();
    }

    /**
     * This object, fixed to one prompt path, so that each await dismisses its own prompt: two
     * threads can await prompts through the same object.
     */
    private final class Bound implements de.swiesend.secretservice.interfaces.Prompt {

        private final DBusPath path;

        Bound(DBusPath path) {
            this.path = path;
        }

        @Override
        public boolean prompt(String window_id) {
            return Prompt.this.prompt(window_id);
        }

        @Override
        public boolean prompt(DBusPath prompt) {
            return Prompt.this.prompt(prompt);
        }

        @Override
        public boolean dismiss() {
            return Prompt.this.dismiss(path);
        }

        @Override
        public boolean isRemote() {
            return false;
        }

        @Override
        public String getObjectPath() {
            return path.getPath();
        }
    }

    /**
     * Await the user interaction with the prompt.
     * <p>
     * A prompt can either be dismissed or be completed successfully.
     *
     * @param path Objectpath of the prompt.
     * @return Completed, or null if user input exceeds the default timeout, or if {@code path} is
     *         "/", for no prompt.
     * @see Completed
     */
    public Completed await(DBusPath path) {
        return await(path, DEFAULT_PROMPT_TIMEOUT);
    }

    @Override
    public boolean dismiss() {
        return send("Dismiss", "").isPresent();
    }

    @Override
    public boolean isRemote() {
        return false;
    }

    @Override
    public String getObjectPath() {
        return super.getObjectPath();
    }

}

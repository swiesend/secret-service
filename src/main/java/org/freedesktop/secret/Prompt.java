package org.freedesktop.secret;

import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.messages.DBusSignal;
import org.freedesktop.secret.errors.NoSuchObject;
import org.freedesktop.secret.handlers.Messaging;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.freedesktop.secret.Static.DEFAULT_PROMPT_TIMEOUT;
import static org.freedesktop.secret.Static.ObjectPaths.PROMPT;

public class Prompt extends Messaging implements org.freedesktop.secret.interfaces.Prompt {

    public static final List<Class<? extends DBusSignal>> signals = Arrays.asList(Completed.class);

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
    public boolean prompt(ObjectPath prompt) {
        objectPath = prompt.getPath();
        try {
            if (objectPath.startsWith(PROMPT + "/p") || objectPath.startsWith(PROMPT + "/u")) {
                String[] split = prompt.getPath().split("/");
                String window_id = split[split.length - 1];
                return send("Prompt", "s", window_id).isPresent();
            } else {
                // log.info("NoSuchObject(" + objectPath+ ")")
                // throw new NoSuchObject(objectPath);
                return false;
            }
        } catch (IndexOutOfBoundsException | NullPointerException e) {
            // throw new NoSuchObject(objectPath);
            return false;
        }
    }

    /**
     * Await the user interaction with the prompt.
     * <p>
     * A prompt can either be dismissed or be completed successfully.
     *
     * @param path    Objectpath of the prompt.
     * @param timeout Duration until the prompt times out.
     * @return Completed or null if user input exceeds the default timeout.
     * @see Completed
     */
    public Completed await(ObjectPath path, Duration timeout) {
        if ("/".equals(path.getPath())) {
            return sh.getLastHandledSignal(Completed.class);
        } else {
            return sh.await(Completed.class, path.getPath(), () -> {
                        prompt(path);
                        return this;
                    },
                    timeout);
        }
    }

    /**
     * Await the user interaction with the prompt.
     * <p>
     * A prompt can either be dismissed or be completed successfully.
     *
     * @param path Objectpath of the prompt.
     * @return Completed or null if user input exceeds the default timeout.
     * @see Completed
     */
    public Completed await(ObjectPath path) {
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

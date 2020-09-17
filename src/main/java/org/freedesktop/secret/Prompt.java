package org.freedesktop.secret;

import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.messages.DBusSignal;
import org.freedesktop.secret.errors.NoSuchObject;
import org.freedesktop.secret.handlers.Messaging;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;

import static org.freedesktop.secret.Static.DEFAULT_TIMEOUT;

public class Prompt extends Messaging implements org.freedesktop.secret.interfaces.Prompt {

    public static final List<Class<? extends DBusSignal>> signals = Arrays.asList(Completed.class);

    public Prompt(Service service) {
        super(service.getConnection(), signals,
                Static.Service.SECRETS,
                "/",
                Static.Interfaces.PROMPT);
    }

    @Override
    public void prompt(String window_id) {
        objectPath = Static.ObjectPaths.prompt(window_id);
        send("Prompt", "s", window_id);
    }

    @Override
    public void prompt(ObjectPath prompt) throws NoSuchObject {
        objectPath = prompt.getPath();

        if (objectPath.startsWith("/org/freedesktop/secrets/prompt/p") ||
                objectPath.startsWith("/org/freedesktop/secrets/prompt/u")) {
            String[] split = prompt.getPath().split("/");
            String window_id = split[split.length - 1];

            send("Prompt", "s", window_id);
        } else {
            throw new NoSuchObject(objectPath);
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
        return await(path, DEFAULT_TIMEOUT);
    }


    @Override
    public void dismiss() {
        send("Dismiss", "");
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

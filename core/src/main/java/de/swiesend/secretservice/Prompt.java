package de.swiesend.secretservice;

import de.swiesend.secretservice.handlers.Messaging;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.messages.DBusSignal;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;

import static de.swiesend.secretservice.Static.DEFAULT_PROMPT_TIMEOUT;

public class Prompt extends Messaging implements de.swiesend.secretservice.interfaces.Prompt {

    public static final List<Class<? extends DBusSignal>> signals = Arrays.asList(Completed.class);

    private final Service service;

    public Prompt(Service service) {
        super(service.getMessageHandler(), signals,
                Static.Service.SECRETS,
                "/",
                Static.Interfaces.PROMPT);
        this.service = service;
    }

    @Override
    public boolean prompt(String window_id) {
        objectPath = Static.ObjectPaths.prompt(window_id);
        return send("Prompt", "s", window_id).isPresent();
    }

    @Override
    public boolean prompt(DBusPath prompt) {
        objectPath = prompt.getPath();
        // The window_id names the caller's window, over which the provider shows its dialog: the
        // service's window handle, empty for none.
        return send("Prompt", "s", service.getWindowHandle()).isPresent();
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
    public Completed await(DBusPath path, Duration timeout) {
        if ("/".equals(path.getPath())) {
            return sh.getLastHandledSignal(Completed.class);
        } else {
            return sh.await(
                    Completed.class,
                    path.getPath(),
                    () -> {
                        prompt(path);
                        return this;
                    },
                    timeout
            );
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

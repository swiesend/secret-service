package org.freedesktop.secret;

import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.messages.DBusSignal;
import org.freedesktop.secret.errors.NoSuchObject;
import org.freedesktop.secret.handlers.SignalHandler;

import java.util.Arrays;
import java.util.List;

public class Prompt extends org.freedesktop.secret.interfaces.Prompt {

    public static final List<Class<? extends DBusSignal>> signals = Arrays.asList(Completed.class);

    public Prompt(Service service) {
        super(service.getConnection(), signals,
                Static.Service.SECRETS,
                "/",
                Static.Interfaces.PROMT);
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

    @Override
    public Completed await(ObjectPath path) {
        if ("/".equals(path.getPath())) {
            return sh.getLastHandledSignal(Completed.class);
        } else {
            return sh.await(Completed.class, path.getPath(), () -> {
                prompt(path);
                return null;
            });
        }
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

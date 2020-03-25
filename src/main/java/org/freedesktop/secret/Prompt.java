package org.freedesktop.secret;

import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.messages.DBusSignal;
import org.freedesktop.secret.errors.NoSuchObjectException;

import java.util.Arrays;
import java.util.List;

public class Prompt extends org.freedesktop.secret.interfaces.Prompt {

    public static final List<Class<? extends DBusSignal>> signals = Arrays.asList(Completed.class);

    public Prompt(Service service) {
        super(service.getConnection(), signals,
                Static.Service.SECRETS,
                "/",
                Static.Interfaces.PROMPT);
    }

    @Override
    public void prompt(String window_id) throws DBusException {
        objectPath = Static.ObjectPaths.prompt(window_id);
        send("Prompt", "s", window_id);
    }

    @Override
    public void prompt(ObjectPath prompt) throws NoSuchObjectException, DBusException {
        objectPath = prompt.getPath();

        if (objectPath.startsWith("/org/freedesktop/secrets/prompt/p") ||
                objectPath.startsWith("/org/freedesktop/secrets/prompt/u")) {
            String[] split = prompt.getPath().split("/");
            String window_id = split[split.length - 1];

            send("Prompt", "s", window_id);
        } else {
            throw new NoSuchObjectException(objectPath);
        }
    }

    @Override
    public Completed await(ObjectPath path) throws DBusException {
        if ("/".equals(path.getPath())) {
            return sh.getLastHandledSignal(Completed.class).orElseThrow(DBusException::new);
        } else {
            return sh.await(Completed.class, path.getPath(), () -> {
                prompt(path);
                return null;
            }).orElseThrow(DBusException::new);
        }
    }

    @Override
    public void dismiss() {
        try {
            send("Dismiss", "");
        } catch (DBusException e) {
            // nothing
        }
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

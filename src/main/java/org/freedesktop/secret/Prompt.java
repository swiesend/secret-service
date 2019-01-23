package org.freedesktop.secret;

import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.secret.errors.NoSuchObject;

import java.util.Arrays;
import java.util.List;

public class Prompt extends org.freedesktop.secret.interfaces.Prompt {

    public static final List<Class> signals = Arrays.asList(Completed.class);

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

    public void await(ObjectPath path) throws InterruptedException, NoSuchObject {
        int init = sh.getCount();
        int await = init;
        prompt(path);
        while (await == init) {
            // wait until the user handles the prompt
            Thread.sleep(200L);
            await = sh.getCount();
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

    public Completed getCurrentSingal() {
        return (Completed) sh.getHandled()[0];
    }

}

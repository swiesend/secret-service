package org.freedesktop.secret;

import org.freedesktop.dbus.DBusPath;
import org.freedesktop.secret.handlers.Messaging;


public class Session extends Messaging implements org.freedesktop.secret.interfaces.Session {


    public Session(DBusPath path, Service service) {
        super(service.getConnection(), null,
                Static.Service.SECRETS, path.getPath(), Static.Interfaces.SESSION);
    }

    public Session(String session_id, Service service) {
        super(service.getConnection(), null,
                Static.Service.SECRETS, Static.ObjectPaths.session(session_id), Static.Interfaces.SESSION);
    }

    @Override
    public boolean close() {
        return send("Close").isPresent();
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

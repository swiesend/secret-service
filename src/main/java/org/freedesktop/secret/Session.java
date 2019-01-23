package org.freedesktop.secret;

import org.freedesktop.dbus.DBusPath;


public class Session extends org.freedesktop.secret.interfaces.Session {

    private Service service;

    public Session(DBusPath path, Service service) {
        super(service.getConnection(), null,
                Static.Service.SECRETS, path.getPath(), Static.Interfaces.SESSION);
        this.service = service;
    }

    public Session(String session_id, Service service) {
        super(service.getConnection(), null,
                Static.Service.SECRETS, Static.ObjectPaths.session(session_id), Static.Interfaces.SESSION);
        this.service = service;
    }

    @Override
    public void close() {
        send("Close");
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

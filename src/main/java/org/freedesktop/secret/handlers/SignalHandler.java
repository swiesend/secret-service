package org.freedesktop.secret.handlers;

import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.interfaces.DBusSigHandler;
import org.freedesktop.dbus.messages.DBusSignal;
import org.freedesktop.secret.interfaces.Collection;
import org.freedesktop.secret.interfaces.Prompt;
import org.freedesktop.secret.interfaces.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class SignalHandler implements DBusSigHandler {

    private Logger log = LoggerFactory.getLogger(getClass());
    private List<Class> signals = null;
    private DBusConnection connection = null;
    private DBusSignal[] handled = new DBusSignal[100];
    private int count = 0;

    public SignalHandler(DBusConnection connection, List<Class> signals) {
        this.connection = connection;
        this.signals = signals;

        if (signals != null) {
            try {
                for (Class sc : signals) {
                    connection.addSigHandler(sc, this);
                }
            } catch (DBusException e) {
                log.error(e.toString(), e.getCause());
            }

            Runtime.getRuntime().addShutdownHook(new Thread(() -> disconnect()));
        }
    }

    public void disconnect() {
        try {
            for (Class sc : signals) {
                connection.removeSigHandler(sc, this);
            }
        } catch (DBusException e) {
            log.error(e.toString(), e.getCause());
        }
    }

    @Override
    public void handle(DBusSignal s) {

        Collections.rotate(Arrays.asList(handled), 1);
        handled[0] = s;
        count += 1;

        if (s instanceof Collection.ItemCreated) {
            Collection.ItemCreated ic = (Collection.ItemCreated) s;
            log.info("Collection.ItemCreated: " + ic.item);
        } else if (s instanceof Collection.ItemChanged) {
            Collection.ItemChanged ic = (Collection.ItemChanged) s;
            log.info("Collection.ItemChanged: " + ic.item);
        } else if (s instanceof Collection.ItemDeleted) {
            Collection.ItemDeleted ic = (Collection.ItemDeleted) s;
            log.info("Collection.ItemDeleted: " + ic.item);
        } else if (s instanceof Prompt.Completed) {
            Prompt.Completed c = (Prompt.Completed) s;
            log.info("Prompt.Completed: dismissed: " + c.dismissed + ", result: " + c.result);
        } else if (s instanceof Service.CollectionCreated) {
            Service.CollectionCreated cc = (Service.CollectionCreated) s;
            log.info("Service.CollectionCreated: " + cc.collection);
        } else if (s instanceof Service.CollectionChanged) {
            Service.CollectionChanged cc = (Service.CollectionChanged) s;
            log.info("Service.CollectionChanged: " + cc.collection);
        } else if (s instanceof Service.CollectionDeleted) {
            Service.CollectionDeleted cc = (Service.CollectionDeleted) s;
            log.info("Service.CollectionDeleted: " + cc.collection);
        } else {
            log.warn("handled unknown signal: " + s.getClass().toString() + " {" + s.toString() + "}");
        }
    }

    public DBusSignal[] getHandled() {
        return handled;
    }

    public int getCount() {
        return count;
    }

    public DBusSignal getLastHandledSignal() {
        return handled[0];
    }

}

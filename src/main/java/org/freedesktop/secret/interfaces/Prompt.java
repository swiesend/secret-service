package org.freedesktop.secret.interfaces;

import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.annotations.DBusInterfaceName;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.interfaces.DBusInterface;
import org.freedesktop.dbus.messages.DBusSignal;
import org.freedesktop.dbus.types.Variant;
import org.freedesktop.secret.Static;
import org.freedesktop.secret.errors.NoSuchObject;
import org.freedesktop.secret.handlers.Messaging;

import java.util.List;

@DBusInterfaceName(Static.Interfaces.PROMPT)
public abstract class Prompt extends Messaging implements DBusInterface {

    public Prompt(DBusConnection connection, List<Class<? extends DBusSignal>> signals,
                  String serviceName, String objectPath, String interfaceName) {
        super(connection, signals, serviceName, objectPath, interfaceName);
    }

    public static class Completed extends DBusSignal {
        public final boolean dismissed;
        public final Variant result;

        /**
         * The prompt and operation completed.
         * 
         * @param path          The path to the object this is emitted from.
         * @param dismissed     Whether the prompt and operation were dismissed or not.
         * @param result        The possibly empty, operation specific, result.
         * 
         * @throws DBusException    Could not communicate properly with the D-Bus.
         */
        public Completed(String path, boolean dismissed, Variant result) throws DBusException {
            super(path, dismissed, result);
            this.dismissed = dismissed;
            this.result = result;
        }
    }

    /**
     * Perform the prompt.
     * 
     * @param window_id     Platform specific window handle to use for showing the prompt.
     * 
     * @see Completed
     */
    abstract public void prompt(String window_id) throws DBusException;

    /**
     * Perform the prompt.
     * 
     * @param prompt        Objectpath of the prompt.
     * @throws NoSuchObject No such item or collection exists.
     * 
     * @see Completed
     */
    abstract public void prompt(ObjectPath prompt) throws NoSuchObject, DBusException;

    /**
     * Await the user interaction with the prompt.
     * 
     * A prompt can either be dismissed or be completed successfully.
     * 
     * @param prompt        Objectpath of the prompt.
     *
     * @return Completed or null if user input exceeds the default timeout of 300 seconds.
     * 
     * @throws InterruptedException A D-Bus signal failed.
     * @throws NoSuchObject         No such item or collection exists.
     * 
     * @see Completed
     */
    abstract public Completed await(ObjectPath prompt) throws InterruptedException, NoSuchObject, DBusException;

    /**
     * Dismiss the prompt.
     */
    abstract public void dismiss() throws DBusException;

}

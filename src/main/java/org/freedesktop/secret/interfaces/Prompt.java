package org.freedesktop.secret.interfaces;

import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.annotations.DBusInterfaceName;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.interfaces.DBusInterface;
import org.freedesktop.dbus.messages.DBusSignal;
import org.freedesktop.dbus.types.Variant;
import org.freedesktop.secret.Static;
import org.freedesktop.secret.errors.NoSuchObject;

@DBusInterfaceName(Static.Interfaces.PROMPT)
public interface Prompt extends DBusInterface {

    class Completed extends DBusSignal {
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
    boolean prompt(String window_id);

    /**
     * Perform the prompt.
     * 
     * @param prompt        Objectpath of the prompt.
     * 
     * @see Completed
     */
    boolean prompt(ObjectPath prompt);

    /**
     * Dismiss the prompt.
     */
    boolean dismiss();

}

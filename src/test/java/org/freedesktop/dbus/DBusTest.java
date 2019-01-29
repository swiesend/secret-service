package org.freedesktop.dbus;

import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.messages.Message;
import org.freedesktop.dbus.messages.MethodCall;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class DBusTest {

    private Logger log = LoggerFactory.getLogger(getClass());
    private DBusConnection connection = null;

    @Test
    @Disabled
    public void openSession() throws DBusException, InterruptedException {
        log.info("start");

        connection = DBusConnection.getConnection(DBusConnection.DBusBusType.SESSION);
        assertNotNull(connection);
        log.info(Arrays.toString(connection.getNames()));

        // send second "Hello" message
        Message m = new MethodCall(
                // service
                "org.freedesktop.DBus",
                // object path
                "/org/freedesktop/DBus",
                // interface
                "org.freedesktop.DBus",
                // method
                "Hello",
                // flags
                (byte) 0,
                // method signature
                null,
                // method arguments
                "");

        connection.sendMessage(m);
        Thread.sleep(50L);
        Message r = ((MethodCall) m).getReply(100L);
        log.info(r.toString());

        connection.disconnect();
        Thread.sleep(100L);

        log.info("stop");
    }

}


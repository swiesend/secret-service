package de.freedesktop.dbus;

import org.freedesktop.dbus.bin.CreateInterface;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.messages.Message;
import org.freedesktop.dbus.messages.MethodCall;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Disabled
public class GenerateInterfaces {

    private Logger log = LoggerFactory.getLogger(getClass());
    private DBusConnection connection = null;

    @BeforeEach
    public void beforeEach() throws Exception {
        connection = DBusConnection.getConnection(DBusConnection.DBusBusType.SESSION);
    }

    @AfterEach
    public void afterEach() throws Exception {
        connection.disconnect();
    }

    @Test
    @Disabled
    public void introspectInterface() {
        try {
            Message m = new MethodCall(
                    "org.freedesktop.secrets",
                    "/org/freedesktop/secrets",
                    "org.freedesktop.DBus.Introspectable", "Introspect", (byte) 0, null);
            connection.sendMessage(m);
            Message r = ((MethodCall) m).getReply(100L);
            log.info(r.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    @Disabled
    public void generateInterface() {
        try {
            String input = getClass().getResource(
                    "/org.freedesktop.DBus.Properties.xml").getFile();
            log.info(input);
            String[] args = {input};
            CreateInterface.main(args);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

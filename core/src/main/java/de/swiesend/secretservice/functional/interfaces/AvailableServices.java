package de.swiesend.secretservice.functional.interfaces;

import de.swiesend.secretservice.Static;
import de.swiesend.secretservice.functional.System;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.interfaces.DBus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class AvailableServices {

    private static final Logger log = LoggerFactory.getLogger(AvailableServices.class);

    public EnumSet<Activatable> services = EnumSet.noneOf(Activatable.class);

    public AvailableServices(SystemInterface system) {
        DBusConnection connection = system.getConnection();
        if (connection.isConnected()) {
            try {
                DBus bus = connection.getRemoteObject(
                        Static.DBus.Service.DBUS,
                        Static.DBus.ObjectPaths.DBUS,
                        DBus.class);

                // Check both running services and activatable services.
                // A service is available if it appears in either list.
                Set<String> available = new HashSet<>();
                available.addAll(Arrays.asList(bus.ListNames()));
                available.addAll(Arrays.asList(bus.ListActivatableNames()));

                // Required: org.freedesktop.DBus
                if (!available.contains(Static.DBus.Service.DBUS)) {
                    log.error("Missing required D-Bus service: " + Static.DBus.Service.DBUS);
                } else {
                    services.add(Activatable.DBUS);
                }

                // Required: org.freedesktop.secrets
                if (!available.contains(Static.Service.SECRETS)) {
                    log.error("Missing required D-Bus service: " + Static.Service.SECRETS);
                } else {
                    services.add(Activatable.SECRETS);
                }

                // Optional: org.gnome.keyring
                if (!available.contains(de.swiesend.secretservice.gnome.keyring.Static.Service.KEYRING)) {
                    log.warn("Proceeding without optional D-Bus service: " + de.swiesend.secretservice.gnome.keyring.Static.Service.KEYRING);
                } else {
                    services.add(Activatable.GNOME_KEYRING);
                }
            } catch (DBusException | ExceptionInInitializerError e) {
                log.warn("The secret service is not available. You may want to install the `gnome-keyring` package. Is the `gnome-keyring-daemon` running?", e);
            }
        }
    }


}

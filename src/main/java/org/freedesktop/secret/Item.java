package org.freedesktop.secret;

import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.types.UInt64;
import org.freedesktop.dbus.types.Variant;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class Item extends org.freedesktop.secret.interfaces.Item {

    private String id;

    public Item(String collectionID, String itemID, Service service) {
        super(service.getConnection(), null,
                Static.Service.SECRETS,
                Static.ObjectPaths.item(collectionID, itemID),
                Static.Interfaces.ITEM);
        this.id = itemID;
    }

    public Item(ObjectPath item, Service service) {
        super(service.getConnection(), null,
                Static.Service.SECRETS,
                item.getPath(),
                Static.Interfaces.ITEM);
        List<String> list = Arrays.asList(objectPath.split("/"));
        String itemID = list.get(list.size() - 1);
        this.id = itemID;
    }

    @Override
    public ObjectPath delete() throws DBusException {
        Object[] response = send("Delete", "");
        ObjectPath prompt = (ObjectPath) response[0];
        return prompt;
    }

    @Override
    public Secret getSecret(ObjectPath session) throws DBusException {
        Object[] response = send("GetSecret", "o", session);
        Object[] inner = (Object[]) response[0];

        ObjectPath session_path = (ObjectPath) inner[0];
        byte[] parameters = Static.Convert.toByteArray((ArrayList<Byte>) inner[1]);
        byte[] value = Static.Convert.toByteArray((ArrayList<Byte>) inner[2]);
        String contentType = (String) inner[3];

        Secret secret;
        if (contentType.equals(Secret.TEXT_PLAIN) ||
                contentType.equals(Secret.TEXT_PLAIN_CHARSET_UTF_8)) {
            // replace the content-type "text/plain" with default "text/plain; charset=utf8"
            secret = new Secret(session_path, parameters, value);
        } else {
            // use given non default content-type
            secret = new Secret(session_path, parameters, value, contentType);
        }

        return secret;
    }

    @Override
    public void setSecret(Secret secret) throws DBusException {
        send("SetSecret", "(oayays)", secret);
    }

    @Override
    public boolean isLocked() throws DBusException {
        Variant response = getProperty("Locked");
        return (boolean) response.getValue();
    }

    @Override
    public Map<String, String> getAttributes() throws DBusException {
        Variant response = getProperty("Attributes");
        return (Map<String, String>) response.getValue();
    }

    @Override
    public void setAttributes(Map<String, String> attributes) throws DBusException {
        setProperty("Attributes", new Variant(attributes, "a{ss}"));
    }

    @Override
    public String getLabel() throws DBusException {
        Variant response = getProperty("Label");
        return (String) response.getValue();
    }

    @Override
    public void setLabel(String label) throws DBusException {
        setProperty("Label", new Variant(label));
    }

    @Override
    public String getType() throws DBusException {
        Variant response = getProperty("Type");
        return (String) response.getValue();
    }

    @Override
    public UInt64 created() throws DBusException {
        Variant response = getProperty("Created");
        return (UInt64) response.getValue();
    }

    @Override
    public UInt64 modified() throws DBusException {
        Variant response = getProperty("Modified");
        return (UInt64) response.getValue();
    }

    @Override
    public boolean isRemote() {
        return false;
    }

    @Override
    public String getObjectPath() {
        return super.getObjectPath();
    }

    public String getId() {
        return id;
    }

}

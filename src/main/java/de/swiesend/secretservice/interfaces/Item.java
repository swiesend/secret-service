package de.swiesend.secretservice.interfaces;

import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.annotations.DBusInterfaceName;
import org.freedesktop.dbus.interfaces.DBusInterface;
import org.freedesktop.dbus.types.UInt64;
import de.swiesend.secretservice.Secret;
import de.swiesend.secretservice.Static;

import java.util.Map;
import java.util.Optional;

@DBusInterfaceName(Static.Interfaces.ITEM)
public interface Item extends DBusInterface {

    /**
     * The key of of the D-Bus properties for the label of an item.
     */
    String LABEL = "org.freedesktop.Secret.Item.Label";

    /**
     * The key of the D-Bus properties for the attributes of an item.
     */
    String ATTRIBUTES = "org.freedesktop.Secret.Item.Attributes";

    /**
     * Delete this item.
     *
     * @return Prompt   &mdash; A prompt objectpath, or the special value '/' if no prompt is necessary.
     */
    Optional<ObjectPath> delete();

    /**
     * Retrieve the secret for this item.
     *
     * @param session The session to use to encode the secret.
     * @return secret   &mdash; The secret retrieved.
     */
    Optional<Secret> getSecret(ObjectPath session);

    /**
     * Set the secret for this item.
     *
     * @param secret The secret to set, encoded for the included session.
     * @return
     */
    boolean setSecret(Secret secret);

    /**
     * @return Whether the item is locked and requires authentication, or not.
     */
    boolean isLocked();

    /**
     * The lookup attributes for this item.
     *
     * <b>Attributes</b> is a D-Bus Property.
     *
     * <p>It is managed by using the <code>org.freedesktop.DBus.Properties</code> interface.</p>
     *
     * @return The attributes of the item.
     */
    Optional<Map<String, String>> getAttributes();


    /**
     * The lookup attributes for this item.
     *
     * <b>Attributes</b> is a D-Bus Property.
     *
     * <p>It is managed by using the <code>org.freedesktop.DBus.Properties</code> interface.</p>
     *
     * @param attributes The attributes of the item.
     * @return
     */
    boolean setAttributes(Map<String, String> attributes);

    /**
     * <b>Label</b> is a D-Bus Property.
     *
     * <p>It is managed by using the <code>org.freedesktop.DBus.Properties</code> interface.</p>
     *
     * @return The displayable label of this collection.
     *
     * <p>
     * <b>Note:</b>
     * The displayable <code>label</code> can differ from the actual <code>name</code> of a collection.
     * </p>
     */
    Optional<String> getLabel();


    /**
     * <b>Label</b> is a D-Bus Property.
     *
     * <p>It is managed by using the <code>org.freedesktop.DBus.Properties</code> interface.</p>
     *
     * @param label The displayable label of this collection.
     *
     *              <p>
     *              <b>Note:</b>
     *              The displayable <code>label</code> can differ from the actual <code>name</code> of a collection.
     *              </p>
     * @return
     */
    boolean setLabel(String label);

    /**
     * @return The "xdg:schema" of the item attributes.
     */
    Optional<String> getType();

    /**
     * @return The unix time when the item was created.
     */
    Optional<UInt64> created();

    /**
     * @return The unix time when the item was last modified.
     */
    Optional<UInt64> modified();

}

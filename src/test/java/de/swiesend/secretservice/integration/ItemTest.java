package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.*;
import de.swiesend.secretservice.integration.test.Context;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.types.UInt64;
import org.junit.jupiter.api.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import static de.swiesend.secretservice.integration.test.Context.label;
import static org.junit.jupiter.api.Assertions.*;
public class ItemTest {
    private Logger log = LoggerFactory.getLogger(getClass());
    private Context context;
    @BeforeEach
    public void beforeEach(TestInfo info) {
        log.info(info.getDisplayName());
        context = new Context(log);
        context.ensureItem();
    }
    @AfterEach
    public void afterEach() {
        context.after();
    @Test
    @DisplayName("delete item")
    public void delete() {
        List<DBusPath> items = context.collection.getItems().get();
        assertEquals(1, items.size());
        DBusPath prompt = context.item.delete().get();
        // expect: no prompt
        assertEquals("/", prompt.getPath());
        items = context.collection.getItems().get();
        assertEquals(0, items.size());
    public void getSecret() {
        Secret secret = context.item.getSecret(context.session.getPath()).get();
        log.info(label("secret", secret.toString()));
        assertTrue(secret.getSession().getPath().startsWith("/org/freedesktop/secrets/session/s"));
        assertTrue(secret.getContentType().startsWith("text/plain"));
        String parameters = new String(secret.getSecretParameters(), StandardCharsets.UTF_8);
        log.info(label("parameters", parameters));
        if (context.encrypted == false) assertEquals("", parameters);
        String value;
        if (context.encrypted == false) {
            value = new String(secret.getSecretValue(), StandardCharsets.UTF_8);
        } else {
            value = new String(context.encryption.decrypt(secret).get());
        }
        log.info(label("value", value));
        assertEquals("super secret", value);
    @Disabled
    public void getForeignSecret() {
        //
        // NOTE: This is considered by NIST as a security vulnerability, but apparently it is not easy to solve with the
        //       current design of the gnome-keyring library and gnome-seahorse application.
        //  see: https://nvd.nist.gov/vuln/detail/CVE-2018-19358
        DBusPath alias = new DBusPath(Static.ObjectPaths.DEFAULT_COLLECTION);
        Collection login = new Collection(alias, context.service.getConnection());
        List<DBusPath> items = login.getItems().get();
        Item item = new Item(items.get(0), context.service);
        Secret secret = item.getSecret(context.session.getPath()).get();
        log.info("'" + new String(secret.getSecretValue()) + "' [" + new String(secret.getSecretParameters()) + "]");
    public void setSecret() {
        Secret secret = context.encryption.encrypt("new secret").get();
        assertTrue(context.item.setSecret(secret));
        Secret result = context.item.getSecret(context.session.getPath()).get();
        log.info(label("secret", result.toString()));
        assertEquals("new secret", new String(context.encryption.decrypt(result).orElse(null)));
    public void isLocked() {
        boolean locked = context.item.isLocked();
        log.info(String.valueOf(locked));
        assertFalse(locked);
    public void getAttributes() {
        Map<String, String> attributes = context.item.getAttributes().get();
        log.info(attributes.toString());
        assertTrue(attributes.size() > 0);
        assertEquals("Value1", attributes.get("Attribute1"));
        assertEquals("Value2", attributes.get("Attribute2"));
        assertTrue(attributes.containsKey("TransportEncryption"));
        if (attributes.containsKey("xdg:schema")) {
            assertEquals("org.freedesktop.Secret.Generic", attributes.get("xdg:schema"));
    public void setAttributes() {
        log.info(context.item.getId());
        assertTrue(attributes.size() == 3 || attributes.size() == 4);
        attributes = new HashMap();
        attributes.put("Attribute1", "Value1");
        attributes.put("Attribute2", "Replaced");
        attributes.put("Attribute3", "Added");
        context.item.setAttributes(attributes);
        attributes = context.item.getAttributes().get();
        assertEquals("Replaced", attributes.get("Attribute2"));
        assertEquals("Added", attributes.get("Attribute3"));
        assertFalse(attributes.containsKey("TransportEncryption"));
        Pair<List<DBusPath>, List<DBusPath>> result = context.service.searchItems(attributes).get();
        log.info(result.toString());
        assertEquals(1, result.a.size());
    /**
     * The displayable label for this item.
     */
    public void getLabel() {
        String label = context.item.getLabel().get();
        log.info(label("label", label));
        assertEquals("TestItem", label);
    public void setLabel() {
        boolean result = context.item.setLabel("RelabeledItem");
        assertTrue(result);
        assertEquals("RelabeledItem", label);
    public void getType() {
        String type = context.item.getType().get();
        log.info(type);
        if (!type.isEmpty()) {
            assertEquals("org.freedesktop.Secret.Generic", type);
    @DisplayName("created at unixtime")
    public void created() {
        UInt64 created = context.item.created().get();
        log.info(String.valueOf(created));
        assertTrue(created.longValue() > 0L);
    @DisplayName("modified at unixtime")
    public void modified() {
        UInt64 modified = context.item.created().get();
        log.info(String.valueOf(modified));
        assertTrue(modified.longValue() >= 0L);
    public void isRemote() {
        assertFalse(context.item.isRemote());
    public void getObjectPath() {
        String path = context.item.getObjectPath();
        assertTrue(path.startsWith(Static.ObjectPaths.collection("test") + "/"));
}

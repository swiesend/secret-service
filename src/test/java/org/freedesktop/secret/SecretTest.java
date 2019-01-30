package org.freedesktop.secret;

import org.freedesktop.dbus.ObjectPath;
import org.junit.jupiter.api.Test;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class SecretTest {

    private static ObjectPath session = new ObjectPath("", Static.ObjectPaths.session("1"));
    private static final String parameters = "";
    private static final String value = "secret";

    @Test
    public void getSession() {
        Secret secret = new Secret(session, parameters.getBytes(), value.getBytes());
        assertEquals("/org/freedesktop/secrets/session/1", secret.getSession().getPath());
    }

    @Test
    public void getSecretValue() {
        Secret secret = new Secret(session, parameters.getBytes(), value.getBytes());
        assertArrayEquals("secret".getBytes(), secret.getSecretValue());
    }

    @Test
    public void getSecretParameters() {
        Secret secret = new Secret(session, "initialization vector".getBytes(), value.getBytes());
        assertArrayEquals("initialization vector".getBytes(), secret.getSecretParameters());
    }

    @Test
    public void createContentType() {
        String contentType;
        Secret secret;

        assertEquals(Charset.forName("utf8"), StandardCharsets.UTF_8);

        secret = new Secret(session, parameters.getBytes(), value.getBytes(), "text/plain;charset=utf-8");
        assertEquals("text/plain; charset=utf-8", secret.getContentType());

        secret = new Secret(session, parameters.getBytes(), value.getBytes(), "text/plain;\tcharset=utf-8");
        assertEquals("text/plain; charset=utf-8", secret.getContentType());

        secret = new Secret(session, parameters.getBytes(), value.getBytes(), "text/plain;\t; ;;; charset=utf-8  ; ,,,");
        assertEquals("text/plain; charset=utf-8", secret.getContentType());

        contentType = Secret.createContentType(StandardCharsets.UTF_8);
        assertEquals("text/plain; charset=utf-8", contentType);
        secret = new Secret(session, parameters.getBytes(), value.getBytes(), contentType);
        assertEquals("text/plain; charset=utf-8", secret.getContentType());

        contentType = Secret.createContentType(StandardCharsets.UTF_16);
        assertEquals("text/plain; charset=utf-16", contentType);
        secret = new Secret(session, parameters.getBytes(), value.getBytes(), contentType);
        assertEquals("text/plain; charset=utf-16", secret.getContentType());

        contentType = Secret.createContentType(StandardCharsets.US_ASCII);
        assertEquals("text/plain; charset=us-ascii", contentType);
        secret = new Secret(session, parameters.getBytes(), value.getBytes(), contentType);
        assertEquals("text/plain; charset=us-ascii", secret.getContentType());

        secret = new Secret(session, parameters.getBytes(), value.getBytes(), "application/octet-stream");
        assertEquals("application/octet-stream", secret.getContentType());

        contentType = Secret.createContentType("text/plain", StandardCharsets.UTF_8);
        assertEquals("text/plain; charset=utf-8", contentType);
        secret = new Secret(session, parameters.getBytes(), value.getBytes(), contentType);
        assertEquals("text/plain; charset=utf-8", secret.getContentType());

        contentType = Secret.createContentType("text/plain", StandardCharsets.UTF_16);
        assertEquals("text/plain; charset=utf-16", contentType);
        secret = new Secret(session, parameters.getBytes(), value.getBytes(), contentType);
        assertEquals("text/plain; charset=utf-16", secret.getContentType());

        contentType = Secret.createContentType("text/plain", StandardCharsets.US_ASCII);
        assertEquals("text/plain; charset=us-ascii", contentType);
        secret = new Secret(session, parameters.getBytes(), value.getBytes(), contentType);
        assertEquals("text/plain; charset=us-ascii", secret.getContentType());
    }

    @Test
    public void getContentType() {
        Secret secret = new Secret(session, parameters.getBytes(), value.getBytes());
        assertEquals("text/plain; charset=utf-8", secret.getContentType());

        secret = new Secret(session, parameters.getBytes(), value.getBytes(), (String) null);
        assertEquals("text/plain; charset=utf-8", secret.getContentType());

        secret = new Secret(session, parameters.getBytes(), value.getBytes(), "");
        assertEquals("text/plain; charset=utf-8", secret.getContentType());

        secret = new Secret(session, parameters.getBytes(), value.getBytes(), StandardCharsets.UTF_16);
        assertEquals("text/plain; charset=utf-16", secret.getContentType());

        secret = new Secret(session, parameters.getBytes(), value.getBytes(), "application/octet-stream");
        assertEquals("application/octet-stream", secret.getContentType());
    }

    @Test
    public void getMimeType() {
        Secret secret;

        secret = new Secret(session, parameters.getBytes(), value.getBytes());
        assertEquals("text/plain", secret.getMimeType());

        secret = new Secret(session, parameters.getBytes(), value.getBytes(), "text/plain; charset=utf-8");
        assertEquals("text/plain", secret.getMimeType());

        secret = new Secret(session, parameters.getBytes(), value.getBytes(), "application/octet-stream");
        assertEquals("application/octet-stream", secret.getMimeType());
    }

    @Test
    public void getCharset() {
        Secret secret;

        secret = new Secret(session, parameters.getBytes(), value.getBytes());
        assertEquals(StandardCharsets.UTF_8, secret.getCharset());

        secret = new Secret(session, parameters.getBytes(), value.getBytes(), StandardCharsets.UTF_16);
        assertEquals(StandardCharsets.UTF_16, secret.getCharset());

        secret = new Secret(session, parameters.getBytes(), value.getBytes(), StandardCharsets.US_ASCII);
        assertEquals(StandardCharsets.US_ASCII, secret.getCharset());
    }

    @Test
    void toBytes() {
        String plaintext = "sécrèt";
        byte[] encoded = Secret.toBytes(plaintext);
        assertEquals(plaintext, new String(encoded));

        char[] decoded = Secret.toChars(plaintext.getBytes());
        encoded = Secret.toBytes(decoded);
        assertEquals(plaintext, new String(encoded));
    }

    @Test
    void toChars() {
        String plaintext = "sécrèt";
        char[] decoded = Secret.toChars(plaintext.getBytes());
        assertEquals(plaintext, new String(decoded));
    }

    @Test
    void clear() {
        Secret secret;
        secret = new Secret(session, parameters.getBytes(), value.getBytes());
        secret.clear();
        for(byte b: secret.getSecretValue()) {
            assertEquals((byte) 0 ,b);
        }
    }
}
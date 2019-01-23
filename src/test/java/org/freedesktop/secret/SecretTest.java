package org.freedesktop.secret;

import org.freedesktop.dbus.ObjectPath;
import org.junit.jupiter.api.Test;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class SecretTest {

    private static ObjectPath session = new ObjectPath("", Static.ObjectPaths.session("1"));
    private static byte[] parameters = "".getBytes();
    private static byte[] value = "secret".getBytes();

    @Test
    void getSession() {
        Secret secret = new Secret(session, parameters, value);
        assertEquals("/org/freedesktop/secrets/session/1", secret.getSession().getPath());
    }

    @Test
    void getSecretValue() {
        Secret secret = new Secret(session, parameters, value);
        assertArrayEquals("secret".getBytes(), secret.getSecretValue());
    }

    @Test
    void getSecretParameters() {
        Secret secret = new Secret(session, "initialization vector".getBytes(), value);
        assertArrayEquals("initialization vector".getBytes(), secret.getSecretParameters());
    }

    @Test
    void createContentType() {
        String contentType;
        Secret secret;

        assertEquals(Charset.forName("utf8"), StandardCharsets.UTF_8);

        secret = new Secret(session, parameters, value, "text/plain;charset=utf-8");
        assertEquals("text/plain; charset=utf-8", secret.getContentType());

        secret = new Secret(session, parameters, value, "text/plain;\tcharset=utf-8");
        assertEquals("text/plain; charset=utf-8", secret.getContentType());

        secret = new Secret(session, parameters, value, "text/plain;\t; ;;; charset=utf-8  ; ,,,");
        assertEquals("text/plain; charset=utf-8", secret.getContentType());

        contentType = Secret.createContentType(StandardCharsets.UTF_8);
        assertEquals("text/plain; charset=utf-8", contentType);
        secret = new Secret(session, parameters, value, contentType);
        assertEquals("text/plain; charset=utf-8", secret.getContentType());

        contentType = Secret.createContentType(StandardCharsets.UTF_16);
        assertEquals("text/plain; charset=utf-16", contentType);
        secret = new Secret(session, parameters, value, contentType);
        assertEquals("text/plain; charset=utf-16", secret.getContentType());

        contentType = Secret.createContentType(StandardCharsets.US_ASCII);
        assertEquals("text/plain; charset=us-ascii", contentType);
        secret = new Secret(session, parameters, value, contentType);
        assertEquals("text/plain; charset=us-ascii", secret.getContentType());

        secret = new Secret(session, parameters, value, "application/octet-stream");
        assertEquals("application/octet-stream", secret.getContentType());

        contentType = Secret.createContentType("text/plain", StandardCharsets.UTF_8);
        assertEquals("text/plain; charset=utf-8", contentType);
        secret = new Secret(session, parameters, value, contentType);
        assertEquals("text/plain; charset=utf-8", secret.getContentType());

        contentType = Secret.createContentType("text/plain", StandardCharsets.UTF_16);
        assertEquals("text/plain; charset=utf-16", contentType);
        secret = new Secret(session, parameters, value, contentType);
        assertEquals("text/plain; charset=utf-16", secret.getContentType());

        contentType = Secret.createContentType("text/plain", StandardCharsets.US_ASCII);
        assertEquals("text/plain; charset=us-ascii", contentType);
        secret = new Secret(session, parameters, value, contentType);
        assertEquals("text/plain; charset=us-ascii", secret.getContentType());
    }

    @Test
    void getContentType() {
        Secret secret = new Secret(session, parameters, value);
        assertEquals("text/plain; charset=utf-8", secret.getContentType());

        secret = new Secret(session, parameters, value, (String) null);
        assertEquals("text/plain; charset=utf-8", secret.getContentType());

        secret = new Secret(session, parameters, value, "");
        assertEquals("text/plain; charset=utf-8", secret.getContentType());

        secret = new Secret(session, parameters, value, StandardCharsets.UTF_16);
        assertEquals("text/plain; charset=utf-16", secret.getContentType());

        secret = new Secret(session, parameters, value, "application/octet-stream");
        assertEquals("application/octet-stream", secret.getContentType());
    }

    @Test
    void getMimeType() {
        Secret secret;

        secret = new Secret(session, parameters, value);
        assertEquals("text/plain", secret.getMimeType());

        secret = new Secret(session, parameters, value, "text/plain; charset=utf-8");
        assertEquals("text/plain", secret.getMimeType());

        secret = new Secret(session, parameters, value, "application/octet-stream");
        assertEquals("application/octet-stream", secret.getMimeType());
    }

    @Test
    void getCharset() {
        Secret secret;

        secret = new Secret(session, parameters, value);
        assertEquals(StandardCharsets.UTF_8, secret.getCharset());

        secret = new Secret(session, parameters, value, StandardCharsets.UTF_16);
        assertEquals(StandardCharsets.UTF_16, secret.getCharset());

        secret = new Secret(session, parameters, value, StandardCharsets.US_ASCII);
        assertEquals(StandardCharsets.US_ASCII, secret.getCharset());
    }
}
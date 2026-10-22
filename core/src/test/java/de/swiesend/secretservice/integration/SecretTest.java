package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.Secret;
import de.swiesend.secretservice.Static;
import org.freedesktop.dbus.DBusPath;
import org.junit.jupiter.api.Test;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class SecretTest {

    private static DBusPath session = new DBusPath(Static.ObjectPaths.session("1"));
    private static final String parameters = "";
    private static final String value = "secret";

    @Test
    public void getSession() {
        Secret secret = new Secret(session, parameters.getBytes(), value.getBytes());
        assertEquals("/org/freedesktop/secrets/session/1", secret.getSession().getPath());
    }

    @Test
    public void toBytesEncodesUtf8LikeTheJdk() {
        // Non-ASCII outgrew the JDK encoder's first buffer, which is where an unerased copy of the
        // secret used to be left; the bytes must still be exactly the UTF-8 encoding. An unpaired
        // surrogate becomes '?', as with Charset.encode.
        for (String s : new String[]{"", "secret", "sécrèt", "пароль", "日本語のパスワード", "😀🔑",
                "x\uD800y", "ü".repeat(1000)}) {
            byte[] expected = s.getBytes(StandardCharsets.UTF_8);
            assertArrayEquals(expected, Secret.toBytes((CharSequence) s), s);
            assertArrayEquals(expected, Secret.toBytes(s.toCharArray()), s);
        }
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

        // libsecret reads a password only under "text/plain", and oo7 0.6 refuses any other text type.
        contentType = Secret.createContentType(StandardCharsets.UTF_8);
        assertEquals("text/plain", contentType);
        secret = new Secret(session, parameters.getBytes(), value.getBytes(), contentType);
        assertEquals("text/plain", secret.getContentType());

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
    public void aCharsetIsNamedAlikeInEveryLocale() {
        // Lower-cased in a Turkish locale, the I of ISO-8859-1 and US-ASCII becomes a dotless i.
        Locale before = Locale.getDefault();
        Locale.setDefault(Locale.forLanguageTag("tr-TR"));
        try {
            assertEquals("text/plain; charset=iso-8859-1", Secret.createContentType(StandardCharsets.ISO_8859_1));
            assertEquals("text/plain; charset=us-ascii", Secret.createContentType("text/plain", StandardCharsets.US_ASCII));
        } finally {
            Locale.setDefault(before);
        }
    }

    @Test
    public void getContentType() {
        Secret secret = new Secret(session, parameters.getBytes(), value.getBytes());
        assertEquals("text/plain", secret.getContentType());

        secret = new Secret(session, parameters.getBytes(), value.getBytes(), (String) null);
        assertEquals("text/plain", secret.getContentType());

        secret = new Secret(session, parameters.getBytes(), value.getBytes(), "");
        assertEquals("text/plain", secret.getContentType());

        secret = new Secret(session, parameters.getBytes(), value.getBytes(), StandardCharsets.UTF_8);
        assertEquals("text/plain", secret.getContentType());

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

        // Although its content type, "text/plain", names no charset.
        secret = new Secret(session, parameters.getBytes(), value.getBytes(), StandardCharsets.UTF_8);
        assertEquals(StandardCharsets.UTF_8, secret.getCharset());

        secret = new Secret(session, parameters.getBytes(), value.getBytes(), StandardCharsets.UTF_16);
        assertEquals(StandardCharsets.UTF_16, secret.getCharset());

        secret = new Secret(session, parameters.getBytes(), value.getBytes(), StandardCharsets.US_ASCII);
        assertEquals(StandardCharsets.US_ASCII, secret.getCharset());
    }

    @Test
    public void aContentTypeWithAnUnknownOrIllegalCharsetHasNone() {
        // Another application's content type: the secret stays readable.
        for (String contentType : new String[]{"text/plain; charset=x-no-such-charset", "text/plain; charset=x@y"}) {
            Secret secret = new Secret(session, parameters.getBytes(), value.getBytes(), contentType);
            assertNull(secret.getCharset(), contentType);
            assertEquals("text/plain", secret.getMimeType(), contentType);
        }
    }

    @Test
    public void aCharsetNameIsReadInEveryLocale() {
        // Upper-cased in a Turkish locale, the i of iso-8859-1 becomes a dotted capital I.
        Locale before = Locale.getDefault();
        Locale.setDefault(Locale.forLanguageTag("tr-TR"));
        try {
            Secret secret = new Secret(session, parameters.getBytes(), value.getBytes(), "text/plain; charset=iso-8859-1");
            assertEquals(StandardCharsets.ISO_8859_1, secret.getCharset());
        } finally {
            Locale.setDefault(before);
        }
    }

    @Test
    public void toBytes() {
        String plaintext = "sécrèt";
        byte[] encoded = Secret.toBytes(plaintext);
        assertEquals(plaintext, new String(encoded));

        char[] decoded = Secret.toChars(plaintext.getBytes());
        encoded = Secret.toBytes(decoded);
        assertEquals(plaintext, new String(encoded));
    }

    @Test
    public void toChars() {
        String plaintext = "sécrèt";
        char[] decoded = Secret.toChars(plaintext.getBytes());
        assertEquals(plaintext, new String(decoded));
    }

    @Test
    public void toCharsDecodesLikeTheJdkInEveryCharset() {
        for (Charset charset : new Charset[]{StandardCharsets.UTF_8, StandardCharsets.ISO_8859_1,
                StandardCharsets.UTF_16, StandardCharsets.UTF_16LE, StandardCharsets.US_ASCII}) {
            for (String s : new String[]{"", "secret", "sécrèt", "пароль", "😀🔑", "ü".repeat(1000)}) {
                byte[] bytes = s.getBytes(charset);
                String expected = new String(bytes, charset);
                assertEquals(expected, new String(Secret.toChars(bytes.clone(), charset)), charset + ": " + s);
            }
        }
        assertEquals("sécrèt", new String(Secret.toChars("sécrèt".getBytes(StandardCharsets.UTF_8), null)),
                "no charset is UTF-8");
    }

    @Test
    public void clear() {
        Secret secret;
        secret = new Secret(session, parameters.getBytes(), value.getBytes());
        secret.clear();
        for(byte b: secret.getSecretValue()) {
            assertEquals((byte) 0 ,b);
        }
    }
}
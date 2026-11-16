package de.swiesend.secretservice;

import org.freedesktop.dbus.DBusPath;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code Secret.clear} erases what holds a secret and tells whether it did. It told so with an
 * {@code assert}, which a JVM skips unless it runs with {@code -ea}, and it threw for what it
 * could not erase: for no array at all, which two of {@code Secret}'s constructors take as a
 * value, and for a buffer without an array of its own.
 */
class SecretClearTest {

    private static final DBusPath SESSION = new DBusPath("/org/freedesktop/secrets/session/s1");

    private static byte[] secret() {
        return "sécret".getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void anArrayIsErased() {
        byte[] bytes = secret();

        assertTrue(Secret.clear(bytes));
        assertArrayEquals(new byte[bytes.length], bytes);
    }

    @Test
    void noArrayHoldsNothingToErase() {
        assertTrue(Secret.clear((byte[]) null));
        assertTrue(Secret.clear((ByteBuffer) null));
        assertTrue(Secret.clear((CharBuffer) null));
    }

    @Test
    void aSecretWithoutAValueCloses() {
        assertDoesNotThrow(() -> {
            try (Secret secret = new Secret(SESSION, null)) {
                assertTrue(secret.clear());
            }
        });
        assertDoesNotThrow(() -> new Secret(SESSION, null, null).close());
    }

    @Test
    void aSecretsValueIsErasedWhenItCloses() {
        byte[] value = secret();

        new Secret(SESSION, value).close();

        assertArrayEquals(new byte[value.length], value);
    }

    @Test
    void aBufferIsErasedUpToItsLimit() {
        ByteBuffer bytes = ByteBuffer.allocate(16).put(secret());
        bytes.flip();
        CharBuffer chars = CharBuffer.allocate(16).put("sécret");
        chars.flip();

        assertTrue(Secret.clear(bytes));
        assertTrue(Secret.clear(chars));

        for (int i = 0; i < bytes.limit(); i++) assertEquals(0, bytes.get(i));
        for (int i = 0; i < chars.limit(); i++) assertEquals(0, chars.get(i));
    }

    @Test
    void aBufferOutsideTheHeapIsErased() {
        ByteBuffer direct = ByteBuffer.allocateDirect(16).put(secret());
        direct.flip();

        assertTrue(Secret.clear(direct));

        for (int i = 0; i < direct.limit(); i++) assertEquals(0, direct.get(i));
    }

    @Test
    void aBufferThatCannotBeWrittenIsReportedAsNotErased() {
        byte[] bytes = secret();

        assertFalse(Secret.clear(ByteBuffer.wrap(bytes).asReadOnlyBuffer()));
        assertFalse(Secret.clear(CharBuffer.wrap("a String stays as it is")));
        assertArrayEquals(secret(), bytes);
    }
}

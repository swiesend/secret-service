package de.swiesend.secretservice;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The transport session key must be erasable, because {@code TransportEncryption.clear()} relies
 * on it. A {@code SecretKeySpec} is not: its {@code destroy()} throws, and its
 * {@code getEncoded()} hands out copies, so erasing a copy leaves the key in memory.
 */
class SessionKeyTest {

    /** The bytes the key holds; the only way to see that destroy() really erased them. */
    private static byte[] heldBytes(TransportEncryption.SessionKey key) throws Exception {
        Field field = TransportEncryption.SessionKey.class.getDeclaredField("key");
        field.setAccessible(true);
        return (byte[]) field.get(key);
    }

    private static byte[] sevens() {
        byte[] bytes = new byte[16];
        Arrays.fill(bytes, (byte) 7);
        return bytes;
    }

    @Test
    void holdsItsOwnCopyOfTheKeyBytes() {
        byte[] input = sevens();
        TransportEncryption.SessionKey key = new TransportEncryption.SessionKey(input);
        Arrays.fill(input, (byte) 0);   // what generateSessionKey does with its array

        assertEquals(7, key.getEncoded()[0], "erasing the caller's array must not erase the key");
        assertNotSame(key.getEncoded(), key.getEncoded(), "getEncoded hands out copies");
    }

    @Test
    void destroyErasesTheKeyBytesAndRefusesFurtherUse() throws Exception {
        TransportEncryption.SessionKey key = new TransportEncryption.SessionKey(sevens());

        key.destroy();

        assertTrue(key.isDestroyed());
        assertArrayEquals(new byte[16], heldBytes(key), "destroy must erase the bytes it holds");
        assertThrows(IllegalStateException.class, key::getEncoded);
    }
}

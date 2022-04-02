package org.freedesktop.secret;

import org.freedesktop.secret.Static.Utils;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

public class StaticTest {

    @Test
    public void testSecondOakleyGroup() {
        // @formatter:off
        String expectedPrime =
                "FFFFFFFF" + "FFFFFFFF" + "C90FDAA2" + "2168C234" + "C4C6628B" + "80DC1CD1" +
                "29024E08" + "8A67CC74" + "020BBEA6" + "3B139B22" + "514A0879" + "8E3404DD" +
                "EF9519B3" + "CD3A431B" + "302B0A6D" + "F25F1437" + "4FE1356D" + "6D51C245" +
                "E485B576" + "625E7EC6" + "F44C42E9" + "A637ED6B" + "0BFF5CB6" + "F406B7ED" +
                "EE386BFB" + "5A899FA5" + "AE9F2411" + "7C4B1FE6" + "49286651" + "ECE65381" +
                "FFFFFFFF" + "FFFFFFFF";
        String expectedGenerator = "2";
        // @formatter:on

        BigInteger prime = new BigInteger(1, Static.RFC_2409.SecondOakleyGroup.PRIME);
        BigInteger generator = new BigInteger(1, Static.RFC_2409.SecondOakleyGroup.GENERATOR);

        assertEquals(expectedPrime, prime.toString(16).toUpperCase());
        assertEquals(expectedGenerator, generator.toString(16).toUpperCase());
    }

    @Test
    public void isNullOrEmptyCharSeq() {
        CharSequence nullCharSeq = null;
        assertTrue(Utils.isNullOrEmpty(nullCharSeq));
        CharSequence emptyCharSeq = "";
        assertTrue(Utils.isNullOrEmpty(emptyCharSeq));
        CharSequence blankCharSeq = " ";
        assertTrue(Utils.isNullOrEmpty(blankCharSeq));
        CharSequence nonEmptyCharSeq = "not empty";
        assertFalse(Utils.isNullOrEmpty(nonEmptyCharSeq));
    }

    @Test
    public void isNullOrEmptyStr() {
        String nullStr = null;
        assertTrue(Utils.isNullOrEmpty(nullStr));
        String emptyStr = "";
        assertTrue(Utils.isNullOrEmpty(emptyStr));
        String blankStr = " ";
        assertTrue(Utils.isNullOrEmpty(blankStr));
        String nonEmptyStr = "not empty";
        assertFalse(Utils.isNullOrEmpty(nonEmptyStr));
    }

    @Test
    public void isNullOrEmptyArrayOfObjects() {
        assertTrue(Utils.isNullOrEmpty((Object[]) null));
        Object[] emptyArrayOfObj = new Object[0];
        assertTrue(Utils.isNullOrEmpty(emptyArrayOfObj));
        Object[] nonEmptyArrayOfObj = new Object[]{new Object()};
        assertFalse(Utils.isNullOrEmpty(nonEmptyArrayOfObj));
    }

}

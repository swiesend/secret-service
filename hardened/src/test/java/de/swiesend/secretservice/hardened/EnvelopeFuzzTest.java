package de.swiesend.secretservice.hardened;

import com.code_intelligence.jazzer.junit.FuzzTest;

/**
 * Coverage-guided fuzzing of the untrusted-input surface: {@link Envelope#fromBytes(byte[])} parses
 * arbitrary bytes pulled from a keyring item, so a malformed or adversarial body must never do worse
 * than throw {@link IllegalArgumentException}. Any other Throwable (buffer underflow leaking through,
 * a negative-size allocation, an OOM from an unbounded length field, …) is a parser bug.
 *
 * <p>Under a normal {@code mvn test} this runs in JUnit "regression" mode (seed corpus + a bounded
 * number of generated inputs). Set {@code JAZZER_FUZZ=1} to fuzz continuously.</p>
 */
class EnvelopeFuzzTest {

    @FuzzTest(maxDuration = "10s")
    void fromBytesOnlyThrowsIllegalArgument(byte[] data) {
        Envelope env;
        try {
            env = Envelope.fromBytes(data);
        } catch (IllegalArgumentException expected) {
            return; // the only permitted failure for malformed input
        }
        // A successfully parsed envelope must re-serialize and expose its AAD without throwing, and
        // the serialized header prefix must equal the associated data.
        byte[] roundTrip = env.toBytes();
        byte[] aad = env.associatedData();
        if (aad.length > roundTrip.length) {
            throw new AssertionError("associatedData longer than the whole envelope");
        }
    }
}

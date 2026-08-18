package de.swiesend.secretservice.hardened.tpm2;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Arrays;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Tpm2SealedBlobTest {

    private static byte[] pattern(int n, int fill) {
        byte[] a = new byte[n];
        Arrays.fill(a, (byte) fill);
        return a;
    }

    @Test
    void binaryRoundTripPreservesAllFields() {
        byte[] pub = pattern(120, 0x11);
        byte[] priv = pattern(80, 0x22);
        Tpm2SealedBlob blob = new Tpm2SealedBlob(Tpm2SealedBlob.PolicyKind.PASSWORD, pub, priv);
        Tpm2SealedBlob parsed = Tpm2SealedBlob.fromBytes(blob.toBytes());
        assertEquals(Tpm2SealedBlob.PolicyKind.PASSWORD, parsed.policyKind());
        assertArrayEquals(pub, parsed.outPublic());
        assertArrayEquals(priv, parsed.outPrivate());
    }

    @Test
    void rejectsBadMagic() {
        byte[] raw = new Tpm2SealedBlob(Tpm2SealedBlob.PolicyKind.PASSWORD,
                pattern(16, 1), pattern(16, 2)).toBytes();
        raw[0] = 'X';
        assertThrows(IllegalArgumentException.class, () -> Tpm2SealedBlob.fromBytes(raw));
    }

    @Test
    void rejectsUnknownPolicyKind() {
        byte[] raw = new Tpm2SealedBlob(Tpm2SealedBlob.PolicyKind.PASSWORD,
                pattern(16, 1), pattern(16, 2)).toBytes();
        // magic(8) + version(1) + policyKind(1) = offset 9 for policy byte
        raw[9] = (byte) 0x7f;
        assertThrows(IllegalArgumentException.class, () -> Tpm2SealedBlob.fromBytes(raw));
    }

    @Test
    void rejectsLegacyV1BlobWithReprovisionHint() {
        // A v1 blob (byte 8 == 0x01) sealed the pepper verbatim and is not binary-safe (F-9).
        // Reading it must fail with guidance to re-provision, not silently return a wrong pepper.
        byte[] raw = new Tpm2SealedBlob(Tpm2SealedBlob.PolicyKind.PASSWORD,
                pattern(16, 1), pattern(16, 2)).toBytes();
        raw[8] = 0x01; // downgrade the version byte to v1
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> Tpm2SealedBlob.fromBytes(raw));
        assertTrue(e.getMessage().contains("re-provision"),
                "v1 rejection must tell the operator to re-provision; was: " + e.getMessage());
    }

    @Test
    void rejectsEmptyParts() {
        assertThrows(IllegalArgumentException.class,
                () -> new Tpm2SealedBlob(Tpm2SealedBlob.PolicyKind.PASSWORD, new byte[0], new byte[4]));
        assertThrows(IllegalArgumentException.class,
                () -> new Tpm2SealedBlob(Tpm2SealedBlob.PolicyKind.PASSWORD, new byte[4], new byte[0]));
    }

    @Test
    void fileRoundTripSetsMode0600(@TempDir Path dir) throws IOException {
        Path target = dir.resolve("pepper.tpm2blob");
        byte[] pub = pattern(24, 0x33);
        byte[] priv = pattern(24, 0x44);
        new Tpm2SealedBlob(Tpm2SealedBlob.PolicyKind.PASSWORD, pub, priv).writeTo(target);

        PosixFileAttributeView view = Files.getFileAttributeView(target, PosixFileAttributeView.class);
        if (view != null) {
            Set<PosixFilePermission> perms = view.readAttributes().permissions();
            assertEquals(Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE), perms,
                    "sealed blob must be written mode 0600");
        }

        Tpm2SealedBlob parsed = Tpm2SealedBlob.readFrom(target);
        assertArrayEquals(pub, parsed.outPublic());
        assertArrayEquals(priv, parsed.outPrivate());
    }

    @Test
    void readFromRejectsOverPermissiveFile(@TempDir Path dir) throws IOException {
        Path target = dir.resolve("bad.tpm2blob");
        new Tpm2SealedBlob(Tpm2SealedBlob.PolicyKind.PASSWORD, pattern(16, 1), pattern(16, 2))
                .writeTo(target);
        PosixFileAttributeView view = Files.getFileAttributeView(target, PosixFileAttributeView.class);
        if (view == null) return; // non-POSIX fs: test n/a
        view.setPermissions(Set.of(
                PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.GROUP_READ));
        IOException e = assertThrows(IOException.class, () -> Tpm2SealedBlob.readFrom(target));
        assertTrue(e.getMessage().contains("over-permissive"));
    }
}

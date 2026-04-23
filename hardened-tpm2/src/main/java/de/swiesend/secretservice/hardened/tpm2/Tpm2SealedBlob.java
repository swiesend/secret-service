package de.swiesend.secretservice.hardened.tpm2;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Arrays;
import java.util.Set;

/**
 * On-disk container for a TPM-sealed pepper.
 *
 * <pre>
 * magic(8="TPM2BLOB") | version(1) | policyKind(1) |
 * pubLen(2)  | outPublic[pubLen]   |   // TPM2B_PUBLIC-serialised
 * privLen(2) | outPrivate[privLen] |   // TPM2B_PRIVATE-serialised
 * </pre>
 *
 * <p>The bytes here are the TPM-wrapped material only. No plaintext pepper is
 * ever written to this file; the pepper is recoverable only with (a) the TPM
 * that produced it and (b) the policy secret (password or PCR state).</p>
 *
 * <p>File permissions are enforced to {@code 0600} on write. Readers validate
 * mode {@code 0600} at load time and refuse over-permissive files.</p>
 */
public final class Tpm2SealedBlob {

    public enum PolicyKind {
        /** Unseal requires a caller-supplied password (HMAC-session with the TPM). */
        PASSWORD,
        /** Unseal requires matching PCR state at load time. Not yet shipped; reserved. */
        PCR
    }

    private static final byte[] MAGIC = {'T', 'P', 'M', '2', 'B', 'L', 'O', 'B'};
    private static final byte VERSION_1 = 0x01;

    private final PolicyKind policyKind;
    private final byte[] outPublic;
    private final byte[] outPrivate;

    public Tpm2SealedBlob(PolicyKind policyKind, byte[] outPublic, byte[] outPrivate) {
        this.policyKind = policyKind;
        this.outPublic = outPublic.clone();
        this.outPrivate = outPrivate.clone();
        if (outPublic.length == 0 || outPrivate.length == 0) {
            throw new IllegalArgumentException("public/private parts must be non-empty");
        }
        if (outPublic.length > 0xFFFF || outPrivate.length > 0xFFFF) {
            throw new IllegalArgumentException("public/private part exceeds 65535 bytes");
        }
    }

    public PolicyKind policyKind() { return policyKind; }
    public byte[] outPublic()      { return outPublic.clone(); }
    public byte[] outPrivate()     { return outPrivate.clone(); }

    public byte[] toBytes() {
        int total = MAGIC.length + 2 + 2 + outPublic.length + 2 + outPrivate.length;
        ByteBuffer buf = ByteBuffer.allocate(total).order(ByteOrder.BIG_ENDIAN);
        buf.put(MAGIC);
        buf.put(VERSION_1);
        buf.put((byte) policyKind.ordinal());
        buf.putShort((short) outPublic.length);
        buf.put(outPublic);
        buf.putShort((short) outPrivate.length);
        buf.put(outPrivate);
        return buf.array();
    }

    public static Tpm2SealedBlob fromBytes(byte[] input) {
        if (input == null || input.length < MAGIC.length + 2 + 2 + 2) {
            throw new IllegalArgumentException("sealed-blob file too short");
        }
        ByteBuffer buf = ByteBuffer.wrap(input).order(ByteOrder.BIG_ENDIAN);
        byte[] magic = new byte[MAGIC.length];
        buf.get(magic);
        if (!Arrays.equals(magic, MAGIC)) throw new IllegalArgumentException("bad magic");
        byte version = buf.get();
        if (version != VERSION_1) {
            throw new IllegalArgumentException("unsupported sealed-blob version: " + version);
        }
        int kindOrdinal = Byte.toUnsignedInt(buf.get());
        PolicyKind[] kinds = PolicyKind.values();
        if (kindOrdinal >= kinds.length) {
            throw new IllegalArgumentException("unknown policy kind: " + kindOrdinal);
        }
        PolicyKind policyKind = kinds[kindOrdinal];
        int pubLen = Short.toUnsignedInt(buf.getShort());
        if (pubLen <= 0 || pubLen > buf.remaining() - 2) {
            throw new IllegalArgumentException("bad public-part length: " + pubLen);
        }
        byte[] pub = new byte[pubLen];
        buf.get(pub);
        int privLen = Short.toUnsignedInt(buf.getShort());
        if (privLen <= 0 || privLen > buf.remaining()) {
            throw new IllegalArgumentException("bad private-part length: " + privLen);
        }
        byte[] priv = new byte[privLen];
        buf.get(priv);
        return new Tpm2SealedBlob(policyKind, pub, priv);
    }

    /** Write the blob atomically, mode 0600. */
    public void writeTo(Path target) throws IOException {
        Path tmp = target.resolveSibling(target.getFileName() + ".tmp");
        Files.write(tmp, toBytes(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE);
        try {
            PosixFileAttributeView view = Files.getFileAttributeView(tmp, PosixFileAttributeView.class);
            if (view != null) {
                view.setPermissions(Set.of(
                        PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
            }
            Files.move(tmp, target,
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            Files.deleteIfExists(tmp);
            throw e;
        }
    }

    /** Load a blob, failing closed if the file is readable by group/others. */
    public static Tpm2SealedBlob readFrom(Path source) throws IOException {
        validateOwnerReadOnly(source);
        byte[] raw = Files.readAllBytes(source);
        try {
            return fromBytes(raw);
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }

    private static void validateOwnerReadOnly(Path path) throws IOException {
        PosixFileAttributeView view = Files.getFileAttributeView(path, PosixFileAttributeView.class);
        if (view == null) return; // non-POSIX filesystem: can't enforce
        Set<PosixFilePermission> perms = view.readAttributes().permissions();
        Set<PosixFilePermission> forbidden = Set.of(
                PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_WRITE, PosixFilePermission.GROUP_EXECUTE,
                PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_WRITE, PosixFilePermission.OTHERS_EXECUTE);
        for (PosixFilePermission p : forbidden) {
            if (perms.contains(p)) {
                throw new IOException("sealed-blob file " + path + " has over-permissive mode; require 0600");
            }
        }
    }
}

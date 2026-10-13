package de.swiesend.secretservice.hardened.tpm2;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.EnumSet;
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
 * <p>File permissions are enforced to {@code 0600}: the temp file is created
 * mode-0600 from the outset (no umask window), and the atomic move preserves
 * those permissions. Readers validate mode {@code 0600} at load time and
 * refuse over-permissive files.</p>
 *
 * <p>The {@code policyKind} byte uses explicit stable wire codes
 * ({@link PolicyKind#wire()}) rather than {@code ordinal()} so reordering the
 * enum never changes the on-disk format.</p>
 */
public final class Tpm2SealedBlob {

    public enum PolicyKind {
        /** Unseal requires a caller-supplied password (HMAC-session with the TPM). */
        PASSWORD((byte) 0x01),
        /** Unseal requires matching PCR state at load time. Not yet shipped; reserved. */
        PCR((byte) 0x02);

        private final byte wire;
        PolicyKind(byte wire) { this.wire = wire; }
        public byte wire() { return wire; }

        static PolicyKind fromWire(byte b) {
            for (PolicyKind k : values()) if (k.wire == b) return k;
            throw new IllegalArgumentException("unknown policy-kind wire byte: 0x" + Integer.toHexString(b & 0xff));
        }
    }

    private static final byte[] MAGIC = {'T', 'P', 'M', '2', 'B', 'L', 'O', 'B'};
    /** v1 sealed the pepper bytes verbatim -- lossy for non-UTF-8 peppers (see security audit F-9). */
    private static final byte VERSION_1 = 0x01;
    /** v2 seals base64(pepper), so any pepper round-trips losslessly through the text pepper SPI. */
    private static final byte VERSION_2 = 0x02;

    private static final Set<PosixFilePermission> MODE_0600 = EnumSet.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

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
        buf.put(VERSION_2);
        buf.put(policyKind.wire());
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
        if (version == VERSION_1) {
            throw new IllegalArgumentException(
                    "sealed-blob is the older v1 format (pepper sealed verbatim, not binary-safe); "
                            + "re-provision with Tpm2Provisioner to produce a v2 blob");
        }
        if (version != VERSION_2) {
            throw new IllegalArgumentException("unsupported sealed-blob version: " + version);
        }
        PolicyKind policyKind = PolicyKind.fromWire(buf.get());
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

    /**
     * Write the blob atomically, mode {@code 0600}. Creates the temp file with
     * owner-only permissions from the outset via a POSIX file attribute so no
     * umask window exposes the file world-readable. Non-POSIX filesystems fall
     * back to a create-then-chmod sequence.
     */
    public void writeTo(Path target) throws IOException {
        Path tmp = target.resolveSibling(target.getFileName() + ".tmp");
        byte[] bytes = toBytes();
        boolean posix = Files.getFileAttributeView(target.getParent() != null ? target.getParent() : tmp,
                PosixFileAttributeView.class) != null;

        if (posix) {
            FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(MODE_0600);
            try (SeekableByteChannel ch = Files.newByteChannel(tmp,
                    EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), attr)) {
                ch.write(ByteBuffer.wrap(bytes));
            } catch (IOException e) {
                Files.deleteIfExists(tmp);
                throw e;
            }
        } else {
            try {
                Files.write(tmp, bytes,
                        StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            } catch (IOException e) {
                Files.deleteIfExists(tmp);
                throw e;
            }
        }

        try {
            // On POSIX the file is already mode-0600 from the create. On non-POSIX
            // we cannot do better than our FS supports.
            Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            Files.deleteIfExists(tmp);
            throw e;
        }
    }

    /**
     * Load a blob, failing closed if the file is readable by group/others or the
     * content is malformed. Any {@link IllegalArgumentException} raised by
     * {@link #fromBytes} (bad magic, unknown policy kind, truncated lengths) is
     * wrapped as {@link IOException} so this method's declared contract covers
     * every failure mode a caller needs to handle.
     */
    public static Tpm2SealedBlob readFrom(Path source) throws IOException {
        validateOwnerReadOnly(source);
        byte[] raw = Files.readAllBytes(source);
        try {
            return fromBytes(raw);
        } catch (IllegalArgumentException e) {
            throw new IOException("malformed sealed-blob file " + source + ": " + e.getMessage(), e);
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

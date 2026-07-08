package de.swiesend.secretservice.hardened.providers;

import de.swiesend.secretservice.hardened.KeyMaterialProvider;
import de.swiesend.secretservice.hardened.ThreatCoverage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.Set;

/**
 * Reads the pepper from a filesystem path. Enforces POSIX mode 0600 and owner-readable-only
 * semantics at construction. Optionally checks that the file is owned by a UID different from the
 * running process (real cross-UID defense).
 *
 * <p>File format: the first non-blank line is the base64-encoded pepper. Blank lines are ignored.</p>
 */
public final class FileKeyMaterialProvider implements KeyMaterialProvider {

    private static final Logger log = LoggerFactory.getLogger(FileKeyMaterialProvider.class);

    private final Path path;
    private final boolean requireDifferentOwner;

    private volatile byte[] cachedPepper;
    /** True only once the POSIX 0600/owner check actually ran and passed; false on non-POSIX filesystems. */
    private volatile boolean posixEnforced = false;
    private volatile boolean closed = false;

    public FileKeyMaterialProvider(Path path) { this(path, false); }

    public FileKeyMaterialProvider(Path path, boolean requireDifferentOwner) {
        this.path = Objects.requireNonNull(path, "path");
        this.requireDifferentOwner = requireDifferentOwner;
        validatePermissions();
        loadIntoCache();
    }

    private void validatePermissions() {
        if (!Files.exists(path)) {
            throw new IllegalStateException("key-material file does not exist: " + path);
        }
        PosixFileAttributeView view = Files.getFileAttributeView(path, PosixFileAttributeView.class);
        if (view == null) {
            log.warn("Filesystem does not expose POSIX attributes for {}; permission check skipped. "
                    + "Ensure the file is readable only by the owner.", path);
            return;
        }
        Set<PosixFilePermission> perms;
        String owner;
        try {
            perms = view.readAttributes().permissions();
            owner = view.readAttributes().owner().getName();
        } catch (IOException e) {
            throw new IllegalStateException("cannot stat key-material file: " + path, e);
        }
        Set<PosixFilePermission> forbidden = Set.of(
                PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_WRITE, PosixFilePermission.GROUP_EXECUTE,
                PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_WRITE, PosixFilePermission.OTHERS_EXECUTE
        );
        for (PosixFilePermission p : forbidden) {
            if (perms.contains(p)) {
                throw new IllegalStateException("key-material file " + path + " has over-permissive mode "
                        + PosixFilePermissions(perms) + "; require 0600");
            }
        }
        if (requireDifferentOwner) {
            String self = System.getProperty("user.name");
            if (self != null && self.equals(owner)) {
                throw new IllegalStateException("key-material file " + path + " owned by same user (" + owner
                        + "); requireDifferentOwner=true but file gives no cross-UID barrier");
            }
        }
        // The 0600/owner checks above actually ran; threatCoverage() may now claim a
        // perm-based cross-UID/offline barrier. On a non-POSIX filesystem we returned early
        // above with posixEnforced still false, and the coverage is degraded accordingly.
        posixEnforced = true;
    }

    private static String PosixFilePermissions(Set<PosixFilePermission> p) {
        StringBuilder sb = new StringBuilder("rwxrwxrwx".length());
        sb.append(p.contains(PosixFilePermission.OWNER_READ)    ? 'r' : '-');
        sb.append(p.contains(PosixFilePermission.OWNER_WRITE)   ? 'w' : '-');
        sb.append(p.contains(PosixFilePermission.OWNER_EXECUTE) ? 'x' : '-');
        sb.append(p.contains(PosixFilePermission.GROUP_READ)    ? 'r' : '-');
        sb.append(p.contains(PosixFilePermission.GROUP_WRITE)   ? 'w' : '-');
        sb.append(p.contains(PosixFilePermission.GROUP_EXECUTE) ? 'x' : '-');
        sb.append(p.contains(PosixFilePermission.OTHERS_READ)   ? 'r' : '-');
        sb.append(p.contains(PosixFilePermission.OTHERS_WRITE)  ? 'w' : '-');
        sb.append(p.contains(PosixFilePermission.OTHERS_EXECUTE)? 'x' : '-');
        return sb.toString();
    }

    private void loadIntoCache() {
        try {
            byte[] raw = Files.readAllBytes(path);
            String[] lines = new String(raw, StandardCharsets.US_ASCII).split("\r?\n");
            Arrays.fill(raw, (byte) 0);
            byte[] pepperBytes = null;
            for (String line : lines) {
                String trimmed = line.strip();
                if (trimmed.isEmpty()) continue;
                try {
                    pepperBytes = Base64.getDecoder().decode(trimmed);
                } catch (IllegalArgumentException e) {
                    throw new IllegalStateException("key-material file contains non-base64 line", e);
                }
                break; // first non-blank base64 line is the pepper
            }
            if (pepperBytes == null || pepperBytes.length == 0) {
                throw new IllegalStateException("pepper line missing in " + path);
            }
            this.cachedPepper = pepperBytes;
        } catch (IOException e) {
            throw new IllegalStateException("cannot read key-material file: " + path, e);
        }
    }

    @Override
    public char[] getPepper() {
        if (closed) throw new IllegalStateException("provider closed");
        byte[] snap = cachedPepper;
        char[] out = new char[snap.length];
        for (int i = 0; i < snap.length; i++) out[i] = (char) (snap[i] & 0xff);
        return out;
    }

    @Override
    public ThreatCoverage threatCoverage() {
        if (!posixEnforced) {
            // Non-POSIX filesystem: the 0600/owner check was skipped, so we cannot claim any
            // permission-based barrier. Report honestly rather than emit crossUid=REAL on trust.
            return new ThreatCoverage(
                    ThreatCoverage.Level.NONE,
                    ThreatCoverage.Level.NONE,
                    ThreatCoverage.Level.NONE,
                    ThreatCoverage.Level.NOT_APPLICABLE,
                    "Filesystem does not expose POSIX attributes, so the 0600/owner permission check "
                            + "could not be enforced; no cross-UID or offline barrier can be assumed."
            );
        }
        if (requireDifferentOwner) {
            return new ThreatCoverage(
                    ThreatCoverage.Level.PARTIAL,
                    ThreatCoverage.Level.REAL,
                    ThreatCoverage.Level.REAL,
                    ThreatCoverage.Level.NOT_APPLICABLE,
                    "File mode 0600 with a different owner blocks cross-UID and offline/cold-disk "
                            + "attackers. Same-UID attackers with root or ptrace still win."
            );
        }
        return new ThreatCoverage(
                ThreatCoverage.Level.NONE,
                ThreatCoverage.Level.REAL,
                ThreatCoverage.Level.PARTIAL,
                ThreatCoverage.Level.NOT_APPLICABLE,
                "File mode 0600 owned by the running user denies other UIDs but not a malicious "
                        + "same-UID process (which can read the file directly)."
        );
    }

    /** Scrubs the cached pepper. */
    @Override
    public void close() {
        byte[] p = cachedPepper;
        if (p != null) Arrays.fill(p, (byte) 0);
        closed = true;
    }
}

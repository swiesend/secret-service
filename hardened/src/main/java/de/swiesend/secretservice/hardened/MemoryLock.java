package de.swiesend.secretservice.hardened;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

/**
 * Best-effort process memory locking via the JDK Foreign Function &amp; Memory API (final in JDK 25).
 * Calls POSIX {@code mlockall(MCL_CURRENT | MCL_FUTURE)} so pepper and DEK buffers cannot be paged
 * out to swap. This is a whole-process operation and can fail if {@code RLIMIT_MEMLOCK} is too low
 * or the platform is not POSIX; failures are logged and reported honestly rather than thrown.
 *
 * <p>Because {@code mlockall} is a restricted native downcall, silent operation needs
 * {@code --enable-native-access=de.swiesend.secretservice.hardened} on the JVM command line;
 * without it the call still runs but the JVM prints a native-access warning. An adequate
 * {@code memlock} ulimit (systemd {@code LimitMEMLOCK=infinity}, or {@code ulimit -l}) is also
 * required for the lock to actually take.</p>
 */
final class MemoryLock {

    private static final Logger log = LoggerFactory.getLogger(MemoryLock.class);

    private MemoryLock() {}

    private static final int MCL_CURRENT = 1;
    private static final int MCL_FUTURE = 2;

    /** Cached result: {@code null} = not yet attempted, otherwise the outcome of the one attempt. */
    private static volatile Boolean locked;

    /**
     * Attempt to lock all current and future process memory. Idempotent: the first call performs
     * the {@code mlockall} syscall and caches the result; later calls return the cached value.
     *
     * @return {@code true} iff {@code mlockall} returned success
     */
    static synchronized boolean lockAll() {
        if (locked != null) return locked;
        boolean ok = false;
        try {
            Linker linker = Linker.nativeLinker();
            MethodHandle mlockall = linker.defaultLookup().find("mlockall")
                    .map(sym -> linker.downcallHandle(sym,
                            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT)))
                    .orElse(null);
            if (mlockall == null) {
                log.warn("MemoryLock: mlockall is unavailable on this platform; memory not locked.");
            } else {
                int rc = (int) mlockall.invoke(MCL_CURRENT | MCL_FUTURE);
                ok = (rc == 0);
                if (!ok) {
                    log.warn("MemoryLock: mlockall failed (rc={}). Check RLIMIT_MEMLOCK (ulimit -l / "
                            + "systemd LimitMEMLOCK); process memory is NOT locked.", rc);
                } else {
                    log.info("MemoryLock: process memory locked (mlockall MCL_CURRENT|MCL_FUTURE).");
                }
            }
        } catch (Throwable t) {
            // Restricted-method denial, missing native access, or any FFM error: fail soft.
            log.warn("MemoryLock: could not lock process memory ({}); continuing without it. "
                    + "Add --enable-native-access=de.swiesend.secretservice.hardened to silence the "
                    + "native-access warning.", t.toString());
        }
        locked = ok;
        return ok;
    }
}

package de.swiesend.secretservice.simple;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * Lets the closing of a shared connection wait for the operations that it must not cut off. Any
 * number of operations run side by side; the closing waits until none runs, for a time. The
 * connection is not opened again, so no operation starts once a closing has begun: it gets the
 * refusal instead.
 */
final class RunningOperations {

    private static final Logger log = LoggerFactory.getLogger(RunningOperations.class);

    private final Supplier<? extends RuntimeException> refusal;

    // Guards running and closingBegun: an operation starts or is refused, never in between.
    private final Object monitor = new Object();
    /** The operations that run; one that runs inside another is part of that one. */
    private int running = 0;
    private boolean closingBegun = false;

    /** Whether the thread runs an operation. */
    private final ThreadLocal<Boolean> inOperation = new ThreadLocal<>();

    /**
     * @param refusal what an operation throws that starts once a closing has begun
     */
    RunningOperations(Supplier<? extends RuntimeException> refusal) {
        this.refusal = refusal;
    }

    /**
     * Runs {@code operation} as one that a closing waits for. Once a closing has begun, the
     * operation does not run and the refusal is thrown: it would run on a connection that closes
     * under it, or has closed. An operation inside a running one is part of that and runs.
     */
    <T> T during(Supplier<T> operation) {
        if (isInOperation()) return operation.get();
        synchronized (monitor) {
            if (closingBegun) throw refusal.get();
            running++;
        }
        inOperation.set(Boolean.TRUE);
        try {
            return operation.get();
        } finally {
            inOperation.remove();
            synchronized (monitor) {
                running--;
                monitor.notifyAll();
            }
        }
    }

    /**
     * Runs {@code closing} once no operation runs, and after {@code patience} all the same: an
     * operation may wait for the user, and a shutdown does not. Called from within an operation,
     * it waits for the other ones only. An interrupt ends the waiting, not the closing: the
     * closing runs with the thread's interrupt flag cleared, which is set again afterwards.
     *
     * @return what {@code closing} returns
     */
    <T> T whenIdle(Duration patience, Supplier<T> closing) {
        int own = isInOperation() ? 1 : 0;
        boolean interrupted = false;
        boolean idle;
        synchronized (monitor) {
            closingBegun = true;
            long deadline = System.nanoTime() + patience.toNanos();
            try {
                while (running > own) {
                    long left = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime());
                    if (left <= 0) break;
                    monitor.wait(left);
                }
            } catch (InterruptedException e) {
                interrupted = true;
            }
            idle = running <= own;
        }
        if (!idle) {
            log.warn("An operation still runs on the D-Bus connection; closing it all the same. "
                    + "A collection that the operation locked to ask for the user's permission stays locked.");
        }
        // A closing that waits for the connection would take a pending interrupt for its own,
        // and report a connection that it closed as not closed.
        interrupted |= Thread.interrupted();
        try {
            return closing.get();
        } finally {
            if (interrupted) Thread.currentThread().interrupt();
        }
    }

    private boolean isInOperation() {
        boolean inside = Boolean.TRUE.equals(inOperation.get());
        // get() left an entry behind for a thread that runs none.
        if (!inside) inOperation.remove();
        return inside;
    }
}

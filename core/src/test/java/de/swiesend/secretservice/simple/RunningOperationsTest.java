package de.swiesend.secretservice.simple;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code SimpleCollection.disconnect()}, and the JVM's shutdown hook through it, closed the shared
 * connection under a call that had locked a collection to ask for the user's permission. The call
 * could not unlock the collection again, and it stayed locked for every application.
 *
 * <p>Without a bus: the waiting and the refusing alone, which {@code disconnect()} does through
 * {@link RunningOperations}. A test of {@code disconnect()} itself would close the static
 * connection for the rest of the JVM.</p>
 */
@Timeout(30)
class RunningOperationsTest {

    private static final Duration LONG = Duration.ofSeconds(20);

    private static final String WARNING = "An operation still runs";

    private final RunningOperations operations = new RunningOperations(() -> new SecurityException("closed"));

    /** Set by an operation as its last step. */
    private final AtomicBoolean ended = new AtomicBoolean();

    /** An operation that runs until {@code end} is counted down; {@code started} tells that it runs. */
    private CompletableFuture<String> operationUntil(CountDownLatch end, CountDownLatch started) {
        return CompletableFuture.supplyAsync(() -> operations.during(() -> {
            started.countDown();
            await(end);
            ended.set(true);
            return "done";
        }));
    }

    private static void await(CountDownLatch latch) {
        try {
            assertTrue(latch.await(20, TimeUnit.SECONDS));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    /** Returns once a closing has begun: an operation is refused from then on. */
    private void awaitTheClosingToBegin() throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (true) {
            try {
                operations.during(() -> "ran");
            } catch (SecurityException e) {
                return;
            }
            assertTrue(System.nanoTime() < deadline, "no closing began");
            Thread.sleep(10);
        }
    }

    /** What slf4j-simple wrote to the error stream while {@code action} ran, and its result. */
    private static <T> String logOf(Supplier<T> action, T expected) {
        PrintStream original = System.err;
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
        try {
            assertEquals(expected, action.get());
        } finally {
            System.setErr(original);
        }
        return captured.toString(StandardCharsets.UTF_8);
    }

    @Test
    void theClosingWaitsForARunningOperation() throws Exception {
        CountDownLatch end = new CountDownLatch(1);
        CountDownLatch started = new CountDownLatch(1);
        CompletableFuture<String> operation = operationUntil(end, started);
        await(started);

        CompletableFuture<Boolean> closing = CompletableFuture.supplyAsync(
                () -> operations.whenIdle(LONG, ended::get));
        assertThrows(TimeoutException.class, () -> closing.get(300, TimeUnit.MILLISECONDS),
                "not while the operation runs");

        end.countDown();
        assertTrue(closing.get(10, TimeUnit.SECONDS), "the operation had ended when the connection closed");
        assertEquals("done", operation.get(10, TimeUnit.SECONDS));
    }

    @Test
    void theClosingGoesAheadWhereAnOperationOutlastsItsPatience() throws Exception {
        // An operation that waits for the user's answer: a shutdown does not wait as long.
        CountDownLatch end = new CountDownLatch(1);
        CountDownLatch started = new CountDownLatch(1);
        CompletableFuture<String> operation = operationUntil(end, started);
        await(started);

        assertEquals("closed", operations.whenIdle(Duration.ofMillis(100), () -> "closed"));
        assertFalse(ended.get(), "the operation is cut off");

        end.countDown();
        assertEquals("done", operation.get(10, TimeUnit.SECONDS));
    }

    @Test
    void anOperationThatStartsWhileTheClosingWaitsIsRefusedAtOnce() throws Exception {
        // It would lock a collection on a connection that closes under it.
        CountDownLatch end = new CountDownLatch(1);
        CountDownLatch started = new CountDownLatch(1);
        CompletableFuture<String> operation = operationUntil(end, started);
        await(started);
        CompletableFuture<String> closing = CompletableFuture.supplyAsync(
                () -> operations.whenIdle(LONG, () -> "closed"));
        awaitTheClosingToBegin();

        AtomicBoolean ran = new AtomicBoolean();
        long start = System.nanoTime();
        SecurityException refusal = assertThrows(SecurityException.class, () -> operations.during(() -> {
            ran.set(true);
            return "ran";
        }));

        assertEquals("closed", refusal.getMessage(), "the refusal that the owner gave");
        assertFalse(ran.get());
        assertTrue(Duration.ofNanos(System.nanoTime() - start).compareTo(Duration.ofSeconds(5)) < 0,
                "it does not wait for the closing");
        assertFalse(closing.isDone(), "the closing still waits for the first operation");

        end.countDown();
        assertEquals("closed", closing.get(10, TimeUnit.SECONDS));
        assertEquals("done", operation.get(10, TimeUnit.SECONDS));
    }

    @Test
    void noOperationStartsOnceTheConnectionIsClosed() {
        assertEquals("closed", operations.whenIdle(LONG, () -> "closed"));

        AtomicBoolean ran = new AtomicBoolean();
        assertThrows(SecurityException.class, () -> operations.during(() -> {
            ran.set(true);
            return "ran";
        }));
        assertFalse(ran.get(), "nothing runs against the closed connection");
    }

    @Test
    void anOperationInsideARunningOneStillRunsWhileTheClosingWaits() throws Exception {
        // getSecrets() asks through unlockWithUserPermission(): the inner call is part of the outer.
        CountDownLatch closingBegun = new CountDownLatch(1);
        CountDownLatch started = new CountDownLatch(1);
        CompletableFuture<String> operation = CompletableFuture.supplyAsync(() -> operations.during(() -> {
            started.countDown();
            await(closingBegun);
            return operations.during(() -> "inner");
        }));
        await(started);
        CompletableFuture<String> closing = CompletableFuture.supplyAsync(
                () -> operations.whenIdle(LONG, () -> "closed"));
        awaitTheClosingToBegin();

        closingBegun.countDown();

        assertEquals("inner", operation.get(10, TimeUnit.SECONDS));
        assertEquals("closed", closing.get(10, TimeUnit.SECONDS));
    }

    @Test
    void operationsRunSideBySide() throws Exception {
        CountDownLatch end = new CountDownLatch(1);
        CountDownLatch started = new CountDownLatch(1);
        CompletableFuture<String> first = operationUntil(end, started);
        await(started);

        assertEquals("second", operations.during(() -> "second"), "while the first still runs");

        end.countDown();
        assertEquals("done", first.get(10, TimeUnit.SECONDS));
    }

    @Test
    void aClosingFromWithinAnOperationDoesNotWaitForItself() {
        long start = System.nanoTime();

        String log = logOf(() -> operations.during(() -> operations.whenIdle(LONG, () -> "closed")), "closed");

        assertTrue(Duration.ofNanos(System.nanoTime() - start).compareTo(Duration.ofSeconds(10)) < 0);
        assertFalse(log.contains(WARNING), "no other operation runs, and none is left locked: " + log);
    }

    @Test
    void aClosingFromWithinAnOperationWaitsForTheOthers() throws Exception {
        CountDownLatch end = new CountDownLatch(1);
        CountDownLatch started = new CountDownLatch(1);
        CompletableFuture<String> other = operationUntil(end, started);
        await(started);

        CompletableFuture<Boolean> closing = CompletableFuture.supplyAsync(
                () -> operations.during(() -> operations.whenIdle(LONG, ended::get)));
        assertThrows(TimeoutException.class, () -> closing.get(300, TimeUnit.MILLISECONDS),
                "not while the other operation runs");

        end.countDown();
        assertTrue(closing.get(10, TimeUnit.SECONDS), "the other operation had ended when the connection closed");
        assertEquals("done", other.get(10, TimeUnit.SECONDS));
    }

    @Test
    void aClosingThatCutsAnOperationOffSaysSo() throws Exception {
        CountDownLatch end = new CountDownLatch(1);
        CountDownLatch started = new CountDownLatch(1);
        CompletableFuture<String> operation = operationUntil(end, started);
        await(started);

        String log = logOf(() -> operations.whenIdle(Duration.ofMillis(100), () -> "closed"), "closed");

        assertTrue(log.contains(WARNING), log);
        end.countDown();
        assertEquals("done", operation.get(10, TimeUnit.SECONDS));
    }

    @Test
    void anInterruptEndsTheWaitingAndIsNotCarriedIntoTheClosing() throws Exception {
        // The closing waits for the connection with a sleep: with the flag set it would give up at
        // once and report a connection that it closed as not closed.
        CountDownLatch end = new CountDownLatch(1);
        CountDownLatch started = new CountDownLatch(1);
        CompletableFuture<String> operation = operationUntil(end, started);
        await(started);
        long start = System.nanoTime();

        Thread.currentThread().interrupt();
        boolean flagWhileClosing;
        boolean flagAfterwards;
        try {
            flagWhileClosing = operations.whenIdle(LONG, () -> Thread.currentThread().isInterrupted());
        } finally {
            flagAfterwards = Thread.interrupted();
        }

        assertFalse(flagWhileClosing, "the closing runs to its end");
        assertTrue(flagAfterwards, "the interrupt is the caller's to handle afterwards");
        assertTrue(Duration.ofNanos(System.nanoTime() - start).compareTo(Duration.ofSeconds(10)) < 0,
                "the interrupt ended the waiting");
        end.countDown();
        assertEquals("done", operation.get(10, TimeUnit.SECONDS));
    }

    @Test
    void anInterruptThatIsPendingIsNotCarriedIntoTheClosingEither() {
        // Nothing runs, so nothing waits and nothing takes the interrupt before the closing.
        Thread.currentThread().interrupt();
        boolean flagWhileClosing;
        boolean flagAfterwards;
        try {
            flagWhileClosing = operations.whenIdle(LONG, () -> Thread.currentThread().isInterrupted());
        } finally {
            flagAfterwards = Thread.interrupted();
        }

        assertFalse(flagWhileClosing);
        assertTrue(flagAfterwards);
    }

    @Test
    void anOperationsExceptionLeavesNothingHeld() throws Exception {
        assertThrows(SecurityException.class, () -> operations.during(() -> {
            throw new SecurityException("refused");
        }));

        // The thread runs no operation any more: its closing waits for another one, and says so.
        CountDownLatch end = new CountDownLatch(1);
        CountDownLatch started = new CountDownLatch(1);
        CompletableFuture<String> other = operationUntil(end, started);
        await(started);
        String log = logOf(() -> operations.whenIdle(Duration.ofMillis(100), () -> "closed"), "closed");
        assertTrue(log.contains(WARNING), log);
        end.countDown();
        assertEquals("done", other.get(10, TimeUnit.SECONDS));

        // And the failed operation does not count as running: from another thread, which would wait for it.
        assertEquals("closed", CompletableFuture.supplyAsync(() -> operations.whenIdle(LONG, () -> "closed"))
                .get(5, TimeUnit.SECONDS));
    }
}

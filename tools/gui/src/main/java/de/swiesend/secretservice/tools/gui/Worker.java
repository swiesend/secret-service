package de.swiesend.secretservice.tools.gui;

import javax.swing.SwingUtilities;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

/**
 * Makes the calls to the keyring one after the other on a thread of its own, and hands each
 * result to the event thread. A call to the keyring waits for the provider, and for as long as a
 * dialog of the provider waits for the user: on the event thread it would freeze the window.
 */
final class Worker {

    /** Told on the event thread what the worker does. */
    interface Listener {

        /** A task starts. */
        void started(String what);

        /** A task threw, or gave up after {@link #cancel()}: then with a {@link CancellationException}. */
        void failed(String what, Throwable failure);

        /** No task runs or waits any more. */
        void idle();
    }

    private final ExecutorService executor = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "secret-service-gui-worker");
        thread.setDaemon(true);
        return thread;
    });
    private final Listener listener;
    private final Object lock = new Object();
    /** The thread of the task that runs, guarded by {@link #lock}. */
    private Thread running;
    /** The tasks that run or wait, counted on the event thread. */
    private int pending = 0;

    Worker(Listener listener) {
        this.listener = listener;
    }

    /**
     * Runs the task after the ones that wait, then hands its result to {@code done} on the event
     * thread. Called on the event thread.
     */
    <T> void run(String what, Callable<T> task, Consumer<T> done) {
        pending++;
        executor.execute(() -> {
            SwingUtilities.invokeLater(() -> listener.started(what));
            T result = null;
            Throwable failure = null;
            synchronized (lock) {
                Thread.interrupted(); // a cancellation that came after the task before this one ended
                running = Thread.currentThread();
            }
            try {
                result = task.call();
            } catch (Throwable t) {
                failure = t;
            } finally {
                synchronized (lock) {
                    running = null;
                    Thread.interrupted();
                }
            }
            T finalResult = result;
            Throwable finalFailure = failure;
            SwingUtilities.invokeLater(() -> {
                try {
                    if (finalFailure != null) listener.failed(what, finalFailure);
                    else done.accept(finalResult);
                } finally {
                    if (--pending == 0) listener.idle();
                }
            });
        });
    }

    /**
     * Ends the task if it was cancelled, between two of its calls to the keyring. The library
     * returns from a call that the cancellation interrupts, with the thread's interrupt flag set
     * again, and the next call would fail on it.
     *
     * @throws CancellationException if the task was cancelled
     */
    static void checkCancelled() {
        if (Thread.currentThread().isInterrupted()) throw new CancellationException("cancelled");
    }

    /** Whether a task runs or waits. Called on the event thread. */
    boolean isBusy() {
        return pending > 0;
    }

    /**
     * Interrupts the task that runs: the library gives up its wait for the provider or for the
     * user, and the task ends with what the library returns then.
     */
    void cancel() {
        synchronized (lock) {
            if (running != null) running.interrupt();
        }
    }

    /** Interrupts the task that runs and drops the ones that wait. */
    void shutdown() {
        executor.shutdownNow();
    }
}

package de.swiesend.secretservice.tools.gui;

import javax.imageio.ImageIO;
import javax.swing.AbstractButton;
import javax.swing.JDialog;
import javax.swing.SwingUtilities;
import javax.swing.text.JTextComponent;
import java.awt.Component;
import java.awt.Container;
import java.awt.Rectangle;
import java.awt.Robot;
import java.awt.Toolkit;
import java.awt.Window;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Drives the windows of this JVM as a user does: it finds a component by its name, clicks and
 * types on the event thread, waits for what the window shows, and takes screenshots.
 */
final class Gui {

    /** Where the screenshots go, one per call of {@link #screenshot}, numbered in their order. */
    static final Path SCREENSHOTS = Path.of("target", "gui-screenshots");

    /** How long a step may take. A dialog of the provider is answered within a few seconds. */
    static final Duration PATIENCE = Duration.ofSeconds(60);

    private static int screenshots = 0;

    private Gui() {
    }

    /** Runs the call on the event thread and waits for it. */
    static <T> T onEventThread(Callable<T> call) {
        AtomicReference<T> result = new AtomicReference<>();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Runnable run = () -> {
            try {
                result.set(call.call());
            } catch (Throwable t) {
                failure.set(t);
            }
        };
        try {
            if (SwingUtilities.isEventDispatchThread()) run.run();
            else SwingUtilities.invokeAndWait(run);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError("interrupted while waiting for the event thread", e);
        } catch (Exception e) {
            throw new AssertionError("the event thread failed", e);
        }
        if (failure.get() instanceof Error error) throw error;
        if (failure.get() != null) throw new AssertionError("the call on the event thread failed", failure.get());
        return result.get();
    }

    /** The showing component of that type and name, in any window. */
    static <T extends Component> Optional<T> lookup(Class<T> type, String name) {
        return onEventThread(() -> {
            for (Window window : Window.getWindows()) {
                if (!window.isShowing()) continue;
                T found = search(window, type, name);
                if (found != null) return Optional.of(found);
            }
            return Optional.<T>empty();
        });
    }

    private static <T extends Component> T search(Component component, Class<T> type, String name) {
        if (type.isInstance(component) && name.equals(component.getName())) return type.cast(component);
        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                T found = search(child, type, name);
                if (found != null) return found;
            }
        }
        return null;
    }

    /** As {@link #lookup}, failing the test if no window shows such a component. */
    static <T extends Component> T find(Class<T> type, String name) {
        return lookup(type, name).orElseThrow(
                () -> new AssertionError("no window shows a " + type.getSimpleName() + " named \"" + name + "\""));
    }

    /**
     * Clicks the button, which has to be enabled. It does not wait for what the click starts: a
     * click may open a dialog, which the event thread shows until it is answered.
     */
    static void click(String name) {
        AbstractButton button = find(AbstractButton.class, name);
        assertTrue(onEventThread(button::isEnabled), "the button \"" + name + "\" is enabled");
        SwingUtilities.invokeLater(() -> button.doClick(0));
    }

    /** Replaces the text of the field. */
    static void type(String name, String text) {
        JTextComponent field = find(JTextComponent.class, name);
        onEventThread(() -> {
            field.setText(text);
            return null;
        });
    }

    /** Waits until the condition holds on the event thread, and fails the test after {@link #PATIENCE}. */
    static void await(String what, BooleanSupplier condition) {
        long deadline = System.nanoTime() + PATIENCE.toNanos();
        while (!onEventThread(condition::getAsBoolean)) {
            if (System.nanoTime() > deadline) {
                screenshot("timeout");
                fail("not within " + PATIENCE.toSeconds() + " s: " + what);
            }
            pause(100);
        }
    }

    /** Answers the dialog with that title by clicking its button with that text. */
    static void answer(String title, String buttonText) {
        AtomicReference<JDialog> dialog = new AtomicReference<>();
        await("a dialog titled \"" + title + "\"", () -> {
            for (Window window : Window.getWindows()) {
                if (window instanceof JDialog candidate && candidate.isShowing() && title.equals(candidate.getTitle())) {
                    dialog.set(candidate);
                    return true;
                }
            }
            return false;
        });
        AbstractButton button = onEventThread(() -> buttonWithText(dialog.get(), buttonText));
        assertTrue(button != null, "the dialog \"" + title + "\" has the button \"" + buttonText + "\"");
        SwingUtilities.invokeLater(() -> button.doClick(0));
    }

    private static AbstractButton buttonWithText(Component component, String text) {
        if (component instanceof AbstractButton button && text.equals(button.getText())) return button;
        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                AbstractButton found = buttonWithText(child, text);
                if (found != null) return found;
            }
        }
        return null;
    }

    /**
     * The log of the gnome-keyring-dialogs container's answerer, one line per dialog, in the
     * directory from which the test runs, {@code tools/gui}.
     */
    private static final Path DIALOGS_LOG = Path.of("..", "..", "target", "provider-logs", "dialogs.log");

    /** How many dialogs of the provider the container's answerer has answered so far. */
    static long answeredDialogs() {
        try {
            if (!Files.exists(DIALOGS_LOG)) return 0;
            try (var lines = Files.lines(DIALOGS_LOG)) {
                return lines.filter(line -> line.startsWith("answered ")).count();
            }
        } catch (IOException e) {
            throw new AssertionError("could not read " + DIALOGS_LOG, e);
        }
    }

    /**
     * Saves what the screen shows, the window and a dialog of the provider if one is open, and
     * beside it what the window's log shows.
     */
    static Path screenshot(String name) {
        onEventThread(() -> null); // what the event thread has queued is painted first
        Toolkit.getDefaultToolkit().sync();
        pause(200);
        try {
            Files.createDirectories(SCREENSHOTS);
            Path file = SCREENSHOTS.resolve(String.format("%02d-%s.png", ++screenshots, name));
            BufferedImage image = new Robot().createScreenCapture(
                    new Rectangle(Toolkit.getDefaultToolkit().getScreenSize()));
            ImageIO.write(image, "png", file.toFile());
            Optional<JTextComponent> log = lookup(JTextComponent.class, "log");
            if (log.isPresent()) {
                Files.writeString(SCREENSHOTS.resolve(String.format("%02d-%s.log", screenshots, name)),
                        onEventThread(log.get()::getText));
            }
            return file;
        } catch (IOException | java.awt.AWTException e) {
            throw new AssertionError("could not take the screenshot \"" + name + "\"", e);
        }
    }

    static void pause(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError("interrupted", e);
        }
    }
}

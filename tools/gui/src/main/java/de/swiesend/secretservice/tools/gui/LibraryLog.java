package de.swiesend.secretservice.tools.gui;

import java.util.function.Consumer;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 * Hands the library's log to the window. The GUI binds SLF4J to {@code java.util.logging}
 * ({@code slf4j-jdk14}), and this handler on the library's logger passes each record on as one
 * line, under SLF4J's names of the levels. The library logs no secret and no label, so its log can
 * show in the window.
 */
final class LibraryLog extends Handler {

    /** The logger of the library's packages. */
    static final String LIBRARY = "de.swiesend.secretservice";

    /** The levels that the window offers, by SLF4J's names, with their {@code java.util.logging} level. */
    enum Threshold {
        ERROR(Level.SEVERE), WARN(Level.WARNING), INFO(Level.INFO), DEBUG(Level.FINE), TRACE(Level.FINEST);

        final Level level;

        Threshold(Level level) {
            this.level = level;
        }
    }

    // The logger is held: java.util.logging keeps only weak references to its loggers, and a
    // collected one loses its level and its handlers.
    private final Logger library = Logger.getLogger(LIBRARY);
    private final Consumer<String> lines;
    private final SimpleFormatter formatter = new SimpleFormatter();

    /**
     * Adds the handler to the library's logger, at the threshold.
     *
     * @param lines takes each line, on the thread that logged it
     */
    LibraryLog(Consumer<String> lines, Threshold threshold) {
        this.lines = lines;
        library.addHandler(this);
        setThreshold(threshold);
    }

    /** Passes on the records at that level and above. */
    void setThreshold(Threshold threshold) {
        library.setLevel(threshold.level);
        setLevel(threshold.level);
    }

    @Override
    public void publish(LogRecord record) {
        if (record == null || !isLoggable(record)) return;
        StringBuilder line = new StringBuilder("lib ")
                .append(levelName(record.getLevel())).append(' ')
                .append(simpleName(record.getLoggerName())).append(": ")
                .append(formatter.formatMessage(record));
        if (record.getThrown() != null) {
            line.append(" (").append(record.getThrown().getClass().getSimpleName());
            if (record.getThrown().getMessage() != null) line.append(": ").append(record.getThrown().getMessage());
            line.append(')');
        }
        lines.accept(line.toString());
    }

    private static String levelName(Level level) {
        if (level.intValue() >= Level.SEVERE.intValue()) return "ERROR";
        if (level.intValue() >= Level.WARNING.intValue()) return "WARN";
        if (level.intValue() >= Level.INFO.intValue()) return "INFO";
        if (level.intValue() >= Level.FINE.intValue()) return "DEBUG";
        return "TRACE";
    }

    private static String simpleName(String logger) {
        if (logger == null) return "?";
        return logger.substring(logger.lastIndexOf('.') + 1);
    }

    @Override
    public void flush() {
    }

    /** Removes the handler from the library's logger. */
    @Override
    public void close() {
        library.removeHandler(this);
    }
}

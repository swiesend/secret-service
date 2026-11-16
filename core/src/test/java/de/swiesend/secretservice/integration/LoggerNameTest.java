package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.handlers.MessageHandler;
import de.swiesend.secretservice.handlers.SignalHandler;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The handlers log under the name of the class that declares the logger, also for a subclass. A
 * consumer filters the library's log by these names, and a logger named after the runtime class
 * does not match the name that the consumer configured.
 *
 * <p>Needs no bus.</p>
 */
class LoggerNameTest {

    private static String loggerNameOf(Class<?> declaring, Object handler) throws Exception {
        Field field = declaring.getDeclaredField("log");
        field.setAccessible(true);
        return ((Logger) field.get(handler)).getName();
    }

    @Test
    void aSubclassOfMessageHandlerLogsAsMessageHandler() throws Exception {
        MessageHandler subclass = new MessageHandler(null) { };

        assertEquals("de.swiesend.secretservice.handlers.MessageHandler",
                loggerNameOf(MessageHandler.class, subclass));
    }

    @Test
    void aSubclassOfSignalHandlerLogsAsSignalHandler() throws Exception {
        SignalHandler subclass = new SignalHandler() { };

        assertEquals("de.swiesend.secretservice.handlers.SignalHandler",
                loggerNameOf(SignalHandler.class, subclass));
    }
}

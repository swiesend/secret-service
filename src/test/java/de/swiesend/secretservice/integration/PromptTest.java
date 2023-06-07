package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.Collection;
import de.swiesend.secretservice.Pair;
import de.swiesend.secretservice.Static;
import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.messages.DBusSignal;
import de.swiesend.secretservice.handlers.SignalHandler;
import org.freedesktop.secret.interfaces.Prompt;
import de.swiesend.secretservice.integration.test.Context;
import org.junit.jupiter.api.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static de.swiesend.secretservice.Static.DEFAULT_PROMPT_TIMEOUT;
import static de.swiesend.secretservice.Static.ObjectPaths.DEFAULT_COLLECTION;
import static org.junit.jupiter.api.Assertions.*;


public class PromptTest {

    private Logger log = LoggerFactory.getLogger(getClass());
    private Context context;

    @BeforeEach
    public void beforeEach(TestInfo info) {
        log.info(info.getDisplayName());
        context = new Context(log);
        context.ensureCollection();
    }

    @AfterEach
    public void afterEach() {
        context.after();
    }

    @Test
    @Disabled
    public void prompt() {
        ObjectPath defaultCollection = Static.Convert.toObjectPath(DEFAULT_COLLECTION);
        ArrayList<ObjectPath> cs = new ArrayList();
        cs.add(defaultCollection);

        log.info("lock default collection");
        Pair<List<ObjectPath>, ObjectPath> locked = context.service.lock(cs);
        log.info(locked.toString());

        log.info("unlock default collection");
        Pair<List<ObjectPath>, ObjectPath> unlocked = context.service.unlock(cs);
        log.info(unlocked.toString());
        ObjectPath prompt = unlocked.b;

        Prompt.Completed completed = context.prompt.await(prompt, DEFAULT_PROMPT_TIMEOUT);
        assertNotNull(completed);
    }

    @Test
    @Disabled("Depends on timing and default collection lock.")
    public void dismissPrompt() throws InterruptedException {
        List<ObjectPath> cs = Arrays.asList(context.collection.getPath());
        context.service.lock(cs);
        SignalHandler handler = context.service.getSignalHandler();
        Collection defaultCollection = new Collection("login", context.service);
        boolean expected = defaultCollection.isLocked();
        Thread.currentThread().sleep(500L);

        Pair<List<ObjectPath>, ObjectPath> response = context.service.unlock(cs);
        ObjectPath prompt = response.b;
        assertDoesNotThrow(() ->context.prompt.prompt(prompt)); // Should not throw NoSuchObject
        DBusSignal signal = handler.getLastHandledSignal();
        Thread.currentThread().sleep(500L);
        assertFalse(signal instanceof Prompt.Completed);

        context.prompt.dismiss();
        Thread.currentThread().sleep(500L); // await signal
        Prompt.Completed completed = handler.getLastHandledSignal(Prompt.Completed.class, prompt.getPath());
        assertNotNull(completed);
        assertEquals(expected, completed.dismissed);
    }

    @Test
    public void isRemote() {
        assertFalse(context.prompt.isRemote());
    }

    @Test
    public void getObjectPath() {
        assertEquals("/", context.prompt.getObjectPath());
    }
}
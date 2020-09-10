package org.freedesktop.secret;

import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.secret.errors.NoSuchObject;
import org.freedesktop.secret.interfaces.Prompt;
import org.freedesktop.secret.test.Context;
import org.junit.jupiter.api.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

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
    public void prompt() throws InterruptedException, NoSuchObject {

        ObjectPath defaultCollection = Static.Convert.toObjectPath(Static.ObjectPaths.DEFAULT_COLLECTION);
        ArrayList<ObjectPath> cs = new ArrayList();
        cs.add(defaultCollection);

        log.info("lock default collection");
        Pair<List<ObjectPath>, ObjectPath> locked = context.service.lock(cs);
        log.info(locked.toString());

        log.info("unlock default collection");
        Pair<List<ObjectPath>, ObjectPath> unlocked = context.service.unlock(cs);
        log.info(unlocked.toString());
        ObjectPath prompt = unlocked.b;

        Duration timeout = Duration.ofSeconds(300);

        Prompt.Completed completed = context.prompt.await(prompt, timeout);
        assertNotNull(completed);
    }

    @Test
    @Disabled
    public void dismissPrompt() throws InterruptedException, NoSuchObject {
        ArrayList<ObjectPath> cs = new ArrayList();
        cs.add(context.collection.getPath());
        context.service.lock(cs);

        Pair<List<ObjectPath>, ObjectPath> response = context.service.unlock(cs);
        ObjectPath prompt = response.b;

        context.prompt.prompt(prompt);
        Thread.currentThread().sleep(250L);
        // requires Dismiss() to be implemented from the secret service. Some older versions, like GDBus 2.56.3 do provide this method.
        // org.freedesktop.dbus.exceptions.DBusException: org.freedesktop.DBus.Error.UnknownMethod: Method Dismiss is not implemented on interface org.freedesktop.Secret.Prompt
        context.prompt.dismiss();
        Thread.currentThread().sleep(500L); // await signal

        Prompt.Completed completed = context.service.getSignalHandler()
                .getLastHandledSignal(Prompt.Completed.class, prompt.getPath());
        assertTrue(completed.dismissed);
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
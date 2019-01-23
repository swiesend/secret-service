package org.freedesktop.Secret;

import org.freedesktop.Secret.interfaces.Prompt;
import org.freedesktop.Secret.test.Context;
import org.freedesktop.dbus.ObjectPath;
import org.junit.jupiter.api.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
    public void prompt() throws InterruptedException {

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
        context.prompt.await(prompt);

        Prompt.Completed completed = context.prompt.getCurrentSingal();
        assertNotNull(completed);
    }

    @Test
    @Disabled
    public void dismissPrompt() throws InterruptedException {
        ArrayList<ObjectPath> cs = new ArrayList();
        cs.add(context.collection.getPath());
        context.service.lock(cs);

        Pair<List<ObjectPath>, ObjectPath> response = context.service.unlock(cs);
        ObjectPath prompt = response.b;

        context.prompt.prompt(prompt);
        Thread.sleep(250L);
        context.prompt.dismiss();
        Thread.sleep(500L); // await signal

        Prompt.Completed completed = context.prompt.getCurrentSingal();
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
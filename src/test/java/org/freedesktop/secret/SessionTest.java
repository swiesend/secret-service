package org.freedesktop.secret;

import org.freedesktop.secret.test.Context;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;


public class SessionTest {

    private Logger log = LoggerFactory.getLogger(getClass());
    private Context context;

    @BeforeEach
    public void beforeEach(TestInfo info) {
        log.info(info.getDisplayName());
        context = new Context(log);
        context.ensureSession();
    }

    @AfterEach
    public void afterEach() {
        context.after();
    }

    @Test
    public void close() {
        context.session.close();
    }

    @Test
    public void isRemote() {
        assertFalse(context.session.isRemote());
    }

    @Test
    public void getObjectPath() {
        assertTrue(context.session.getObjectPath().startsWith(Static.ObjectPaths.SESSION + "/s"));
    }

}
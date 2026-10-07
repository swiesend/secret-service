package de.swiesend.secretservice;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The tests run inside the library's own module, so they are subject to its module rules -- for
 * example the {@code opens} that dbus-java needs to reach the exported objects.
 *
 * <p>Surefire falls back to the class path without a warning when it cannot read
 * {@code module-info.class}. Version 3.5.2 could not read Java 25 class files, and the tests ran in
 * the unnamed module from the move to release 25 on, where no module rule applies.</p>
 */
class ModulePathTest {

    @Test
    void theTestsRunInTheLibrarysModule() {
        assertEquals("de.swiesend.secretservice", getClass().getModule().getName(),
                "surefire ran the tests on the class path, so the module rules go untested");
    }
}

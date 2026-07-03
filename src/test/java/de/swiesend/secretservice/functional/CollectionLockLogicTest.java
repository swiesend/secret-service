package de.swiesend.secretservice.functional;

import org.freedesktop.dbus.DBusPath;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pure unit tests (no D-Bus daemon) for the decision helpers behind the response-aware
 * {@link Collection#lock()}. These cover the branch conditions that the integration tests cannot
 * reach: gnome-keyring locks synchronously and never returns a prompt for a lock, so the
 * {@code requiresPrompt(...)==true} and {@code containsPath(...)==false} cases -- and thus the
 * prompt-required and "neither" branches of {@code lock()} -- are never exercised against a live
 * provider.
 */
class CollectionLockLogicTest {

    // ---- containsPath: drives the "collection was locked immediately" branch ----

    @Test
    void containsPath_nullList_isFalse() {
        assertFalse(Collection.containsPath(null, "/org/freedesktop/secrets/collection/test"));
    }

    @Test
    void containsPath_noMatch_isFalse() {
        List<DBusPath> locked = List.of(new DBusPath("/org/freedesktop/secrets/collection/other"));
        assertFalse(Collection.containsPath(locked, "/org/freedesktop/secrets/collection/test"));
    }

    @Test
    void containsPath_match_isTrue() {
        List<DBusPath> locked = List.of(
                new DBusPath("/org/freedesktop/secrets/collection/other"),
                new DBusPath("/org/freedesktop/secrets/collection/test"));
        assertTrue(Collection.containsPath(locked, "/org/freedesktop/secrets/collection/test"));
    }

    @Test
    void containsPath_ignoresNullElements() {
        List<DBusPath> locked = Arrays.asList(
                null, new DBusPath("/org/freedesktop/secrets/collection/test"));
        assertTrue(Collection.containsPath(locked, "/org/freedesktop/secrets/collection/test"));
    }

    // ---- requiresPrompt: drives the "locking needs a prompt" branch ----

    @Test
    void requiresPrompt_null_isFalse() {
        assertFalse(Collection.requiresPrompt(null));
    }

    @Test
    void requiresPrompt_sentinelSlash_isFalse() {
        // "/" is the Secret Service "no prompt required" sentinel.
        assertFalse(Collection.requiresPrompt(new DBusPath("/")));
    }

    @Test
    void requiresPrompt_realPromptPath_isTrue() {
        assertTrue(Collection.requiresPrompt(new DBusPath("/org/freedesktop/secrets/prompt/p1")));
    }

    // ---- awaitUntil: bounded poll used by the happy path ----

    @Test
    void awaitUntil_trueImmediately_returnsWithoutWaiting() {
        long start = java.lang.System.nanoTime();
        assertTrue(Collection.awaitUntil(() -> true));
        long elapsedMillis = (java.lang.System.nanoTime() - start) / 1_000_000L;
        // Must short-circuit on the first check (no DEFAULT_DELAY_MILLIS sleep).
        assertTrue(elapsedMillis < 100, "awaitUntil must return immediately when already satisfied");
    }
}

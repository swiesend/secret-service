package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.functional.SecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import de.swiesend.secretservice.integration.test.Dialogs;
import org.freedesktop.dbus.interfaces.DBus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The unlock dialog of gnome-keyring that nobody answers in time stays on the screen, and
 * gnome-keyring keeps running: before 51 it aborts when a client dismisses an unlock prompt whose
 * dialog is open, as the library did at its timeout. In the gnome-keyring-dialogs container, whose
 * answerer the test holds back as a user who is away, on the container's own login keyring.
 */
@EnabledIfSystemProperty(named = Dialogs.ANSWERED, matches = "true",
        disabledReason = "Locks the user's default collection, which only its password dialog unlocks again")
@EnabledIfSystemProperty(named = Dialogs.DEFAULT_COLLECTION, matches = "throwaway",
        disabledReason = Dialogs.NOT_A_THROWAWAY_KEYRING)
@EnabledIfEnvironmentVariable(named = Dialogs.CONTROL, matches = ".+",
        disabledReason = Dialogs.NO_ANSWERER_TO_CONTROL)
class GnomeKeyringUnlockDialogTest {

    @Test
    void anUnlockDialogThatNobodyAnswersInTimeStaysOpenAndGnomeKeyringKeepsRunning() throws Exception {
        try (ServiceInterface service = SecretService.create().orElseThrow();
             SessionInterface session = service.openSession().orElseThrow();
             CollectionInterface login = session.defaultCollection().orElseThrow()) {
            String item = login.createItem("unlock dialog", "secret").orElseThrow();
            try {
                String daemon = secretsOwner(service);
                service.setTimeout(Duration.ofSeconds(3));
                assertTrue(login.lock());

                Dialogs.hold();
                try {
                    assertEquals(Optional.empty(), login.getSecret(item), "nobody answered the dialog in time");
                } finally {
                    Dialogs.release();
                }

                assertEquals(daemon, secretsOwner(service), "the gnome-keyring that served the secrets still runs");
                assertTrue(unlockedWithin(login, Duration.ofSeconds(15)),
                        "the dialog stayed open, and the answer that it got now unlocked the collection");
                char[] secret = login.getSecret(item).orElseThrow();
                assertArrayEquals("secret".toCharArray(), secret);
                Arrays.fill(secret, '\0');
            } finally {
                service.setTimeout(Duration.ofSeconds(120));
                login.deleteItem(item);
            }
        }
    }

    /** The unique name of the connection that serves the secrets: a daemon started again has another. */
    private static String secretsOwner(ServiceInterface service) throws Exception {
        return ((SecretService) service).getService().getConnection()
                .getRemoteObject("org.freedesktop.DBus", "/org/freedesktop/DBus", DBus.class)
                .GetNameOwner("org.freedesktop.secrets");
    }

    private static boolean unlockedWithin(CollectionInterface collection, Duration timeout) throws InterruptedException {
        long deadline = java.lang.System.nanoTime() + timeout.toNanos();
        while (collection.isLocked() && java.lang.System.nanoTime() < deadline) {
            Thread.sleep(200);
        }
        return !collection.isLocked();
    }
}

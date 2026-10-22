package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.Collection;
import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.Item;
import de.swiesend.secretservice.Pair;
import de.swiesend.secretservice.Prompt;
import de.swiesend.secretservice.ProviderBug;
import de.swiesend.secretservice.Secret;
import de.swiesend.secretservice.Service;
import de.swiesend.secretservice.Static;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.types.Variant;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Each bug that {@link FakeSecretService} reproduces on request gives the answers that the provider
 * with the bug gives, as observed there or read from its code: a test that turns one on checks the
 * library against the provider, not against a guess. Through the low-level API, call by call.
 */
class ProviderBugReproductionTest {

    private static final DBusPath COLLECTION = new DBusPath(FakeSecretService.COLLECTION_PATH);

    private final FakeProviderFixture harness = new FakeProviderFixture();
    private FakeSecretService fake;
    private Service service;
    private Prompt prompt;

    @BeforeEach
    void start() throws Exception {
        Assumptions.assumeTrue(FakeProviderFixture.dbusDaemonAvailable(),
                "dbus-daemon is not on the PATH");
        harness.start(false);
        fake = harness.fake();
        service = harness.service().getService();
        // Receives every Completed signal on the bus from here on.
        prompt = new Prompt(service);
    }

    @AfterEach
    void stop() {
        if (prompt != null) prompt.getSignalHandler().disconnect();
        harness.stop();
    }

    // ---- gnome-keyring -----------------------------------------------------------------------

    @Test
    void gnomeKeyringBefore51AbortsWhenTheUnlockDialogOnTheScreenIsDismissed() {
        fake.reproduce(ProviderBug.GNOME_KEYRING_ABORTS_ON_A_DISMISSED_UNLOCK_DIALOG);
        DBusPath unlock = shownUnlockPrompt();

        assertFalse(prompt.dismiss(unlock), "the daemon dies before it replies");

        assertTrue(fake.hasAborted());
        assertTrue(service.unlock(List.of(COLLECTION)).isEmpty(), "and answers no call any more");
    }

    @Test
    void gnomeKeyringAbortsWhenAnUnlockPromptThatWaitsBehindTheDialogIsDismissed() {
        fake.reproduce(ProviderBug.GNOME_KEYRING_ABORTS_ON_A_DISMISSED_WAITING_UNLOCK);
        shownUnlockPrompt();
        DBusPath waiting = unlockPrompt();
        prompt.prompt(waiting);

        assertFalse(prompt.dismiss(waiting));

        assertTrue(fake.hasAborted());
    }

    @Test
    void gnomeKeyringAbortsWhenAnUnlockPromptThatWasNeverShownIsDismissedWhileTheDialogShows() {
        fake.reproduce(ProviderBug.GNOME_KEYRING_ABORTS_ON_A_DISMISSED_WAITING_UNLOCK);
        shownUnlockPrompt();
        DBusPath unshown = unlockPrompt();

        assertFalse(prompt.dismiss(unshown));

        assertTrue(fake.hasAborted());
    }

    @Test
    void withoutADialogOnTheScreenADismissedUnlockPromptAbortsNothing() throws Exception {
        fake.reproduce(ProviderBug.GNOME_KEYRING_ABORTS_ON_A_DISMISSED_UNLOCK_DIALOG,
                ProviderBug.GNOME_KEYRING_ABORTS_ON_A_DISMISSED_WAITING_UNLOCK);
        fake.lockCollection();
        fake.setRequirePromptForCollectionUnlock(true);
        DBusPath unshown = unlockPrompt();

        assertTrue(prompt.dismiss(unshown));

        assertFalse(fake.hasAborted());
        assertTrue(completedOn(unshown).dismissed);
    }

    @Test
    void gnomeKeyring51LeavesTheDialogOfADismissedUnlockPromptAndStrandsThePromptThatWaits() throws Exception {
        fake.reproduce(ProviderBug.GNOME_KEYRING_STRANDS_THE_UNLOCKS_BEHIND_A_DISMISSED_DIALOG);
        DBusPath first = shownUnlockPrompt();
        DBusPath second = unlockPrompt();
        prompt.prompt(second);

        assertTrue(prompt.dismiss(first));
        assertTrue(completedOn(first).dismissed);
        assertTrue(fake.hasPendingPrompt(), "the dismissed prompt's dialog stays on the screen");

        fake.approvePendingPrompt();

        assertFalse(fake.isCollectionLocked(), "the answer to it unlocks the collection");
        assertNull(completedWithin(second, 500), "the prompt that waited behind it never completes");
        assertFalse(fake.hasAborted());

        fake.lockCollection();
        DBusPath later = shownUnlockPrompt();
        fake.approvePendingPrompt();
        assertFalse(completedOn(later).dismissed, "a prompt that comes later works");
    }

    @Test
    void gnomeKeyringGivesEverySecretAsTextPlain() throws Exception {
        fake.reproduce(ProviderBug.GNOME_KEYRING_GIVES_EVERY_SECRET_AS_TEXT_PLAIN);
        fake.setSecretContentType("application/octet-stream");

        assertEquals("text/plain", readSecret().getContentType());
    }

    // ---- KeePassXC ---------------------------------------------------------------------------

    @Test
    void keePassXcTakesTheItemsOfALockedDatabaseOffTheBus() {
        fake.reproduce(ProviderBug.KEEPASSXC_HIDES_THE_ITEMS_OF_A_LOCKED_DATABASE);
        fake.lockCollection();

        Pair<List<DBusPath>, List<DBusPath>> found = service.searchItems(Map.of("k", "v")).orElseThrow();
        assertEquals(List.of(), found.a, "no unlocked item");
        assertEquals(List.of(), found.b, "and no locked one");
        assertEquals(Optional.of(List.of()), new Collection(COLLECTION, harness.clientConnection()).getItems());
        assertTrue(new Item(new DBusPath(FakeSecretService.ITEM_PATH), service).getLabel().isEmpty(),
                "the item is no object");
    }

    @Test
    void keePassXcFindsNothingForAnEmptySearch() {
        fake.reproduce(ProviderBug.KEEPASSXC_AN_EMPTY_SEARCH_FINDS_NOTHING);

        assertEquals(List.of(), service.searchItems(Map.of()).orElseThrow().a);
        assertEquals(List.of(FakeSecretService.ITEM_PATH),
                service.searchItems(Map.of("k", "v")).orElseThrow().a.stream().map(DBusPath::getPath).toList(),
                "a search with an attribute finds the item");
    }

    @Test
    void keePassXcDropsTheCharset() throws Exception {
        fake.reproduce(ProviderBug.KEEPASSXC_DROPS_THE_CHARSET);
        fake.setSecretContentType("text/plain; charset=iso-8859-1");

        assertEquals("text/plain", readSecret().getContentType());
    }

    // ---- KWallet -----------------------------------------------------------------------------

    @Test
    void kWalletBefore625RefusesAPublicKeyOfFewerThan128Bytes() {
        fake.reproduce(ProviderBug.KWALLET_REFUSES_A_SHORT_PUBLIC_KEY);
        byte[] two = new byte[128];
        two[127] = 2;

        assertTrue(openSession(new byte[127]).isEmpty(), "127 bytes");
        assertTrue(openSession(two).isPresent(), "128 bytes");
    }

    @Test
    void kWalletRefusesToLockAClosedWallet() {
        fake.reproduce(ProviderBug.KWALLET_REFUSES_TO_LOCK_A_LOCKED_WALLET);
        fake.lockCollection();

        assertTrue(service.lock(List.of(COLLECTION)).isEmpty());
    }

    // ---- oo7 ---------------------------------------------------------------------------------

    @Test
    void oo7_0_6RefusesAContentTypeWithParameters() {
        fake.reproduce(ProviderBug.OO7_REFUSES_A_CONTENT_TYPE_WITH_PARAMETERS);
        Item item = new Item(new DBusPath(FakeSecretService.ITEM_PATH), service);

        assertFalse(item.setSecret(secret("text/plain; charset=utf-8")));
        assertTrue(item.setSecret(secret("text/plain")));
        assertTrue(item.setSecret(secret("application/octet-stream")));
    }

    @Test
    void oo7GivesNoReplyToACreateItemWithoutAttributes() {
        fake.reproduce(ProviderBug.OO7_PANICS_ON_CREATE_ITEM_WITHOUT_ATTRIBUTES);
        Collection collection = new Collection(COLLECTION, harness.clientConnection());
        long start = java.lang.System.nanoTime();

        Optional<Pair<DBusPath, DBusPath>> created = collection.createItem(
                Map.of(Item.LABEL, new Variant<>("new")), secret("text/plain"), false);

        assertTrue(created.isEmpty());
        long waited = (java.lang.System.nanoTime() - start) / 1_000_000;
        assertTrue(waited >= Static.DBus.MAX_DELAY_MILLIS - 100, "no reply: the wait for it ran out after " + waited + " ms");
    }

    @Test
    void oo7SendsNoCompletedForADismissedPrompt() throws Exception {
        fake.reproduce(ProviderBug.OO7_DISMISS_SENDS_NO_COMPLETED);
        DBusPath unlock = shownUnlockPrompt();

        assertTrue(prompt.dismiss(unlock));

        assertNull(completedWithin(unlock, 500), "no Completed");
        assertEquals(List.of(unlock.getPath()), fake.dismissCalls());
        assertFalse(fake.hasPendingPrompt());
    }

    // ---- helpers -----------------------------------------------------------------------------

    /** An unlock prompt of the collection, which the fake gives for it locked. */
    private DBusPath unlockPrompt() {
        DBusPath path = service.unlock(List.of(COLLECTION)).orElseThrow().b;
        assertTrue(path.getPath().startsWith("/org/freedesktop/secrets/prompt/u"), path.getPath());
        return path;
    }

    /** An unlock prompt of the locked collection, whose dialog the client has brought up. */
    private DBusPath shownUnlockPrompt() {
        fake.lockCollection();
        fake.setRequirePromptForCollectionUnlock(true);
        DBusPath path = unlockPrompt();
        assertTrue(prompt.prompt(path));
        assertTrue(fake.hasPendingPrompt(), "its dialog shows");
        return path;
    }

    private Optional<Pair<Variant<byte[]>, DBusPath>> openSession(byte[] publicKey) {
        return service.openSession(Static.Algorithm.DH_IETF1024_SHA256_AES128_CBC_PKCS7, new Variant<>(publicKey));
    }

    /** The item's secret as the fake sends it, through a session opened for the library's key. */
    private Secret readSecret() {
        return new Item(new DBusPath(FakeSecretService.ITEM_PATH), service)
                .getSecret(harness.service().openSession().orElseThrow().getSession().getPath())
                .orElseThrow();
    }

    /** A secret the fake takes without reading it: it decrypts no secret that it is sent. */
    private static Secret secret(String contentType) {
        return new Secret(new DBusPath(FakeSecretService.SESSION_PATH), new byte[16], new byte[16], contentType);
    }

    private Prompt.Completed completedOn(DBusPath path) throws InterruptedException {
        Prompt.Completed completed = completedWithin(path, 5_000);
        assertNotNull(completed, "Completed on " + path.getPath());
        return completed;
    }

    private Prompt.Completed completedWithin(DBusPath path, long millis) throws InterruptedException {
        long deadline = java.lang.System.nanoTime() + millis * 1_000_000L;
        Prompt.Completed completed;
        while ((completed = prompt.getSignalHandler().getLastHandledSignal(Prompt.Completed.class, path.getPath())) == null
                && java.lang.System.nanoTime() < deadline) {
            Thread.sleep(20);
        }
        return completed;
    }
}

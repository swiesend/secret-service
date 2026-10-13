package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.functional.ConsentPolicy;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static de.swiesend.secretservice.functional.ConsentPolicy.Operation.DELETE_MANY;
import static de.swiesend.secretservice.functional.ConsentPolicy.Operation.READ_ALL;
import static de.swiesend.secretservice.functional.ConsentPolicy.Requirement.PROVIDER_PROMPT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * What each consent policy asks before a bulk read or a delete, and what reaches the provider.
 *
 * <p>Against {@link FakeSecretService}, which counts the dialogs a user would have seen and records
 * every call. Unlocking a collection asks the user here, as on gnome-keyring: that is the dialog
 * {@code PROVIDER_PROMPT} relies on.</p>
 */
class ConsentGateTest {

    private final FakeProviderFixture harness = new FakeProviderFixture();
    private CollectionInterface collection;
    private FakeSecretService fake;

    @BeforeEach
    void start() throws Exception {
        Assumptions.assumeTrue(FakeProviderFixture.dbusDaemonAvailable(), "dbus-daemon is not on the PATH");
        collection = harness.start(false);
        fake = harness.fake();
        fake.setRequirePromptForCollectionUnlock(true);
    }

    @AfterEach
    void stop() {
        harness.stop();
    }

    @Test
    void noneAsksNobody() {
        assertEquals(ConsentPolicy.none(), collection.getConsentPolicy(), "none() is the default");

        assertTrue(collection.withSecrets(Map::size).isPresent());
        collection.deleteItem(FakeSecretService.ITEM_PATH);

        assertFalse(fake.hasItem(FakeSecretService.ITEM_PATH), "the item is deleted");
        assertTrue(fake.promptCalls().isEmpty(), "no dialog was shown");
        assertTrue(calls("Service.Lock").isEmpty(), "and nothing was locked to force one");
    }

    @Test
    void legacyShowsTheProvidersDialogOnceForTheLifeOfTheCollection() {
        collection.setConsentPolicy(ConsentPolicy.legacy());

        assertTrue(collection.withSecrets(Map::size).isPresent());
        assertEquals(1, fake.promptCalls().size(), "the bulk read forced the unlock dialog");
        assertEquals(1, calls("Service.Lock").size(), "by locking the collection first");

        assertTrue(collection.withSecrets(Map::size).isPresent());
        collection.deleteItem(FakeSecretService.ITEM_PATH);
        assertFalse(fake.hasItem(FakeSecretService.ITEM_PATH));
        assertEquals(1, fake.promptCalls().size(),
                "the one dialog covers every later operation that requires one");
    }

    @Test
    void aDismissedDialogRefusesTheBulkRead() {
        collection.setConsentPolicy(ConsentPolicy.legacy());
        fake.setDismissPrompts(true);

        assertEquals(Optional.empty(), collection.withSecrets(Map::size));
        assertEquals(1, fake.promptCalls().size(), "the user saw the dialog and refused it");
        assertTrue(calls("Item.GetSecret").isEmpty(), "no secret was read");
    }

    @Test
    void withoutAnUnlockDialogTheBulkReadIsRefusedAndTheDeleteGoesAhead() {
        // A provider that asks before it locks, as KeePassXC does, can never show the unlock dialog:
        // the library does not drive the lock prompt, so the collection stays unlocked. legacy()
        // refuses the bulk read then, and lets a delete go ahead, as 3.x did.
        fake.setRequirePromptForCollectionLock(true);
        collection.setConsentPolicy(ConsentPolicy.legacy());

        assertEquals(Optional.empty(), collection.withSecrets(Map::size));
        assertTrue(calls("Item.GetSecret").isEmpty(), "no secret was read");

        collection.deleteItem(FakeSecretService.ITEM_PATH);
        assertFalse(fake.hasItem(FakeSecretService.ITEM_PATH), "the delete went ahead");
        assertTrue(fake.promptCalls().isEmpty(), "and no dialog was shown");
    }

    @Test
    void aPolicyAsksOnlyForTheOperationsItNames() {
        String second = fake.addItem(FakeSecretService.COLLECTION_PATH, "second", "second-secret", Map.of());
        collection.setConsentPolicy(ConsentPolicy.none().require(DELETE_MANY, PROVIDER_PROMPT));

        assertTrue(collection.withSecrets(Map::size).isPresent());
        assertTrue(fake.promptCalls().isEmpty(), "this policy lets a bulk read through");

        collection.deleteItems(List.of(second, FakeSecretService.ITEM_PATH));
        assertEquals(1, fake.promptCalls().size(), "one dialog for the whole call, not one per item");
        assertFalse(fake.hasItem(second));
        assertFalse(fake.hasItem(FakeSecretService.ITEM_PATH));
    }

    @Test
    void aCallRefusedForItsPathsAsksNothing() {
        String foreign = fake.addItem(fake.addCollection("other"), "foreign", "foreign-secret", Map.of());
        collection.setConsentPolicy(ConsentPolicy.legacy());
        List<String> before = fake.calls();

        assertFalse(collection.deleteItems(List.of(FakeSecretService.ITEM_PATH, foreign)));

        assertEquals(before, fake.calls(), "the scope check comes before the consent");
        assertTrue(fake.promptCalls().isEmpty());
    }

    @Test
    void aRememberedConsentExpires() throws Exception {
        collection.setConsentPolicy(ConsentPolicy.none()
                .require(READ_ALL, PROVIDER_PROMPT)
                .remember(Duration.ofSeconds(1)));

        collection.withSecrets(Map::size);
        collection.withSecrets(Map::size);
        assertEquals(1, fake.promptCalls().size(), "within the remembered time, one dialog covers both");

        Thread.sleep(1_500);
        collection.withSecrets(Map::size);
        assertEquals(2, fake.promptCalls().size(), "after it, the next bulk read asks again");
    }

    @Test
    void aNewPolicyForgetsTheGrantedConsents() {
        collection.setConsentPolicy(ConsentPolicy.legacy());
        collection.withSecrets(Map::size);

        collection.setConsentPolicy(ConsentPolicy.legacy());
        collection.withSecrets(Map::size);

        assertEquals(2, fake.promptCalls().size());
    }

    private List<String> calls(String call) {
        return fake.calls().stream().filter(c -> c.startsWith(call + " ")).toList();
    }
}

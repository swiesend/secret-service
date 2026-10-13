package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.functional.ConsentPolicy;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.freedesktop.dbus.DBusPath;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static de.swiesend.secretservice.functional.ConsentPolicy.Operation.DELETE_COLLECTION;
import static de.swiesend.secretservice.functional.ConsentPolicy.Operation.DELETE_MANY;
import static de.swiesend.secretservice.functional.ConsentPolicy.Operation.DELETE_ONE;
import static de.swiesend.secretservice.functional.ConsentPolicy.Operation.READ_ALL;
import static de.swiesend.secretservice.functional.ConsentPolicy.Operation.READ_ONE;
import static de.swiesend.secretservice.functional.ConsentPolicy.Operation.WRITE;
import static de.swiesend.secretservice.functional.ConsentPolicy.Requirement.CALLBACK;
import static de.swiesend.secretservice.functional.ConsentPolicy.Requirement.PROVIDER_PROMPT;
import static de.swiesend.secretservice.functional.ConsentPolicy.WhenUnavailable.PROCEED;
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

    @Test
    void aHandlerSeesTheOperationTheCollectionAndTheItems() {
        String second = fake.addItem(FakeSecretService.COLLECTION_PATH, "second", "second-secret", Map.of());
        List<ConsentPolicy.Request> asked = new ArrayList<>();
        collection.setConsentPolicy(ConsentPolicy.none()
                .require(DELETE_MANY, CALLBACK)
                .handler(asked::add));

        collection.deleteItems(List.of(second, FakeSecretService.ITEM_PATH));

        assertEquals(List.of(new ConsentPolicy.Request(DELETE_MANY, FakeSecretService.COLLECTION_PATH,
                List.of(second, FakeSecretService.ITEM_PATH))), asked, "asked once, naming everything");
        assertFalse(fake.hasItem(second));
        assertFalse(fake.hasItem(FakeSecretService.ITEM_PATH));
        assertTrue(fake.promptCalls().isEmpty(), "the application asked, not the provider");
    }

    @Test
    void aHandlerThatSaysNoStopsTheCallBeforeAnythingIsSent() {
        collection.setConsentPolicy(ConsentPolicy.none().require(DELETE_ONE, CALLBACK).handler(request -> false));
        List<String> before = fake.calls();

        assertFalse(collection.deleteItem(FakeSecretService.ITEM_PATH));

        assertEquals(before, fake.calls(), "nothing reached the provider");
        assertTrue(fake.hasItem(FakeSecretService.ITEM_PATH));
    }

    @Test
    void aHandlerThatThrowsCountsAsNo() {
        collection.setConsentPolicy(ConsentPolicy.none().require(READ_ALL, CALLBACK).handler(request -> {
            throw new IllegalStateException("the dialog could not be shown");
        }));

        assertEquals(Optional.empty(), collection.withSecrets(Map::size));
        assertTrue(calls("Item.GetSecret").isEmpty(), "no secret was read");
    }

    @Test
    void withoutAHandlerACallbackCannotBeAnswered() {
        collection.setConsentPolicy(ConsentPolicy.none().require(READ_ALL, CALLBACK));
        assertEquals(Optional.empty(), collection.withSecrets(Map::size), "refused, by default");

        collection.setConsentPolicy(ConsentPolicy.none().require(READ_ALL, CALLBACK, PROCEED));
        assertTrue(collection.withSecrets(Map::size).isPresent(), "or let through, when the policy says so");
    }

    @Test
    void aHandlersAnswerCoversOnlyTheOperationItWasAskedAbout() {
        List<ConsentPolicy.Operation> asked = new ArrayList<>();
        collection.setConsentPolicy(ConsentPolicy.none()
                .require(READ_ALL, CALLBACK)
                .require(DELETE_ONE, CALLBACK)
                .handler(request -> asked.add(request.operation()))
                .remember(Duration.ofMinutes(1)));

        collection.withSecrets(Map::size);
        collection.withSecrets(Map::size);
        collection.deleteItem(FakeSecretService.ITEM_PATH);

        assertEquals(List.of(READ_ALL, DELETE_ONE), asked,
                "the read is remembered, and the delete is asked about anew");
    }

    @Test
    void singleReadsAndChangesAskOnlyWhenThePolicyNamesThem() {
        List<ConsentPolicy.Request> asked = new ArrayList<>();
        ConsentPolicy.Handler handler = asked::add;

        collection.setConsentPolicy(ConsentPolicy.none().handler(handler));
        collection.withSecret(FakeSecretService.ITEM_PATH, String::new);
        collection.setItemLabel(FakeSecretService.ITEM_PATH, "relabelled");
        collection.updateItem(FakeSecretService.ITEM_PATH, null, "changed", null);
        assertTrue(asked.isEmpty(), "none() asks about none of them");

        collection.setConsentPolicy(ConsentPolicy.none()
                .require(READ_ONE, CALLBACK)
                .require(WRITE, CALLBACK)
                .handler(handler));
        collection.withSecret(FakeSecretService.ITEM_PATH, String::new);
        collection.setItemLabel(FakeSecretService.ITEM_PATH, "relabelled again");
        collection.updateItem(FakeSecretService.ITEM_PATH, null, "changed again", null);

        List<String> item = List.of(FakeSecretService.ITEM_PATH);
        assertEquals(List.of(
                new ConsentPolicy.Request(READ_ONE, FakeSecretService.COLLECTION_PATH, item),
                new ConsentPolicy.Request(WRITE, FakeSecretService.COLLECTION_PATH, item),
                new ConsentPolicy.Request(WRITE, FakeSecretService.COLLECTION_PATH, item)), asked);
        assertEquals(Optional.of("changed again"), fake.secretOf(FakeSecretService.ITEM_PATH));
    }

    @Test
    void aBulkReadAsksOnceAndNotForEachItem() {
        fake.addItem(FakeSecretService.COLLECTION_PATH, "second", "second-secret", Map.of());
        List<ConsentPolicy.Operation> asked = new ArrayList<>();
        collection.setConsentPolicy(ConsentPolicy.none()
                .require(READ_ALL, CALLBACK)
                .require(READ_ONE, CALLBACK)
                .handler(request -> asked.add(request.operation())));

        assertEquals(Optional.of(2), collection.withSecrets(Map::size));

        assertEquals(List.of(READ_ALL), asked);
    }

    @Test
    void deletingTheWholeCollectionCanBeAskedAbout() {
        String path = fake.addCollection("deletable");
        CollectionInterface deletable = harness.session().collection("deletable", Optional.empty()).orElseThrow();

        deletable.setConsentPolicy(ConsentPolicy.none().require(DELETE_COLLECTION, CALLBACK).handler(request -> false));
        assertFalse(deletable.delete(), "refused");
        assertTrue(collectionPaths().contains(path), "and the collection is still there");

        deletable.setConsentPolicy(ConsentPolicy.none().require(DELETE_COLLECTION, CALLBACK).handler(request -> true));
        assertTrue(deletable.delete());
        assertFalse(collectionPaths().contains(path));
    }

    private List<String> collectionPaths() {
        return harness.rawService().getCollections().orElseThrow().stream().map(DBusPath::getPath).toList();
    }

    private List<String> calls(String call) {
        return fake.calls().stream().filter(c -> c.startsWith(call + " ")).toList();
    }
}

package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.Failure;
import de.swiesend.secretservice.Failure.Reason;
import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.Item;
import de.swiesend.secretservice.Result;
import de.swiesend.secretservice.Static;
import de.swiesend.secretservice.functional.ConsentPolicy;
import de.swiesend.secretservice.functional.SecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.TimeoutException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code withSecretChecked} says why a secret could not be read, where {@code withSecret} answers
 * {@code Optional.empty()} for every reason: one test per reason, against {@link FakeSecretService}.
 */
class WithSecretCheckedTest {

    private final FakeProviderFixture harness = new FakeProviderFixture();

    @BeforeEach
    void requireDbus() {
        Assumptions.assumeTrue(FakeProviderFixture.dbusDaemonAvailable(),
                "dbus-daemon is not on the PATH");
    }

    @AfterEach
    void stop() {
        if (harness.fake() != null) harness.fake().setStallSecrets(false);
        harness.stop();
    }

    private static Result<String> read(CollectionInterface collection, String path) {
        return collection.withSecretChecked(path, String::new);
    }

    private static Reason reasonOf(Result<?> result) {
        return result.reason().orElseThrow(() -> new AssertionError("the read succeeded"));
    }

    @Test
    void aSecretReachesTheCallback() throws Exception {
        CollectionInterface collection = harness.start(false);

        assertEquals(Result.ok(FakeSecretService.SECRET_VALUE), read(collection, FakeSecretService.ITEM_PATH));
        assertEquals(Optional.of(FakeSecretService.SECRET_VALUE),
                collection.withSecret(FakeSecretService.ITEM_PATH, String::new), "withSecret answers the same");
    }

    @Test
    void aCallbackWithoutAResultIsASuccessWithoutAValue() throws Exception {
        CollectionInterface collection = harness.start(false);

        Result<String> read = collection.withSecretChecked(FakeSecretService.ITEM_PATH, secret -> null);

        assertTrue(read.isOk());
        assertEquals(Optional.empty(), read.value());
    }

    @Test
    void anEmptyPathOrAnItemOfAnotherCollectionIsAnInvalidArgument() throws Exception {
        CollectionInterface collection = harness.start(false);

        assertEquals(Reason.INVALID_ARGUMENT, reasonOf(read(collection, "")));
        assertEquals(Reason.INVALID_ARGUMENT, reasonOf(read(collection, "/org/freedesktop/secrets/collection/other/1")));
    }

    @Test
    void aReadThatTheConsentPolicyRefusesIsDenied() throws Exception {
        CollectionInterface collection = harness.start(false);
        collection.setConsentPolicy(ConsentPolicy.none()
                .require(ConsentPolicy.Operation.READ_ONE, ConsentPolicy.Requirement.CALLBACK)
                .handler(request -> false));

        assertEquals(Reason.DENIED, reasonOf(read(collection, FakeSecretService.ITEM_PATH)));
    }

    @Test
    void aLockedItemWithPromptingDisabledIsLocked() throws Exception {
        CollectionInterface collection = harness.start(true);
        collection.disablePrompt();

        assertEquals(Reason.LOCKED, reasonOf(read(collection, FakeSecretService.ITEM_PATH)));
    }

    @Test
    void anUnlockDialogThatTheUserDismissesIsDismissed() throws Exception {
        CollectionInterface collection = harness.start(true);
        harness.fake().setDismissPrompts(true);

        assertEquals(Reason.DISMISSED, reasonOf(read(collection, FakeSecretService.ITEM_PATH)));
    }

    @Test
    void anUnlockDialogThatNobodyAnswersTimedOut() throws Exception {
        CollectionInterface collection = harness.start(true);
        harness.fake().setLeavePromptsOpen(true);
        harness.session().getService().setTimeout(Duration.ofSeconds(1));

        assertEquals(Reason.TIMED_OUT, reasonOf(read(collection, FakeSecretService.ITEM_PATH)));
    }

    @Test
    void aSecretThatComesTooLateTimedOut() throws Exception {
        CollectionInterface collection = harness.start(false);
        harness.fake().setStallSecrets(true);

        Failure failure = read(collection, FakeSecretService.ITEM_PATH).failure().orElseThrow();

        assertEquals(Reason.TIMED_OUT, failure.reason());
        assertInstanceOf(TimeoutException.class, failure.cause());
    }

    @Test
    void aDeletedItemIsNotFound() throws Exception {
        CollectionInterface collection = harness.start(false);
        // Through the low-level Item: on this base the functional deleteItem answers false for a
        // delete that needed no prompt, unless gnome-keyring's own bus name is on the bus.
        assertTrue(new Item(Static.Convert.toObjectPath(FakeSecretService.ITEM_PATH), harness.rawService())
                .delete().isPresent());

        assertEquals(Reason.NOT_FOUND, reasonOf(read(collection, FakeSecretService.ITEM_PATH)));
    }

    @Test
    void aReadOnAClosedConnectionIsDisconnected() throws Exception {
        harness.start(false);
        // A connection of its own: the fixture's is shared with the fake's, and closing a shared
        // connection only counts down its users.
        DBusConnection own = harness.connectAnother();
        ServiceInterface service = SecretService.create(
                Optional.of(de.swiesend.secretservice.functional.System.wrap(own))).orElseThrow();
        CollectionInterface collection = service.openSession().orElseThrow()
                .collection(FakeSecretService.COLLECTION_LABEL, Optional.empty()).orElseThrow();
        own.disconnect();

        Failure failure = read(collection, FakeSecretService.ITEM_PATH).failure().orElseThrow();

        assertEquals(Reason.DISCONNECTED, failure.reason(),
                "error " + failure.errorName() + ", cause " + failure.cause());
    }
}

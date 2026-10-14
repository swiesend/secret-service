package de.swiesend.secretservice.integration;

import de.swiesend.secretservice.FakeSecretService;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * KeePassXC answers every {@code CreateItem} with a prompt. {@code createItem()} called it even
 * after {@code disablePrompt()}, waited for it with the default timeout of 120 seconds instead of
 * the configured one, and, after the user had refused to unlock the collection, asked again
 * through the prompt of {@code CreateItem}.
 *
 * <p>Against {@link FakeSecretService}, which creates items through a prompt as KeePassXC does.</p>
 */
class CreateItemPromptTest {

    private static final Duration LONG_BEFORE_THE_DEFAULT_TIMEOUT = Duration.ofSeconds(15);

    private final FakeProviderFixture harness = new FakeProviderFixture();

    @BeforeEach
    void requireDbus() {
        Assumptions.assumeTrue(FakeProviderFixture.dbusDaemonAvailable(),
                "dbus-daemon is not on the PATH");
    }

    @AfterEach
    void stop() {
        harness.stop();
    }

    @Test
    void createItemCompletesThroughThePrompt() throws Exception {
        CollectionInterface collection = harness.start(false);
        Thread approver = approveWhenPrompted(harness.fake());

        assertEquals(Optional.of(FakeSecretService.CREATED_ITEM_PATH), collection.createItem("new", "secret"),
                "the item path comes from the prompt's result, where KeePassXC reports it");
        approver.join(5_000);
    }

    @Test
    void createItemDismissesThePromptWhenPromptingIsDisabled() throws Exception {
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        assertTrue(collection.disablePrompt());

        Optional<String> created = assertTimeoutPreemptively(LONG_BEFORE_THE_DEFAULT_TIMEOUT,
                () -> collection.createItem("new", "secret"),
                "a prompt the caller opted out of is not waited for");

        assertTrue(created.isEmpty(), "nobody answered the prompt, so there is no item");
        assertEquals(List.of("new"), fake.createItemCalls());
    }

    @Test
    void createItemStopsWhenTheCollectionStaysLocked() throws Exception {
        CollectionInterface collection = harness.start(false);
        FakeSecretService fake = harness.fake();
        fake.lockCollection();
        fake.setRefuseCollectionUnlock(true);

        Optional<String> created = assertTimeoutPreemptively(LONG_BEFORE_THE_DEFAULT_TIMEOUT,
                () -> collection.createItem("new", "secret"));

        assertTrue(created.isEmpty(), "the collection stayed locked, so there is no item");
        assertEquals(List.of(), fake.createItemCalls(),
                "and CreateItem, whose prompt would ask to unlock it again, was not sent");
    }

    /** Answers the provider's prompt from another thread, as the user would. */
    private static Thread approveWhenPrompted(FakeSecretService fake) {
        Thread approver = new Thread(() -> {
            try {
                long deadline = java.lang.System.nanoTime() + 5_000_000_000L;
                while (!fake.hasPendingPrompt() && java.lang.System.nanoTime() < deadline) {
                    Thread.sleep(20);
                }
                if (fake.hasPendingPrompt()) {
                    fake.approvePendingPrompt();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }, "approver");
        approver.setDaemon(true);
        approver.start();
        return approver;
    }
}

package de.swiesend.secretservice.tools.gui;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.UIManager;
import java.awt.GraphicsEnvironment;
import java.awt.Rectangle;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Uses the window as a developer does, against a real provider: it creates a collection of its
 * own, creates an item, reads and finds it, opens the collection again by its id, deletes the item
 * and deletes the collection. Each step leaves a screenshot in {@link Gui#SCREENSHOTS}.
 *
 * <p>The window changes the keyring it is connected to, and deleting an item from a collection
 * that the window opened without its password asks through the provider's unlock dialog. So the
 * test runs only where the keyring is the run's own and someone
 * answers its dialogs, as in the {@code gnome-keyring-dialogs} container, whose dialogs take the
 * password {@code test}. The two system properties say so; they are the ones that enable the
 * library's system tests on the default collection.</p>
 * <pre>{@code
 *   docker build -f .github/providers/gnome-keyring-dialogs/Dockerfile -t secret-service-gui-test .
 *   docker run --rm -v "$(pwd)":/workspace secret-service-gui-test bash -c '
 *     mvn -B -q -DskipTests -Dgpg.skip=true install &&
 *     mvn -B -f tools/gui/pom.xml test -Dsecret-service.system-test.dialogs-answered=true \
 *       -Dsecret-service.system-test.default-collection=throwaway'
 * }</pre>
 */
@EnabledIfSystemProperty(named = GuiSmokeTest.DIALOGS_ANSWERED, matches = "true",
        disabledReason = "Deletes an item through the provider's unlock dialog, which needs a user")
@EnabledIfSystemProperty(named = GuiSmokeTest.DEFAULT_COLLECTION, matches = "throwaway",
        disabledReason = "Changes the keyring of the session that it runs in")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class GuiSmokeTest {

    /** {@code true} where each dialog of the provider is answered. */
    static final String DIALOGS_ANSWERED = "secret-service.system-test.dialogs-answered";

    /** {@code throwaway} where the keyring belongs to the run. */
    static final String DEFAULT_COLLECTION = "secret-service.system-test.default-collection";

    /**
     * The environment variable with the directory through which the test holds back the
     * container's dialog answerer, as a user who is away: while the file {@code hold} is in it, the
     * answerer leaves the dialogs open.
     */
    static final String DIALOG_CONTROL = "SECRET_SERVICE_DIALOG_CONTROL";

    /** How long the event thread may take for a task: longer, and the window stops answering. */
    private static final Duration RESPONSIVE = Duration.ofMillis(500);

    /** The password of the test's collection, which the container's answerer types into the unlock dialog. */
    private static final String PASSWORD = "test";

    /** A label that is its own id at every provider, so the window names the collection by it alone. */
    private final String collection = "guismoke" + UUID.randomUUID().toString().substring(0, 8);
    private final CountDownLatch closed = new CountDownLatch(1);
    private JFrame frame;

    @BeforeAll
    void showTheWindow() {
        assertFalse(GraphicsEnvironment.isHeadless(), "the test needs a display");
        frame = Gui.onEventThread(() -> SecretServiceGui.show(closed));
        Gui.await("the window shows", frame::isShowing);
    }

    @AfterAll
    void closeTheWindow() throws InterruptedException {
        if (frame == null) return;
        Gui.onEventThread(() -> {
            frame.dispose();
            return null;
        });
        assertTrue(closed.await(Gui.PATIENCE.toSeconds(), TimeUnit.SECONDS), "the window closes");
    }

    private String log() {
        JTextArea log = Gui.find(JTextArea.class, "log");
        return Gui.onEventThread(log::getText);
    }

    private int items() {
        JList<?> items = Gui.find(JList.class, "items");
        return Gui.onEventThread(() -> items.getModel().getSize());
    }

    private String label(String name) {
        JLabel label = Gui.find(JLabel.class, name);
        return Gui.onEventThread(label::getText);
    }

    private boolean enabled(String button) {
        JButton found = Gui.find(JButton.class, button);
        return Gui.onEventThread(found::isEnabled);
    }

    @Test
    @Order(1)
    @DisplayName("the window fits the screen and shows the item list and the log")
    void fitsTheScreen() {
        Rectangle screen = Gui.onEventThread(() -> frame.getGraphicsConfiguration().getBounds());
        Rectangle window = Gui.onEventThread(frame::getBounds);
        assertTrue(screen.contains(window), "the window " + window + " is within the screen " + screen);
        assertTrue(scrollPaneHeight(Gui.find(JList.class, "items")) >= 80, "the item list shows a few lines");
        assertTrue(scrollPaneHeight(Gui.find(JTextArea.class, "log")) >= 80, "the log shows a few lines");
    }

    private static int scrollPaneHeight(JComponent view) {
        return Gui.onEventThread(() -> SwingUtilities.getAncestorOfClass(JScrollPane.class, view).getHeight());
    }

    @Test
    @Order(2)
    @DisplayName("the window starts disconnected")
    void startsDisconnected() {
        assertTrue(enabled("connect"), "Connect is enabled");
        assertFalse(enabled("disconnect"), "Disconnect is disabled");
        assertFalse(enabled("create-item"), "Create is disabled");
        Gui.screenshot("start");
    }

    @Test
    @Order(3)
    @DisplayName("Connect creates the collection and opens it")
    void connects() {
        Gui.type("collection-id", "");
        Gui.type("collection-label", collection);
        Gui.type("collection-password", PASSWORD);
        Gui.click("connect");
        Gui.await("the collection is open", () -> enabled("disconnect"));

        assertTrue(log().contains("Connected to collection label=\"" + collection + "\""), log());
        assertEquals("Connected", label("connection-status"));
        assertEquals(0, items());
        Gui.screenshot("connected");
    }

    @Test
    @Order(4)
    @DisplayName("Create stores an item, and the list shows it")
    void createsAnItem() {
        Gui.type("item-label", "smoke item");
        Gui.type("item-secret", "s3cret");
        Gui.type("item-attribute-key", "purpose");
        Gui.type("item-attribute-value", "smoke");
        Gui.click("create-item");
        Gui.await("the list shows the item", () -> items() == 1);
        Gui.screenshot("item-created");
    }

    @Test
    @Order(5)
    @DisplayName("selecting the item shows its label and attributes, and Read Secret its secret")
    void readsTheItem() {
        JList<?> items = Gui.find(JList.class, "items");
        Gui.onEventThread(() -> {
            items.setSelectedIndex(0);
            return null;
        });
        Gui.await("the detail shows the label", () -> "smoke item".equals(label("detail-label")));
        JTable attributes = Gui.find(JTable.class, "detail-attributes");
        assertEquals("purpose", Gui.onEventThread(() -> attributes.getValueAt(0, 0)));
        assertEquals("smoke", Gui.onEventThread(() -> attributes.getValueAt(0, 1)));
        assertEquals("********", label("detail-secret"), "the secret is hidden until it is asked for");

        Gui.click("read-secret");
        Gui.await("the detail shows the secret", () -> "s3cret".equals(label("detail-secret")));
        Gui.screenshot("item-read");
    }

    @Test
    @Order(6)
    @DisplayName("Search narrows the list, and List All shows every item again")
    void searches() {
        Gui.type("search", "no item has this name");
        Gui.click("search-items");
        Gui.await("the list is empty", () -> items() == 0);

        Gui.type("search", "smoke item");
        Gui.click("search-items");
        Gui.await("the list shows the match", () -> items() == 1);

        Gui.type("search", "no item has this name");
        Gui.click("search-items");
        Gui.await("the list is empty", () -> items() == 0);
        Gui.click("list-items");
        Gui.await("the list shows every item", () -> items() == 1);
    }

    @Test
    @Order(7)
    @DisplayName("Connect opens the collection by its id, without its password")
    void reconnectsById() {
        Gui.click("disconnect");
        Gui.await("the window is disconnected", () -> enabled("connect"));
        assertEquals(0, items());

        // Connect filled in the id: the window opens the collection by it, and gnome-keyring
        // learns no password, so that it asks through its unlock dialog.
        assertEquals(collection, Gui.onEventThread(() -> Gui.find(JTextField.class, "collection-id").getText()));
        Gui.type("collection-password", "");
        Gui.click("connect");
        Gui.await("the collection is open", () -> enabled("disconnect"));
        assertTrue(log().contains("Opening collection by id: " + collection), log());
        Gui.click("list-items");
        Gui.await("the list shows the item", () -> items() == 1);
    }

    @Test
    @Order(8)
    @DisplayName("the window answers while the provider's dialog waits, and Cancel gives up the wait")
    void staysResponsiveWhileTheProviderAsks() throws IOException {
        String control = System.getenv(DIALOG_CONTROL);
        Assumptions.assumeTrue(control != null, "Needs the dialog answerer of the gnome-keyring-dialogs container");
        Path hold = Path.of(control, "hold");
        JList<?> items = Gui.find(JList.class, "items");
        Gui.onEventThread(() -> {
            items.setSelectedIndex(0);
            return null;
        });
        Gui.await("the detail shows the item", () -> "smoke item".equals(label("detail-label")));

        Files.writeString(hold, "");
        try {
            // Deleting asks for the user's permission through the unlock dialog, which waits.
            Gui.click("delete-item");
            Gui.answer("Confirm Delete Item", UIManager.getString("OptionPane.yesButtonText"));
            Gui.await("the provider's dialog shows", Gui::providerDialogShows);

            assertTrue(label("status").startsWith("Delete item"), label("status"));
            assertTrue(enabled("cancel"), "Cancel is enabled while the call waits");
            assertFalse(enabled("delete-item"), "the item controls are disabled while the call waits");
            Duration pause = Gui.longestPause(Duration.ofSeconds(2));
            assertTrue(pause.compareTo(RESPONSIVE) < 0, "the event thread answers within " + pause.toMillis() + " ms");
            Gui.screenshot("dialog-waits");

            Gui.click("cancel");
            Gui.await("the call has given up", () -> "Ready".equals(label("status")));
            assertEquals(1, items(), "the item stays");
            assertTrue(log().contains("WARNING: deleteItem returned false"), log());
            assertTrue(log().contains("Delete item: cancelled."), log());
        } finally {
            // The unlock dialog of gnome-keyring stays open; the answerer answers it now.
            Files.deleteIfExists(hold);
        }
        Gui.await("the answerer has answered the dialog", () -> !Gui.providerDialogShows());
    }

    @Test
    @Order(9)
    @DisplayName("Delete Item asks, then deletes through the provider's unlock dialog")
    void deletesTheItem() {
        JList<?> items = Gui.find(JList.class, "items");
        Gui.onEventThread(() -> {
            items.setSelectedIndex(0);
            return null;
        });
        Gui.await("the detail shows the item", () -> "smoke item".equals(label("detail-label")));
        Gui.click("delete-item");
        Gui.answer("Confirm Delete Item", UIManager.getString("OptionPane.yesButtonText"));
        Gui.await("the list is empty", () -> items() == 0);
        assertTrue(log().contains("Deleted item: "), log());
        assertTrue(Gui.answeredDialogs() > 0, "the provider asked through its unlock dialog");
        Gui.screenshot("item-deleted");
    }

    @Test
    @Order(10)
    @DisplayName("Delete Collection asks, deletes the collection and disconnects")
    void deletesTheCollection() {
        Gui.click("delete-collection");
        Gui.answer("Confirm Delete Collection \"" + collection + "\"", UIManager.getString("OptionPane.yesButtonText"));
        Gui.await("the window is disconnected", () -> enabled("connect"));
        assertTrue(log().contains("Collection deleted."), log());
        assertEquals("Disconnected", label("connection-status"));
        Gui.screenshot("collection-deleted");
    }
}

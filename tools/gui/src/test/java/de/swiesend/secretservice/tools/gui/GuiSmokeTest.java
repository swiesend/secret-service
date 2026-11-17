package de.swiesend.secretservice.tools.gui;

import de.swiesend.secretservice.functional.Collection;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
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

import javax.swing.AbstractButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import java.awt.GraphicsEnvironment;
import java.awt.Rectangle;
import java.awt.Toolkit;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Uses the window as a developer does, against a real provider: it connects, creates a collection
 * of its own, creates an item, reads and finds it, opens the collection again from the list,
 * deletes the item, opens the default collection after the acknowledgement of its risk, and deletes
 * its own collection. Each step leaves a screenshot in {@link Gui#SCREENSHOTS}.
 *
 * <p>The window changes the keyring it is connected to, opens the default collection, and
 * deleting an item from a collection that the window opened without its password asks through the
 * provider's unlock dialog. So the test runs only where the keyring is the run's own and someone
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

    /** The container's login keyring, which the default alias names. */
    private static final String LOGIN = "Login [login] (default)";

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
        JTable items = Gui.find(JTable.class, "items");
        return Gui.onEventThread(items::getRowCount);
    }

    private String label(String name) {
        JLabel label = Gui.find(JLabel.class, name);
        return Gui.onEventThread(label::getText);
    }

    private boolean showing(String name) {
        JComponent component = Gui.find(JComponent.class, name);
        return Gui.onEventThread(component::isShowing);
    }

    private boolean enabled(String button) {
        AbstractButton found = Gui.find(AbstractButton.class, button);
        return Gui.onEventThread(found::isEnabled);
    }

    private void selectFirstItem() {
        JTable items = Gui.find(JTable.class, "items");
        Gui.onEventThread(() -> {
            items.setRowSelectionInterval(0, 0);
            return null;
        });
        Gui.selectTab("item-tabs", "Selected item");
        Gui.await("the detail shows the item", () -> "smoke item".equals(label("detail-label")));
    }

    /** Opens the collection of the list, which is no default one. */
    private void openFromTheList(String name) {
        Gui.selectRow("collections", name);
        Gui.click("open-collection");
        Gui.await("the collection is open", () -> label("open-collection-name").equals("Open: " + name));
    }

    @Test
    @Order(1)
    @DisplayName("the window fits the screen and shows the item list and the log")
    void fitsTheScreen() {
        Rectangle screen = Gui.onEventThread(() -> frame.getGraphicsConfiguration().getBounds());
        Rectangle window = Gui.onEventThread(frame::getBounds);
        assertTrue(screen.contains(window), "the window " + window + " is within the screen " + screen);
        assertTrue(scrollPaneHeight(Gui.find(JTable.class, "items")) >= 80, "the item list shows a few lines");
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
        assertFalse(enabled("create-collection"), "a collection is created only once connected");
        assertFalse(enabled("create-item"), "Create is disabled");
        Gui.screenshot("start");
    }

    @Test
    @Order(3)
    @DisplayName("Connect lists the provider's collections and opens none")
    void connects() {
        Gui.click("connect");
        Gui.await("the window is connected", () -> enabled("disconnect"));
        assertEquals("Connected", label("connection-status"));
        assertTrue(Gui.firstColumn("collections").contains(LOGIN), String.valueOf(Gui.firstColumn("collections")));
        assertEquals("No collection is open.", label("open-collection-name"));
        assertFalse(enabled("create-item"), "no item is created without a collection");
        assertFalse(enabled("open-collection"), "Open waits for a selection");
    }

    @Test
    @Order(4)
    @DisplayName("the log shows the library's log from the level that is chosen")
    void showsTheLibrarysLog() {
        JComboBox<?> level = Gui.find(JComboBox.class, "log-level");
        Gui.onEventThread(() -> {
            level.setSelectedItem(LibraryLog.Threshold.DEBUG);
            return null;
        });
        Gui.click("refresh-collections");
        Gui.await("the library's debug log shows", () -> log().contains("lib DEBUG "));
        Gui.onEventThread(() -> {
            level.setSelectedItem(LibraryLog.Threshold.INFO);
            return null;
        });
    }

    @Test
    @Order(5)
    @DisplayName("Create / open creates the collection with its password and opens it")
    void createsTheCollection() {
        Gui.type("collection-label", collection);
        Gui.type("collection-password", PASSWORD);
        Gui.click("create-collection");
        Gui.await("the collection is open", () -> label("open-collection-name").equals("Open: " + collection));

        assertTrue(log().contains("Connected to collection label=\"" + collection + "\""), log());
        assertFalse(showing("default-banner"), "the banner shows only for a default collection");
        assertTrue(enabled("delete-collection"), "the collection can be deleted");
        Gui.await("the list shows the new collection", () -> Gui.firstColumn("collections").contains(collection));
        assertEquals(0, items());
        Gui.screenshot("collection-created");
    }

    @Test
    @Order(6)
    @DisplayName("Create stores an item, and the list shows it")
    void createsAnItem() {
        Gui.selectTab("item-tabs", "New item");
        Gui.type("item-label", "smoke item");
        Gui.type("item-secret", "s3cret");
        Gui.type("item-attribute-key", "purpose");
        Gui.type("item-attribute-value", "smoke");
        Gui.click("create-item");
        Gui.await("the list shows the item", () -> items() == 1);
        JPasswordField secret = Gui.find(JPasswordField.class, "item-secret");
        assertEquals(0, (int) Gui.onEventThread(() -> secret.getDocument().getLength()), "the secret field is cleared");
        Gui.screenshot("item-created");
    }

    @Test
    @Order(7)
    @DisplayName("selecting the item shows its label and attributes, and Read Secret its secret")
    void readsTheItem() {
        selectFirstItem();
        JTable attributes = Gui.find(JTable.class, "detail-attributes");
        assertEquals("purpose", Gui.onEventThread(() -> attributes.getValueAt(0, 0)));
        assertEquals("smoke", Gui.onEventThread(() -> attributes.getValueAt(0, 1)));
        SecretView secret = Gui.find(SecretView.class, "detail-secret");
        assertFalse(Gui.onEventThread(secret::isPresent), "the secret is read only when it is asked for");
        assertFalse(enabled("show-secret"), "Show waits for the secret");

        Gui.click("read-secret");
        Gui.await("the detail holds the secret", () -> secret.holds("s3cret"));
        assertFalse(Gui.onEventThread(secret::isRevealed), "the secret shows masked");
        // The items are listed again, as on the provider's signals, and the secret stays.
        Gui.click("list-items");
        Gui.await("the list has been listed again", () -> "Ready".equals(label("status")));
        assertTrue(Gui.onEventThread(() -> secret.holds("s3cret")), "the secret stays after the list is refreshed");
        Gui.click("show-secret");
        Gui.await("the secret shows", secret::isRevealed);
        Gui.screenshot("item-read");

        Gui.click("copy-secret");
        Gui.await("the clipboard holds the secret", () -> "s3cret".equals(clipboard()));
        assertTrue(log().contains("Copied the secret to the clipboard"), log());
        Gui.onEventThread(() -> {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(""), null);
            return null;
        });

        // Selecting the item again forgets the secret that was read.
        JTable items = Gui.find(JTable.class, "items");
        Gui.onEventThread(() -> {
            items.clearSelection();
            return null;
        });
        selectFirstItem();
        Gui.await("the secret is forgotten", () -> !secret.isPresent());
    }

    private static String clipboard() {
        try {
            return String.valueOf(Toolkit.getDefaultToolkit().getSystemClipboard().getData(DataFlavor.stringFlavor));
        } catch (Exception e) {
            return "<" + e.getClass().getSimpleName() + ">";
        }
    }

    @Test
    @Order(8)
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
    @Order(9)
    @DisplayName("Open opens the collection from the list, without its password")
    void reopensFromTheList() {
        Gui.click("disconnect");
        Gui.await("the window is disconnected", () -> enabled("connect"));
        assertEquals(0, items());
        assertTrue(Gui.firstColumn("collections").isEmpty(), "the list is empty without a connection");

        // A new session: the window opens the collection by its id, and gnome-keyring learns no
        // password, so that it asks through its unlock dialog.
        Gui.click("connect");
        Gui.await("the window is connected", () -> enabled("disconnect"));
        openFromTheList(collection);
        Gui.await("the list shows the item", () -> items() == 1);
    }

    @Test
    @Order(10)
    @DisplayName("the window answers while the provider's dialog waits, and Cancel gives up the wait")
    void staysResponsiveWhileTheProviderAsks() throws IOException {
        String control = System.getenv(DIALOG_CONTROL);
        Assumptions.assumeTrue(control != null, "Needs the dialog answerer of the gnome-keyring-dialogs container");
        Path hold = Path.of(control, "hold");
        selectFirstItem();

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
            // The library's own log, in the window's
            assertTrue(log().contains("lib ERROR Collection: The collection was not unlocked with user permission."), log());
        } finally {
            // The unlock dialog of gnome-keyring stays open; the answerer answers it now.
            Files.deleteIfExists(hold);
        }
        Gui.await("the answerer has answered the dialog", () -> !Gui.providerDialogShows());
    }

    @Test
    @Order(11)
    @DisplayName("Delete Item asks, then deletes through the provider's unlock dialog")
    void deletesTheItem() {
        selectFirstItem();
        Gui.click("delete-item");
        Gui.answer("Confirm Delete Item", UIManager.getString("OptionPane.yesButtonText"));
        Gui.await("the list is empty", () -> items() == 0);
        assertTrue(log().contains("Deleted item: "), log());
        assertTrue(Gui.answeredDialogs() > 0, "the provider asked through its unlock dialog");
        Gui.screenshot("item-deleted");
    }

    @Test
    @Order(12)
    @DisplayName("the list shows an item that another client creates, from the provider's signal")
    void refreshesFromTheSignals() throws Exception {
        assertEquals(0, items());
        try (CollectionInterface other = Collection.openById(collection, Optional.empty())
                .orElseThrow(() -> new AssertionError("another client opens the collection"))) {
            assertTrue(other.createItem("outside item", "0utside", Map.of("purpose", "outside")).isPresent());
        }
        Gui.await("the list shows the item of the other client", () -> items() == 1);
        JTable table = Gui.find(JTable.class, "items");
        assertEquals("outside item", Gui.onEventThread(() -> table.getValueAt(0, 0)));
        assertTrue(String.valueOf(Gui.onEventThread(() -> table.getValueAt(0, 1))).contains("purpose=outside"));
        Gui.screenshot("item-from-another-client");
    }

    @Test
    @Order(13)
    @DisplayName("the default collection opens only after the acknowledgement of the potential risk of damage")
    void opensTheDefaultAfterTheAcknowledgement() {
        Gui.selectRow("collections", LOGIN);

        // Cancel keeps the open collection.
        Gui.click("open-collection");
        Gui.await("the window asks", () -> Gui.lookup(AbstractButton.class, "open-default").isPresent());
        assertFalse(enabled("open-default"), "Open waits for the acknowledgement");
        Gui.click("cancel-default");
        Gui.await("the dialog has closed", () -> Gui.lookup(AbstractButton.class, "open-default").isEmpty());
        assertEquals("Open: " + collection, label("open-collection-name"));
        assertTrue(log().contains("Not opened: the risk of the default collection was not acknowledged."), log());

        Gui.click("open-collection");
        Gui.await("the window asks", () -> Gui.lookup(AbstractButton.class, "open-default").isPresent());
        Gui.click("acknowledge-risk");
        Gui.await("Open is enabled", () -> enabled("open-default"));
        Gui.screenshot("default-acknowledgement");
        Gui.click("open-default");
        Gui.await("the default collection is open", () -> label("open-collection-name").equals("Open: Login [login] (default)"));

        assertTrue(showing("default-banner"), "the banner shows while the default collection is open");
        assertFalse(enabled("delete-collection"), "the default collection cannot be deleted");
        Gui.screenshot("default-open");

        openFromTheList(collection);
        assertFalse(showing("default-banner"), "the banner goes with the default collection");
    }

    @Test
    @Order(14)
    @DisplayName("Delete Collection asks, deletes the collection and closes it")
    void deletesTheCollection() {
        Gui.selectTab("bottom-tabs", "Danger zone");
        Gui.click("delete-collection");
        Gui.answer("Confirm Delete Collection \"" + collection + "\"", UIManager.getString("OptionPane.yesButtonText"));
        Gui.await("the collection is closed", () -> "No collection is open.".equals(label("open-collection-name")));
        assertTrue(log().contains("Collection deleted."), log());
        Gui.await("the list has lost the collection", () -> !Gui.firstColumn("collections").contains(collection));
        assertTrue(enabled("disconnect"), "the window stays connected");
        Gui.screenshot("collection-deleted");
    }

    @Test
    @Order(15)
    @DisplayName("Kill Keyring stops the daemon that the bus names, after it names it, and Start Keyring starts one")
    void stopsAndStartsTheDaemon() {
        assertTrue(enabled("kill-keyring"), "Kill is enabled for gnome-keyring");
        assertFalse(enabled("start-keyring"), "Start waits for the window to disconnect");

        Gui.selectTab("bottom-tabs", "Danger zone");
        Gui.click("kill-keyring");
        String question = Gui.dialogMessage(SecretServiceGui.SecretServiceFrame.KILL_TITLE);
        assertTrue(question.startsWith("Stop /usr/bin/gnome-keyring-daemon (process "), question);
        Gui.screenshot("kill-keyring");
        Gui.answer(SecretServiceGui.SecretServiceFrame.KILL_TITLE, UIManager.getString("OptionPane.yesButtonText"));
        Gui.await("the window is disconnected", () -> enabled("connect"));
        assertTrue(log().contains("Stopped /usr/bin/gnome-keyring-daemon (process "), log());

        Gui.click("start-keyring");
        Gui.answer(SecretServiceGui.SecretServiceFrame.START_TITLE, UIManager.getString("OptionPane.yesButtonText"));
        Gui.await("the daemon has started", () -> log().contains("gnome-keyring-daemon --start: exit=0"));

        Gui.click("connect");
        Gui.await("the window is connected", () -> enabled("disconnect"));
        Gui.await("the list shows the login keyring", () -> Gui.firstColumn("collections").contains(LOGIN));
    }
}

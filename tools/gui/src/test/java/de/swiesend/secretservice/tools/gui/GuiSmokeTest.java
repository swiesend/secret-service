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
import javax.swing.JSpinner;
import javax.swing.JTable;
import javax.swing.JOptionPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.text.JTextComponent;
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
        Typography.smoothText(); // as main does, before AWT starts
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

    private String text(String name) {
        JTextComponent field = Gui.find(JTextComponent.class, name);
        return Gui.onEventThread(field::getText);
    }

    /** Sets the attributes in the editor with that name, as a user who adds rows. */
    private static void attributes(String editor, Map<String, String> attributes) {
        JTable table = Gui.find(JTable.class, editor);
        attributes.forEach((key, value) -> {
            int rows = Gui.onEventThread(table::getRowCount);
            Gui.click(editor + "-add");
            Gui.await("the editor has a new row", () -> table.getRowCount() == rows + 1);
            Gui.onEventThread(() -> {
                if (table.isEditing()) table.getCellEditor().cancelCellEditing();
                table.setValueAt(key, rows, 0);
                table.setValueAt(value, rows, 1);
                return null;
            });
        });
    }

    /** The value of the property in the table of the library's state. */
    private static String state(String property) {
        JTable found = Gui.find(JTable.class, "state");
        return Gui.onEventThread(() -> {
            for (int row = 0; row < found.getRowCount(); row++) {
                if (property.equals(String.valueOf(found.getValueAt(row, 1)))) return String.valueOf(found.getValueAt(row, 2));
            }
            return null;
        });
    }

    /** The value in that column of the row of the table whose first column is that text. */
    private static String cell(String table, String firstColumn, int column) {
        JTable found = Gui.find(JTable.class, table);
        return Gui.onEventThread(() -> {
            for (int row = 0; row < found.getRowCount(); row++) {
                if (firstColumn.equals(String.valueOf(found.getValueAt(row, 0)))) return String.valueOf(found.getValueAt(row, column));
            }
            return null;
        });
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
        Gui.await("the detail shows the item", () -> text("detail-label").startsWith("smoke item"));
    }

    /** Opens the collection of the list, which is no default one. */
    private void openFromTheList(String name) {
        Gui.selectRow("collections", name);
        Gui.click("open-collection");
        Gui.await("the collection is open", () -> label("collection-name").equals(name));
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

    @Test
    @Order(2)
    @DisplayName("the window takes the desktop's look, GTK's on Linux, not Swing's own")
    void looksLikeTheDesktop() {
        Assumptions.assumeTrue(System.getProperty("swing.defaultlaf") == null, "-Dswing.defaultlaf chooses the look");
        String look = Gui.onEventThread(() -> UIManager.getLookAndFeel().getClass().getName());
        if (System.getProperty("os.name").toLowerCase(java.util.Locale.ROOT).contains("linux")) {
            // The container has GTK, which gnome-keyring's dialogs need.
            assertEquals(SecretServiceGui.GTK, look);
        } else {
            assertEquals(UIManager.getSystemLookAndFeelClassName(), look);
        }
        // Text in subpixel smoothing, titles and table headers in bold.
        Object hints = Gui.onEventThread(() -> java.awt.Toolkit.getDefaultToolkit().getDesktopProperty("awt.font.desktophints"));
        assertTrue(String.valueOf(hints).contains("LCD HRGB"), "subpixel smoothing: " + hints);
        JTable items = Gui.find(JTable.class, "items");
        assertTrue(Gui.onEventThread(() -> items.getTableHeader().getFont().isBold()), "table headers are bold");
        // GTK's look has no signs for the dialogs; the GUI draws them.
        assertTrue(Gui.onEventThread(() -> UIManager.getIcon("OptionPane.warningIcon") != null), "a warning has its sign");
        assertTrue(Gui.onEventThread(() -> UIManager.getIcon("OptionPane.questionIcon") != null), "a question has its sign");
    }

    private static int scrollPaneHeight(JComponent view) {
        return Gui.onEventThread(() -> SwingUtilities.getAncestorOfClass(JScrollPane.class, view).getHeight());
    }

    @Test
    @Order(3)
    @DisplayName("the window starts disconnected")
    void startsDisconnected() {
        assertTrue(enabled("connect") && showing("connect"), "Connect shows");
        assertFalse(showing("disconnect"), "Disconnect shows only once connected");
        assertFalse(showing("cancel"), "Cancel shows only while a call runs");
        assertTrue(showing("collections-disconnected"), "the place of the collections says what to do");
        assertFalse(showing("new-collection"), "a collection is created only once connected");
        assertTrue(showing("no-collection"), "the place of the items says what to do");
        Gui.screenshot("start");
    }

    @Test
    @Order(4)
    @DisplayName("Connect lists the provider's collections and opens none")
    void connects() {
        Gui.click("connect");
        Gui.await("the window is connected", () -> enabled("disconnect"));
        assertEquals("Connected", label("connection-status"));
        assertTrue(Gui.firstColumn("collections").contains(LOGIN), String.valueOf(Gui.firstColumn("collections")));
        assertTrue(showing("no-collection"), "the place of the items says what to do");
        assertFalse(showing("open-collection"), "Open shows once a collection is selected");
    }

    @Test
    @Order(5)
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
    @Order(6)
    @DisplayName("New collection refuses a label that a collection has, then creates the collection with its password")
    void createsTheCollection() {
        Gui.click("new-collection");
        // A label that the provider has opens from the list, never through New collection.
        Gui.type("new-collection-label", "Login");
        Gui.await("the dialog says why", () -> label("new-collection-message").startsWith("A collection has this label"));
        assertFalse(enabled("new-collection-create"), "Create waits for a new label");
        Gui.type("new-collection-label", collection);
        Gui.click("new-collection-set-password");
        Gui.await("the dialog asks for the password", () -> label("new-collection-message").startsWith("Type the password"));
        Gui.type("new-collection-password", PASSWORD);
        Gui.await("Create is enabled", () -> enabled("new-collection-create"));
        Gui.screenshot("new-collection");
        Gui.click("new-collection-create");
        Gui.await("the collection is open", () -> label("collection-name").equals(collection));

        assertTrue(log().contains("Connected to collection label=\"" + collection + "\""), log());
        assertFalse(showing("default-banner"), "the banner shows only for a default collection");
        assertTrue(enabled("delete-collection"), "the collection can be deleted");
        Gui.await("the list shows the new collection", () -> Gui.firstColumn("collections").contains(collection));
        assertEquals(0, items());
        Gui.screenshot("collection-created");
    }

    @Test
    @Order(7)
    @DisplayName("New item creates an item, and the list shows it")
    void createsAnItem() {
        assertTrue(showing("detail-none"), "the place of the selected item says what to do");
        Gui.click("new-item");
        Gui.type("new-item-label", "smoke item");
        Gui.type("new-item-secret", "s3cret");
        attributes("new-item-attributes", Map.of("purpose", "smoke"));
        Gui.screenshot("new-item");
        Gui.click("new-item-create");
        Gui.await("the list shows the item", () -> items() == 1);
        assertEquals("1 item.", label("items-shown"));
        Gui.screenshot("item-created");
    }

    @Test
    @Order(8)
    @DisplayName("selecting the item shows its label and attributes, and Read Secret its secret")
    void readsTheItem() {
        selectFirstItem();
        JTable attributes = Gui.find(JTable.class, "detail-attributes");
        assertEquals("purpose", Gui.onEventThread(() -> attributes.getValueAt(0, 0)));
        assertEquals("smoke", Gui.onEventThread(() -> attributes.getValueAt(0, 1)));
        SecretView secret = Gui.find(SecretView.class, "detail-secret");
        assertFalse(Gui.onEventThread(secret::isPresent), "the secret is read only when it is asked for");
        assertFalse(showing("show-secret"), "Show waits for the secret");

        Gui.click("read-secret");
        Gui.await("the detail holds the secret", () -> secret.holds("s3cret"));
        assertFalse(Gui.onEventThread(secret::isRevealed), "the secret shows masked");
        // The items are listed again, as on the provider's signals, and the secret stays.
        Gui.click("refresh-items");
        Gui.await("the list has been listed again", () -> "Ready".equals(label("status")));
        assertTrue(Gui.onEventThread(() -> secret.holds("s3cret")), "the secret stays after the list is refreshed");
        Gui.click("show-secret");
        Gui.await("the secret shows", secret::isRevealed);
        assertEquals("Hide", Gui.onEventThread(() -> Gui.find(AbstractButton.class, "show-secret").getText()));
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
    @Order(9)
    @DisplayName("Search narrows the list and says so, and Show all items shows every item again")
    void searches() {
        Gui.type("search", "no item has this name");
        Gui.click("search-items");
        Gui.await("the list is empty", () -> items() == 0);

        Gui.type("search", "smoke item");
        Gui.click("search-items");
        Gui.await("the list shows the match", () -> items() == 1);
        assertEquals("1 of 1 item matches \"smoke item\" in their labels (fuzziness 1).", label("items-shown"));

        Gui.type("search", "no item has this name");
        Gui.click("search-items");
        Gui.await("the list is empty", () -> items() == 0);
        Gui.click("show-all");
        Gui.await("the list shows every item", () -> items() == 1);
        assertEquals("1 item.", label("items-shown"));
        assertEquals("", text("search"), "the search that no longer applies is emptied");
        assertFalse(showing("show-all"), "Show all items shows only while a search narrows the list");
    }

    @Test
    @Order(10)
    @DisplayName("the exact filter lists the items with the attributes, and Read all reads every secret")
    void filtersAndReadsAll() {
        JComboBox<?> mode = Gui.find(JComboBox.class, "search-mode");
        Gui.onEventThread(() -> {
            mode.setSelectedItem("exact attributes (key=value, ...)");
            return null;
        });
        Gui.type("search", "purpose=none");
        Gui.click("search-items");
        Gui.await("no item matches", () -> items() == 0);
        Gui.type("search", "purpose=smoke");
        Gui.click("search-items");
        Gui.await("the item matches", () -> items() == 1);
        assertTrue(log().contains("Filter by 1 attribute(s): 1 item(s) matched."), log());
        assertFalse(showing("search-distance"), "the exact filter has no fuzziness");
        Gui.click("show-all");
        Gui.onEventThread(() -> {
            mode.setSelectedItem("labels");
            return null;
        });

        Gui.click("read-all");
        Gui.await("the window has read every secret", () -> log().contains("Read the secrets of 1 item(s)."));
    }

    @Test
    @Order(11)
    @DisplayName("the timeout goes to the service")
    void setsTheTimeout() {
        Gui.selectTab("bottom-tabs", "Library");
        JSpinner timeout = Gui.find(JSpinner.class, "timeout");
        Gui.onEventThread(() -> {
            timeout.setValue(30);
            return null;
        });
        Gui.await("the service reports the timeout", () -> String.valueOf(state("getTimeout()")).startsWith("30s"));

        // The state needs room: Expand gives the tabs the whole window, Restore gives it back.
        Gui.click("expand-bottom");
        Gui.await("the items have made room", () -> !showing("items"));
        assertTrue(scrollPaneHeight(Gui.find(JTable.class, "state")) > 300, "the state shows many rows");
        Gui.screenshot("library-expanded");
        Gui.click("expand-bottom");
        Gui.await("the items show again", () -> showing("items"));
        Gui.onEventThread(() -> {
            timeout.setValue(120);
            return null;
        });
        Gui.await("the service reports the timeout", () -> String.valueOf(state("getTimeout()")).startsWith("120s"));
        Gui.selectTab("bottom-tabs", "Log");
    }

    @Test
    @Order(12)
    @DisplayName("Save changes the item's label, attributes and secret")
    void editsTheItem() {
        selectFirstItem();
        Gui.type("detail-label", "smoke item, edited");
        attributes("detail-attributes", Map.of("edited", "yes"));
        Gui.click("replace-secret");
        Gui.type("detail-new-secret", "n3w s3cret");
        Gui.click("save-item");
        Gui.await("the table shows the new label", () -> "smoke item, edited".equals(cell("items", "smoke item, edited", 0)));
        assertTrue(cell("items", "smoke item, edited", 1).contains("edited=yes"), cell("items", "smoke item, edited", 1));
        assertTrue(cell("items", "smoke item, edited", 1).contains("purpose=smoke"), "the other attributes stay");
        assertEquals("", text("detail-new-secret"), "the field of the new secret is cleared");

        selectFirstItem();
        SecretView secret = Gui.find(SecretView.class, "detail-secret");
        Gui.click("read-secret");
        Gui.await("the detail holds the new secret", () -> secret.holds("n3w s3cret"));
        // The items are listed again on the provider's signals, and the secret stays shown.
        Gui.click("refresh-items");
        Gui.await("the list has been listed again", () -> "Ready".equals(label("status")));
        assertTrue(Gui.onEventThread(() -> secret.holds("n3w s3cret")), "the secret stays after the list is refreshed");
        Gui.screenshot("item-edited");
    }

    @Test
    @Order(13)
    @DisplayName("Lock locks the collection, which lists its items without a prompt, and Unlock unlocks it")
    void locksAndUnlocksTheCollection() {
        assertFalse(showing("unlock-collection"), "Unlock shows only for a locked collection");
        Gui.click("lock-collection");
        Gui.await("the list shows the collection locked", () -> "yes".equals(cell("collections", collection, 1)));
        Gui.await("the call has ended", () -> "Ready".equals(label("status")));
        Gui.await("the header says so", () -> "locked".equals(label("collection-state")));
        assertFalse(showing("lock-collection"), "Lock shows only for an unlocked collection");
        long prompts = prompts();
        Gui.click("refresh-items");
        Gui.await("the locked collection lists its item", () -> items() == 1 && "Ready".equals(label("status")));
        assertEquals(prompts, prompts(), "listing the locked collection raised no prompt");
        Gui.screenshot("collection-locked");

        // The window created the collection with its password in this session, which the library
        // unlocks it with, without a dialog.
        Gui.click("unlock-collection");
        Gui.await("the list shows the collection unlocked", () -> "no".equals(cell("collections", collection, 1)));
        assertTrue(log().contains("Unlocked the collection."), log());
    }

    /** How many prompts of the provider have completed, as the window's log of the signals tells. */
    private long prompts() {
        return log().lines().filter(line -> line.contains("> Prompt.Completed(")).count();
    }

    @Test
    @Order(14)
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
    @Order(15)
    @DisplayName("the window answers while the provider's dialog waits, and Cancel gives up the wait")
    void staysResponsiveWhileTheProviderAsks() throws IOException {
        String control = System.getenv(DIALOG_CONTROL);
        Assumptions.assumeTrue(control != null, "Needs the dialog answerer of the gnome-keyring-dialogs container");
        Path hold = Path.of(control, "hold");
        selectFirstItem();

        Files.writeString(hold, "");
        try {
            // Deleting asks for the user's permission through the unlock dialog, which waits.
            Gui.click("delete-selected");
            Gui.answer(SecretServiceGui.SecretServiceFrame.DELETE_ITEMS_TITLE, UIManager.getString("OptionPane.yesButtonText"));
            Gui.await("the provider's dialog shows", Gui::providerDialogShows);

            assertTrue(label("status").startsWith("Delete item"), label("status"));
            assertTrue(enabled("cancel") && showing("cancel"), "Cancel shows while the call waits");
            assertFalse(enabled("new-item"), "the item controls are disabled while the call waits");
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
    @Order(16)
    @DisplayName("Delete Item asks, then deletes through the provider's unlock dialog")
    void deletesTheItem() {
        selectFirstItem();
        Gui.click("delete-selected");
        Gui.answer(SecretServiceGui.SecretServiceFrame.DELETE_ITEMS_TITLE, UIManager.getString("OptionPane.yesButtonText"));
        Gui.await("the list is empty", () -> items() == 0);
        assertTrue(log().contains("Deleted item: "), log());
        assertTrue(Gui.answeredDialogs() > 0, "the provider asked through its unlock dialog");
        Gui.screenshot("item-deleted");
    }

    @Test
    @Order(17)
    @DisplayName("without prompts, Unlock does not ask and leaves the collection locked; with them, it asks")
    void unlocksOnlyWithPrompts() {
        Gui.click("lock-collection");
        Gui.await("the list shows the collection locked", () -> "yes".equals(cell("collections", collection, 1)));

        Gui.selectTab("bottom-tabs", "Library");
        Gui.click("prompts");
        Gui.await("prompts are disabled", () -> log().contains("Prompts are disabled."));
        long prompts = prompts();
        Gui.click("unlock-collection");
        Gui.await("the call has ended", () -> log().contains("WARNING: unlockWithUserPermission returned false."));
        Gui.await("the window is ready", () -> "Ready".equals(label("status")));
        assertEquals("yes", cell("collections", collection, 1), "the collection stays locked");
        assertEquals(prompts, prompts(), "no prompt");

        Gui.click("prompts");
        Gui.await("prompts are enabled", () -> log().contains("Prompts are enabled."));
        Gui.click("unlock-collection");
        Gui.await("the list shows the collection unlocked", () -> "no".equals(cell("collections", collection, 1)));
        // gnome-keyring may unlock it without a dialog by now: its unlock dialog stores the password
        // of a collection that it unlocked once, as its box "Automatically unlock" is ticked.
        assertTrue(prompts() > prompts, "the provider completed a prompt");
        Gui.selectTab("bottom-tabs", "Log");
    }

    @Test
    @Order(18)
    @DisplayName("the list shows an item that another client creates, from the provider's signal")
    void refreshesFromTheSignals() throws Exception {
        assertEquals(0, items());
        try (CollectionInterface other = Collection.openById(collection, Optional.empty())
                .orElseThrow(() -> new AssertionError("another client opens the collection"))) {
            assertTrue(other.createItem("outside item", "0utside", Map.of("purpose", "outside")).isPresent());
        }
        Gui.await("the list shows the item of the other client", () -> items() == 1);
        assertTrue(cell("items", "outside item", 1).contains("purpose=outside"), cell("items", "outside item", 1));
        Gui.screenshot("item-from-another-client");
    }

    @Test
    @Order(19)
    @DisplayName("Delete Item deletes the selected items at once")
    void deletesSeveralItems() {
        Gui.click("new-item");
        Gui.type("new-item-label", "second item");
        Gui.type("new-item-secret", "s3cond");
        Gui.click("new-item-create");
        Gui.await("the list shows both items", () -> items() == 2);

        JTable table = Gui.find(JTable.class, "items");
        Gui.onEventThread(() -> {
            table.setRowSelectionInterval(0, 1);
            return null;
        });
        Gui.await("the selected item's place says that several are", () -> showing("detail-many"));
        assertEquals("Delete 2 selected\u2026", Gui.onEventThread(() -> Gui.find(AbstractButton.class, "delete-selected").getText()));
        Gui.screenshot("two-selected");
        Gui.click("delete-selected");
        String question = Gui.dialogMessage(SecretServiceGui.SecretServiceFrame.DELETE_ITEMS_TITLE);
        assertTrue(question.startsWith("Delete 2 items from the collection"), question);
        Gui.answer(SecretServiceGui.SecretServiceFrame.DELETE_ITEMS_TITLE, UIManager.getString("OptionPane.yesButtonText"));
        Gui.await("the list is empty", () -> items() == 0);
        assertTrue(log().contains("Deleted 2 item(s)."), log());
    }

    @Test
    @Order(20)
    @DisplayName("the default collection opens only after the acknowledgement of the potential risk of damage")
    void opensTheDefaultAfterTheAcknowledgement() {
        Gui.selectRow("collections", LOGIN);

        // Cancel keeps the open collection.
        Gui.click("open-collection");
        Gui.await("the window asks", () -> Gui.lookup(AbstractButton.class, "open-default").isPresent());
        assertFalse(enabled("open-default"), "Open waits for the acknowledgement");
        Gui.click("cancel-default");
        Gui.await("the dialog has closed", () -> Gui.lookup(AbstractButton.class, "open-default").isEmpty());
        assertEquals(collection, label("collection-name"));
        assertTrue(log().contains("Not opened: the risk of the default collection was not acknowledged."), log());

        Gui.click("open-collection");
        Gui.await("the window asks", () -> Gui.lookup(AbstractButton.class, "open-default").isPresent());
        Gui.click("acknowledge-risk");
        Gui.await("Open is enabled", () -> enabled("open-default"));
        Gui.screenshot("default-acknowledgement");
        Gui.click("open-default");
        Gui.await("the default collection is open", () -> label("collection-name").equals("Login [login] (default)"));

        assertTrue(showing("default-banner"), "the banner shows while the default collection is open");
        assertFalse(showing("delete-collection"), "a default collection has no Delete");
        Gui.screenshot("default-open");

        // Close leaves no collection open, and the connection as it is.
        Gui.click("close-collection");
        Gui.await("no collection is open", () -> showing("no-collection"));
        assertTrue(showing("disconnect"), "the window stays connected");
        assertFalse(showing("default-banner"), "the banner goes with the default collection");
        openFromTheList(collection);
    }

    @Test
    @Order(21)
    @DisplayName("Rename gives the collection a new label")
    void renamesTheCollection() {
        Gui.click("rename-collection");
        JOptionPane pane = Gui.optionPane(SecretServiceGui.SecretServiceFrame.RENAME_TITLE);
        JTextField input = Gui.onEventThread(() -> searchField(pane));
        Gui.onEventThread(() -> {
            input.setText(collection + " renamed");
            return null;
        });
        Gui.answer(SecretServiceGui.SecretServiceFrame.RENAME_TITLE, UIManager.getString("OptionPane.okButtonText"));
        Gui.await("the list shows the new label", () -> Gui.firstColumn("collections").contains(renamed()));
        assertEquals(renamed(), label("collection-name"));
    }

    private String renamed() {
        return collection + " renamed [" + collection + "]";
    }

    private static JTextField searchField(java.awt.Container container) {
        for (java.awt.Component child : container.getComponents()) {
            if (child instanceof JTextField field) return field;
            if (child instanceof java.awt.Container inner) {
                JTextField found = searchField(inner);
                if (found != null) return found;
            }
        }
        return null;
    }

    @Test
    @Order(22)
    @DisplayName("Delete collection asks, deletes the collection and closes it")
    void deletesTheCollection() {
        Gui.click("delete-collection");
        String question = Gui.dialogMessage(SecretServiceGui.SecretServiceFrame.DELETE_COLLECTION_TITLE);
        assertTrue(question.startsWith("Delete the collection \"" + renamed() + "\" and all its items?"), question);
        Gui.answer(SecretServiceGui.SecretServiceFrame.DELETE_COLLECTION_TITLE, UIManager.getString("OptionPane.yesButtonText"));
        Gui.await("the collection is closed", () -> showing("no-collection"));
        assertTrue(log().contains("Collection deleted."), log());
        Gui.await("the list has lost the collection", () -> !Gui.firstColumn("collections").contains(renamed()));
        assertTrue(enabled("disconnect"), "the window stays connected");
        Gui.screenshot("collection-deleted");
    }

    @Test
    @Order(23)
    @DisplayName("Stop stops the daemon that the bus names, after it names it, and Start starts one")
    void stopsAndStartsTheDaemon() {
        Gui.selectTab("bottom-tabs", "Keyring daemon");
        assertTrue(showing("kill-keyring"), "Stop shows for gnome-keyring");
        assertFalse(showing("start-keyring"), "Start shows only while the window is disconnected");
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

package de.swiesend.secretservice.tools.gui;

import de.swiesend.secretservice.functional.SearchMode;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.CharBuffer;
import java.time.Duration;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.stream.Collectors;
import java.util.concurrent.CountDownLatch;

/**
 * Standalone Swing GUI for manual system-level testing of the secret-service library.
 *
 * <p>This is a developer tool, intentionally kept out of the library jar and the test
 * suite. Build the core library, then launch it from the repository root with:
 * <pre>{@code
 *   mvn -q -DskipTests -Dgpg.skip=true install
 *   mvn -f tools/gui/pom.xml exec:java
 * }</pre>
 *
 * <p>Connect lists the collections of whichever provider serves {@code org.freedesktop.secrets}
 * (gnome-keyring, KeePassXC, KWallet, oo7); the GUI opens one of them, or creates a new one, and
 * creates, reads, lists and deletes its items. A default collection, the keyring of the desktop
 * session, opens only after the user has acknowledged the potential risk of damage.
 */
public final class SecretServiceGui {

    private SecretServiceGui() {
    }

    public static void main(String[] args) throws InterruptedException {
        Typography.smoothText(); // before AWT starts
        // Gate: a GUI needs a display
        if (GraphicsEnvironment.isHeadless()) {
            System.err.println("Headless environment detected — cannot launch the Secret Service GUI.");
            System.err.println("Run on a machine with a display (X11/Wayland) and a running secret service provider.");
            System.exit(2);
            return;
        }

        CountDownLatch latch = new CountDownLatch(1);
        SwingUtilities.invokeLater(() -> show(latch));
        latch.await(); // block until the user closes the window
        System.exit(0);
    }

    /**
     * Shows the window, on the event thread.
     *
     * @param closed counted down when the window has closed
     */
    static JFrame show(CountDownLatch closed) {
        useTheDesktopStyle();
        SecretServiceFrame frame = new SecretServiceFrame(closed);
        frame.setVisible(true);
        return frame;
    }

    /** Swing's look of GTK, the toolkit of GNOME and most Linux desktops' dialogs. */
    static final String GTK = "com.sun.java.swing.plaf.gtk.GTKLookAndFeel";

    /**
     * Takes the look of the desktop: on Windows and macOS their own, on Linux GTK's, which follows
     * the desktop's GTK theme and fonts. The JDK names GTK's look as the system's only where it
     * finds GNOME, and else Metal, Swing's own; so the GUI asks for GTK's first, and takes the
     * system's where GTK is not there. A look that {@code -Dswing.defaultlaf} names stays. Where
     * the look has no signs for its dialogs, as GTK's, the GUI draws its own.
     */
    static void useTheDesktopStyle() {
        if (System.getProperty("swing.defaultlaf") == null) {
            List<String> looks = new java.util.ArrayList<>();
            if (System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("linux")) looks.add(GTK);
            looks.add(UIManager.getSystemLookAndFeelClassName());
            for (String look : looks) {
                try {
                    UIManager.setLookAndFeel(look);
                    break;
                } catch (Exception | LinkageError unavailable) {
                    // GTK's look is not supported without the GTK libraries; the next one is tried.
                }
            }
        }
        OptionPaneIcons.fillIn();
        Typography.boldTitles();
    }

    // ─── GUI implementation ───────────────────────────────────────────────

    static final class SecretServiceFrame extends JFrame {

        private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm:ss");

        /** The smallest size at which the item list and the log still show a few lines. */
        private static final Dimension MINIMUM_SIZE = new Dimension(760, 560);
        private static final int COLLECTION_PANEL_WIDTH = 230;
        private static final int LOG_HEIGHT = 150;
        private static final Color DANGER = new Color(0xC62828);
        /** The title of the dialog that asks for the acknowledgement before a default collection opens. */
        static final String DEFAULT_RISK_TITLE = "Open the default collection";
        static final String KILL_TITLE = "Stop the keyring daemon";
        static final String DELETE_ITEMS_TITLE = "Delete items";
        static final String DELETE_COLLECTION_TITLE = "Delete collection";
        /** The cards of the collection's place: none open, or the open one. */
        private static final String ITEMS_NONE = "none";
        /** The cards of the collections' place: disconnected, or the list. */
        private static final String COLLECTIONS_DISCONNECTED = "disconnected";
        private static final String COLLECTIONS_LIST = "list";
        private static final String ITEMS_OPEN = "open";
        /** The cards of the selected item's place: none, several, or one. */
        private static final String DETAIL_NONE = "none";
        private static final String DETAIL_MANY = "many";
        private static final String DETAIL_ONE = "one";
        static final String EXPAND = "Expand";
        static final String RESTORE = "Restore";
        /** The search mode that lists the items with exactly the attributes "key=value, ...". */
        private static final String BY_ATTRIBUTES = "exact attributes (key=value, ...)";
        static final String RENAME_TITLE = "Rename collection";
        /** How long the window waits after a signal of the provider, which come in bursts. */
        private static final int REFRESH_DELAY_MILLIS = 300;
        static final String START_TITLE = "Start a keyring daemon";
        /** How long the window keeps a secret that it has read. */
        private static final int SECRET_SHOWN_MILLIS = 60_000;
        /** How long the clipboard keeps a secret that the window copied there. */
        static final int CLIPBOARD_MILLIS = 30_000;

        // The provider's collections, in the list on the left
        private final DefaultTableModel collectionsModel = readOnlyTableModel("Collection", "Locked");
        private final JTable collectionsTable = new JTable(collectionsModel);
        private List<KeyringClient.CollectionEntry> collectionEntries = List.of();
        private final JButton btnOpenCollection = new JButton("Open");
        private final JButton btnRefreshCollections = new JButton("Refresh");
        private final JButton btnNewCollection = new JButton("New collection…");
        /** The list, or, while the window is disconnected, what to do. */
        private final CardLayout collectionsCards = new CardLayout();
        private final JPanel collectionsArea = new JPanel(collectionsCards);
        private final JLabel lblDisconnected = new JLabel("<html><div style='text-align:center'>Connect to list<br>the provider's collections.</div></html>",
                SwingConstants.CENTER);

        // The open collection: its name, its state and its actions, above its items
        private final CardLayout itemsCards = new CardLayout();
        private final JPanel itemsArea = new JPanel(itemsCards);
        private final JLabel lblNoCollection = new JLabel("<html><div style='text-align:center'>No collection is open.<br><br>"
                + "Select a collection in the list on the left and click Open,<br>or create one with New collection…</div></html>",
                SwingConstants.CENTER);
        private final JLabel lblCollectionName = new JLabel(" ");
        private final JLabel lblCollectionState = new JLabel(" ");
        private final JButton btnLockCollection = new JButton("Lock");
        private final JButton btnUnlockCollection = new JButton("Unlock");
        private final JButton btnRenameCollection = new JButton("Rename…");
        private final JButton btnCloseCollection = new JButton("Close");
        private final JButton btnDeleteCollection = new JButton("Delete collection…");
        /** Shows while a default collection is open. */
        private final JLabel lblDefaultBanner = new JLabel(
                "Default collection: changes affect every application of the desktop session.");
        /** The open collection's path, and its lock state as the provider last told it, if it did. */
        private String collectionPath = "";
        private Optional<Boolean> collectionLocked = Optional.empty();

        // The open collection's items
        private final DefaultTableModel itemsModel = readOnlyTableModel("Label", "Attributes", "Path");
        private final JTable itemsTable = new JTable(itemsModel);
        private List<KeyringClient.ItemRow> itemRows = List.of();
        /** While the table is rebuilt, its selection changes say nothing about the user's. */
        private boolean rebuildingItems = false;
        /** What lists the items that the table shows: all of them, or the last search. */
        private Callable<KeyringClient.ItemListing> listing;
        /** What the table shows: all items, or what a search looked for. */
        private Optional<String> shownQuery = Optional.empty();
        private final JLabel lblItemsShown = new JLabel(" ");
        private final JButton btnShowAll = new JButton("Show all items");
        /** Lists the items again, as the table lists them. */
        private final JButton btnRefreshItems = new JButton("Refresh");
        private final JButton btnNewItem = new JButton("New item…");
        private final JButton btnDeleteSelected = new JButton("Delete selected…");
        private final JButton btnReadAll = new JButton("Read all secrets…");
        /** Refresh the items and the collections a moment after the provider signals a change. */
        private final Timer refreshItems = new Timer(REFRESH_DELAY_MILLIS, e -> doRefreshItems());
        private final Timer refreshCollections = new Timer(REFRESH_DELAY_MILLIS, e -> doRefreshCollections());

        // Search: "Search [text] in [mode], fuzziness [n]"
        private final JTextField tfSearch = new JTextField(14);
        private final JComboBox<String> cmbSearchMode = new JComboBox<>(new String[]{
                "labels", "attribute keys", "attribute values", "object ids", "object paths", BY_ATTRIBUTES});
        private final JLabel lblFuzziness = new JLabel("Fuzziness:");
        private final JComboBox<Integer> cmbMaxDistance = new JComboBox<>(new Integer[]{0, 1, 2, 3});
        private final JButton btnSearch = new JButton("Search");

        // Library settings
        private final JCheckBox cbPrompts = new JCheckBox("Let the library raise the provider's prompts", true);
        private final JSpinner spTimeout = new JSpinner(new SpinnerNumberModel(120, 1, 3600, 5));

        // The selected item: nothing, several, or one with its fields
        private final CardLayout detailCards = new CardLayout();
        private final JPanel detailArea = new JPanel(detailCards);
        private final JLabel lblDetailNone = new JLabel("Select an item in the list to see and change it.", SwingConstants.CENTER);
        private final JLabel lblDetailMany = new JLabel(" ", SwingConstants.CENTER);
        private final JLabel lblDetailPath = new JLabel(" ");
        private final JButton btnCopyPath = new JButton("Copy path");
        private final JTextField tfDetailLabel = new JTextField(16);
        private final SecretView secretView = new SecretView();
        private final JButton btnRead = new JButton("Read secret");
        private final JToggleButton btnShowSecret = new JToggleButton("Show");
        private final JButton btnCopySecret = new JButton("Copy secret");
        /** A new secret for the item, only where the box is ticked. */
        private final JCheckBox cbReplaceSecret = new JCheckBox("Replace the secret:");
        private final JPasswordField pfDetailNewSecret = new JPasswordField(16);
        private final AttributesEditor detailAttributes = new AttributesEditor("detail-attributes");
        private final JButton btnSaveItem = new JButton("Save changes");
        private final JButton btnRevertItem = new JButton("Revert");
        private final JButton btnLockItem = new JButton("Lock item");
        private final JButton btnUnlockItem = new JButton("Unlock item");
        /** Forgets a secret that the window has read, a minute after it read it. */
        private final Timer forgetSecret = new Timer(SECRET_SHOWN_MILLIS, e -> forgetTheSecret());

        // Log area
        private final JTextArea logArea = new JTextArea();
        private final JComboBox<LibraryLog.Threshold> cmbLogLevel = new JComboBox<>(LibraryLog.Threshold.values());
        /** The library's log, in {@link #logArea}. */
        private final LibraryLog libraryLog = new LibraryLog(this::log, LibraryLog.Threshold.INFO);

        // Buttons
        private final JButton btnConnect = new JButton("Connect");
        private final JButton btnDisconnect = new JButton("Disconnect");
        private final JButton btnKillKeyring = new JButton("Stop the keyring daemon\u2026");
        private final JButton btnStartKeyring = new JButton("Start a keyring daemon\u2026");
        private final JButton btnClearLog = new JButton("Clear Log");

        // Library tab: the library's settings and the state of its objects, in one table
        private final DefaultTableModel stateModel = readOnlyTableModel("Object", "Property", "Value");
        private final JTable stateTable = new JTable(stateModel);
        private final JButton btnDebugRefresh = new JButton("Refresh now");
        private final JCheckBox cbAutoSync = new JCheckBox("Refresh after each call", true);

        // The bottom panel, and its switch that gives it the whole window
        private final JTabbedPane bottomTabs = new JTabbedPane();
        private final JToggleButton btnExpand = new JToggleButton(EXPAND);
        private JSplitPane workSplit;
        private JComponent workArea;
        private int restoreDivider = -1;

        // Connection status icon
        private final JLabel lblConnectionStatus = new JLabel();

        // System panel — D-Bus status labels
        private final JLabel lblDbusConnected = new JLabel("—");
        private final JLabel lblDbusAvailable = new JLabel("—");
        private final JLabel lblProvider = new JLabel("—");

        // Busy state: what the worker does, and Cancel, which gives up a wait for the provider
        private static final String READY = "Ready";
        private final JLabel lblStatus = new JLabel(READY);
        private final JButton btnCancel = new JButton("Cancel the call");

        /** The keyring calls, which run on {@link #worker}, never on the event thread. */
        private final KeyringClient client = new KeyringClient(this::log);
        private final Worker worker = new Worker(workerListener());
        /** Whether the window is connected to the provider. */
        private boolean connected = false;
        /** Whether gnome-keyring serves the Secret Service, as the window found at Connect. */
        private boolean gnomeKeyring = false;
        /** Whether a collection is open, and whether it is a default one. */
        private boolean collectionOpen = false;
        private boolean defaultOpen = false;
        /** The name of the open collection, for the confirmations, and its id. */
        private String collectionName = "";
        private String collectionId = "";
        private final CountDownLatch closeLatch;

        SecretServiceFrame(CountDownLatch closeLatch) {
            super("Secret Service developer GUI");
            this.closeLatch = closeLatch;
            setDefaultCloseOperation(DISPOSE_ON_CLOSE);
            addWindowListener(new WindowAdapter() {
                @Override
                public void windowClosed(WindowEvent e) {
                    closed();
                }
            });
            buildUi();
            Typography.boldTableHeaders(getContentPane());
            nameComponents();
            wireActions();
            fitToScreen();
            updateControls();
            refreshState();
        }

        private static DefaultTableModel readOnlyTableModel(String... columns) {
            return new DefaultTableModel(columns, 0) {
                @Override public boolean isCellEditable(int row, int col) { return false; }
            };
        }

        /** The names by which the smoke test finds the components. */
        private void nameComponents() {
            setName("secret-service-gui");
            btnConnect.setName("connect");
            btnDisconnect.setName("disconnect");
            lblStatus.setName("status");
            btnCancel.setName("cancel");
            lblConnectionStatus.setName("connection-status");
            lblProvider.setName("provider");
            collectionsTable.setName("collections");
            btnOpenCollection.setName("open-collection");
            btnRefreshCollections.setName("refresh-collections");
            btnNewCollection.setName("new-collection");
            lblNoCollection.setName("no-collection");
            lblDisconnected.setName("collections-disconnected");
            lblCollectionName.setName("collection-name");
            lblCollectionState.setName("collection-state");
            btnLockCollection.setName("lock-collection");
            btnUnlockCollection.setName("unlock-collection");
            btnRenameCollection.setName("rename-collection");
            btnCloseCollection.setName("close-collection");
            btnDeleteCollection.setName("delete-collection");
            lblDefaultBanner.setName("default-banner");
            itemsTable.setName("items");
            lblItemsShown.setName("items-shown");
            btnShowAll.setName("show-all");
            btnRefreshItems.setName("refresh-items");
            btnNewItem.setName("new-item");
            btnDeleteSelected.setName("delete-selected");
            btnReadAll.setName("read-all");
            tfSearch.setName("search");
            cmbSearchMode.setName("search-mode");
            cmbMaxDistance.setName("search-distance");
            btnSearch.setName("search-items");
            cbPrompts.setName("prompts");
            spTimeout.setName("timeout");
            lblDetailNone.setName("detail-none");
            lblDetailMany.setName("detail-many");
            lblDetailPath.setName("detail-path");
            btnCopyPath.setName("copy-path");
            tfDetailLabel.setName("detail-label");
            secretView.setName("detail-secret");
            btnRead.setName("read-secret");
            btnShowSecret.setName("show-secret");
            btnCopySecret.setName("copy-secret");
            cbReplaceSecret.setName("replace-secret");
            pfDetailNewSecret.setName("detail-new-secret");
            btnSaveItem.setName("save-item");
            btnRevertItem.setName("revert-item");
            btnLockItem.setName("lock-item");
            btnUnlockItem.setName("unlock-item");
            btnKillKeyring.setName("kill-keyring");
            btnStartKeyring.setName("start-keyring");
            logArea.setName("log");
            cmbLogLevel.setName("log-level");
            btnClearLog.setName("clear-log");
            btnDebugRefresh.setName("refresh-state");
            cbAutoSync.setName("auto-sync");
            stateTable.setName("state");
            bottomTabs.setName("bottom-tabs");
            btnExpand.setName("expand-bottom");
        }

        // ── Layout ────────────────────────────────────────────────────
        //
        // The toolbar on top: the connection and what runs. Below it the collection on the left
        // and its items in the middle, with the selected item and a new one in tabs under the
        // list. At the bottom the log, the library's state and the danger zone, in tabs.

        private void buildUi() {
            JPanel content = new JPanel(new BorderLayout(6, 6));
            content.setBorder(new EmptyBorder(6, 6, 6, 6));
            content.add(buildToolbar(), BorderLayout.NORTH);

            JPanel work = new JPanel(new BorderLayout(6, 6));
            work.add(buildCollectionPanel(), BorderLayout.WEST);
            work.add(buildItemsPanel(), BorderLayout.CENTER);

            bottomTabs.addTab("Log", buildLogPanel());
            bottomTabs.addTab("Library", buildStateTab());
            bottomTabs.addTab("Keyring daemon", buildDaemonTab());
            btnExpand.setToolTipText("Give the whole window to these tabs, as the library's state needs room");
            btnExpand.setFocusable(false);

            workArea = work;
            workSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, work, new CornerPanel(bottomTabs, btnExpand));
            workSplit.setResizeWeight(1.0); // a taller window gives its height to the items
            workSplit.setBorder(null);
            content.add(workSplit, BorderLayout.CENTER);
            setContentPane(content);
        }

        /**
         * Gives the bottom tabs the whole window, below the toolbar, or gives the collections and
         * items their place back.
         */
        private void setBottomExpanded(boolean expanded) {
            if (expanded) {
                restoreDivider = workSplit.getDividerLocation();
                workArea.setVisible(false);
                workSplit.setDividerLocation(0);
                btnExpand.setText(RESTORE);
                btnExpand.setToolTipText("Show the collections and items again");
            } else {
                workArea.setVisible(true);
                if (restoreDivider > 0) workSplit.setDividerLocation(restoreDivider);
                else workSplit.resetToPreferredSizes();
                btnExpand.setText(EXPAND);
                btnExpand.setToolTipText("Give the whole window to these tabs, as the library's state needs room");
            }
            workSplit.revalidate();
            workSplit.repaint();
        }

        /** Fits the window to the screen it opens on, at least {@link #MINIMUM_SIZE}. */
        private void fitToScreen() {
            pack();
            Rectangle screen = getGraphicsConfiguration().getBounds();
            Insets insets = Toolkit.getDefaultToolkit().getScreenInsets(getGraphicsConfiguration());
            int width = Math.min(Math.max(getWidth(), MINIMUM_SIZE.width), screen.width - insets.left - insets.right);
            int height = Math.min(Math.max(getHeight(), MINIMUM_SIZE.height), screen.height - insets.top - insets.bottom);
            setMinimumSize(new Dimension(Math.min(MINIMUM_SIZE.width, width), Math.min(MINIMUM_SIZE.height, height)));
            setSize(width, height);
            setLocationRelativeTo(null);
        }

        private JPanel buildToolbar() {
            JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
            bar.add(lblConnectionStatus);
            bar.add(btnConnect);
            bar.add(btnDisconnect);
            bar.add(new JSeparator(SwingConstants.VERTICAL));
            bar.add(new JLabel("D-Bus:"));
            bar.add(lblDbusConnected);
            bar.add(new JLabel("Service:"));
            bar.add(lblDbusAvailable);
            bar.add(new JLabel("Provider:"));
            bar.add(lblProvider);
            bar.add(new JSeparator(SwingConstants.VERTICAL));
            bar.add(lblStatus);
            bar.add(btnCancel);
            btnCancel.setCursor(Cursor.getDefaultCursor()); // not the window's wait cursor
            updateConnectionIcon(false);

            JPanel panel = new JPanel(new BorderLayout());
            panel.add(bar, BorderLayout.CENTER);
            panel.add(new JSeparator(), BorderLayout.SOUTH);
            return panel;
        }

        /** The provider's collections, and the actions that start from the list. */
        private JPanel buildCollectionPanel() {
            collectionsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            collectionsTable.setFillsViewportHeight(true);
            // Wide enough for its bold header.
            int lockedWidth = collectionsTable.getFontMetrics(Typography.titleFont()).stringWidth("Locked") + 16;
            collectionsTable.getColumnModel().getColumn(1).setPreferredWidth(lockedWidth);
            collectionsTable.getColumnModel().getColumn(1).setMaxWidth(lockedWidth + 20);
            collectionsTable.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    if (e.getClickCount() == 2 && btnOpenCollection.isEnabled()) doOpenCollection();
                }
            });
            collectionsTable.setToolTipText("Double-click a collection to open it");
            JScrollPane tableScroll = new JScrollPane(collectionsTable);
            tableScroll.setPreferredSize(new Dimension(COLLECTION_PANEL_WIDTH, 160));

            // Open last: it shows only while a collection is selected.
            JPanel listButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
            listButtons.add(btnRefreshCollections);
            listButtons.add(btnOpenCollection);
            JPanel newButton = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
            newButton.add(btnNewCollection);
            JPanel buttons = new JPanel(new GridLayout(2, 1, 0, 4));
            buttons.add(listButtons);
            buttons.add(newButton);

            JPanel list = new JPanel(new BorderLayout(4, 6));
            list.add(tableScroll, BorderLayout.CENTER);
            list.add(buttons, BorderLayout.SOUTH);
            collectionsArea.add(centered(lblDisconnected), COLLECTIONS_DISCONNECTED);
            collectionsArea.add(list, COLLECTIONS_LIST);

            JPanel panel = new JPanel(new BorderLayout());
            panel.setBorder(new TitledBorder("Collections"));
            panel.setPreferredSize(new Dimension(COLLECTION_PANEL_WIDTH + 16, 0));
            panel.add(collectionsArea, BorderLayout.CENTER);
            return panel;
        }

        /** Adds a label and its field as row {@code y} of a two-column grid. */
        private static void addRow(JPanel panel, int y, String label, JComponent field) {
            GridBagConstraints gbc = gbc();
            gbc.gridx = 0; gbc.gridy = y; gbc.anchor = GridBagConstraints.EAST; gbc.fill = GridBagConstraints.NONE;
            panel.add(new JLabel(label), gbc);
            gbc.gridx = 1; gbc.anchor = GridBagConstraints.WEST; gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.weightx = 1.0;
            panel.add(field, gbc);
        }

        /**
         * The open collection, or what to do where none is: its header with its name, state and
         * actions, the search, its items with their actions, and the selected item.
         */
        private JPanel buildItemsPanel() {
            lblNoCollection.setForeground(Color.GRAY);
            JPanel none = new JPanel(new BorderLayout());
            none.setBorder(new TitledBorder("Collection"));
            none.add(lblNoCollection, BorderLayout.CENTER);

            JPanel open = new JPanel(new BorderLayout(4, 4));
            open.setBorder(new TitledBorder("Collection"));
            JPanel north = new JPanel(new BorderLayout(4, 4));
            north.add(buildCollectionHeader(), BorderLayout.NORTH);
            lblDefaultBanner.setOpaque(true);
            lblDefaultBanner.setBackground(DANGER);
            lblDefaultBanner.setForeground(Color.WHITE);
            lblDefaultBanner.setBorder(new EmptyBorder(4, 6, 4, 6));
            lblDefaultBanner.setVisible(false);
            north.add(lblDefaultBanner, BorderLayout.CENTER);
            north.add(buildSearchBar(), BorderLayout.SOUTH);
            open.add(north, BorderLayout.NORTH);

            itemsTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
            itemsTable.setFillsViewportHeight(true);
            itemsTable.setAutoCreateRowSorter(true);
            itemsTable.getColumnModel().getColumn(0).setPreferredWidth(140);
            itemsTable.getColumnModel().getColumn(1).setPreferredWidth(200);
            itemsTable.getColumnModel().getColumn(2).setPreferredWidth(260);
            JScrollPane listScroll = new JScrollPane(itemsTable);
            listScroll.setPreferredSize(new Dimension(420, 120));
            listScroll.setMinimumSize(new Dimension(200, 80));

            JPanel shown = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
            shown.add(lblItemsShown);
            shown.add(btnShowAll);
            shown.add(btnRefreshItems);
            JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
            actions.add(btnNewItem);
            actions.add(btnReadAll);
            actions.add(btnDeleteSelected);
            btnDeleteSelected.setForeground(DANGER);
            btnReadAll.setToolTipText("Reads every secret through withSecrets, which asks for permission, and tells only how many");
            JPanel list = new JPanel(new BorderLayout(4, 4));
            list.add(shown, BorderLayout.NORTH);
            list.add(listScroll, BorderLayout.CENTER);
            list.add(actions, BorderLayout.SOUTH);

            detailArea.add(centered(lblDetailNone), DETAIL_NONE);
            detailArea.add(centered(lblDetailMany), DETAIL_MANY);
            detailArea.add(buildDetailPanel(), DETAIL_ONE);
            detailArea.setBorder(new TitledBorder("Selected item"));

            JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, list, detailArea);
            split.setResizeWeight(0.5);
            split.setBorder(null);
            open.add(split, BorderLayout.CENTER);

            itemsArea.add(none, ITEMS_NONE);
            itemsArea.add(open, ITEMS_OPEN);
            JPanel panel = new JPanel(new BorderLayout());
            panel.add(itemsArea, BorderLayout.CENTER);
            return panel;
        }

        private static JPanel centered(JLabel label) {
            label.setForeground(Color.GRAY);
            JPanel panel = new JPanel(new BorderLayout());
            panel.add(label, BorderLayout.CENTER);
            return panel;
        }

        /** The open collection's name and lock state, and the actions on the collection as a whole. */
        private JPanel buildCollectionHeader() {
            lblCollectionName.setFont(Typography.titleFont().deriveFont(Typography.titleFont().getSize2D() + 2f));
            JPanel name = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
            name.add(lblCollectionName);
            name.add(lblCollectionState);
            btnDeleteCollection.setForeground(DANGER);
            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
            buttons.add(btnLockCollection);
            buttons.add(btnUnlockCollection);
            buttons.add(btnRenameCollection);
            buttons.add(btnCloseCollection);
            buttons.add(btnDeleteCollection);
            JPanel header = new JPanel(new BorderLayout(4, 0));
            header.add(name, BorderLayout.CENTER);
            header.add(buttons, BorderLayout.EAST);
            return header;
        }

        /** "Search [text] in [what], fuzziness [n] [Search]". */
        private JPanel buildSearchBar() {
            cmbMaxDistance.setSelectedItem(1);
            String fuzziness = "<html>How far a match may be from the text (Levenshtein distance):<br>"
                    + "<b>0</b> - the text, as a part<br><b>1</b> - one typo<br><b>2</b> - two edits<br><b>3</b> - very loose</html>";
            cmbMaxDistance.setToolTipText(fuzziness);
            lblFuzziness.setToolTipText(fuzziness);
            tfSearch.setToolTipText("For exact attributes: key=value, key2=value2");

            JPanel options = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
            options.add(new JLabel("in"));
            options.add(cmbSearchMode);
            options.add(lblFuzziness);
            options.add(cmbMaxDistance);
            options.add(btnSearch);

            JPanel bar = new JPanel(new BorderLayout(4, 0));
            bar.add(new JLabel("Search:"), BorderLayout.WEST);
            bar.add(tfSearch, BorderLayout.CENTER);
            bar.add(options, BorderLayout.EAST);
            return bar;
        }

        /** The fields of one item, and the actions on it. */
        private JPanel buildDetailPanel() {
            JPanel form = new JPanel(new GridBagLayout());
            JPanel path = new JPanel(new BorderLayout(6, 0));
            path.add(lblDetailPath, BorderLayout.CENTER);
            path.add(btnCopyPath, BorderLayout.EAST);
            addRow(form, 0, "Path:", path);
            addRow(form, 1, "Label:", tfDetailLabel);

            JPanel secret = new JPanel(new BorderLayout(4, 0));
            secret.add(secretView, BorderLayout.CENTER);
            JPanel secretButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
            secretButtons.add(btnRead);
            secretButtons.add(btnShowSecret);
            secretButtons.add(btnCopySecret);
            secret.add(secretButtons, BorderLayout.EAST);
            addRow(form, 2, "Secret:", secret);

            JPanel replace = new JPanel(new BorderLayout(4, 0));
            replace.add(cbReplaceSecret, BorderLayout.WEST);
            replace.add(pfDetailNewSecret, BorderLayout.CENTER);
            GridBagConstraints gbc = gbc();
            gbc.gridx = 1; gbc.gridy = 3;
            form.add(replace, gbc);

            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
            buttons.add(btnSaveItem);
            buttons.add(btnRevertItem);
            buttons.add(btnLockItem);
            buttons.add(btnUnlockItem);
            gbc = gbc();
            gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2; gbc.anchor = GridBagConstraints.NORTHWEST;
            gbc.fill = GridBagConstraints.NONE; gbc.weighty = 1.0;
            form.add(buttons, gbc);

            JPanel panel = new JPanel(new BorderLayout(6, 0));
            panel.setBorder(new EmptyBorder(2, 2, 2, 2));
            panel.add(form, BorderLayout.CENTER);
            panel.add(detailAttributes, BorderLayout.EAST);
            return panel;
        }

        /** The library's settings, and the state of its objects in one table that scrolls. */
        private JPanel buildStateTab() {
            cbPrompts.setToolTipText("<html>enablePrompt / disablePrompt on the open collection and each that opens.<br>"
                    + "Without prompts, the provider alone decides what a call may do.</html>");
            spTimeout.setToolTipText("How long the library waits for a prompt (ServiceInterface.setTimeout)");
            JPanel settings = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
            settings.setBorder(new TitledBorder("Settings"));
            settings.add(cbPrompts);
            settings.add(new JLabel("Prompt timeout:"));
            settings.add(spTimeout);
            settings.add(new JLabel("s"));

            stateTable.setFillsViewportHeight(true);
            stateTable.getColumnModel().getColumn(0).setPreferredWidth(110);
            stateTable.getColumnModel().getColumn(0).setMaxWidth(160);
            stateTable.getColumnModel().getColumn(1).setPreferredWidth(240);
            stateTable.getColumnModel().getColumn(2).setPreferredWidth(420);
            JScrollPane scroll = new JScrollPane(stateTable);
            scroll.setPreferredSize(new Dimension(0, LOG_HEIGHT));
            JPanel stateControls = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
            stateControls.add(cbAutoSync);
            stateControls.add(btnDebugRefresh);
            JPanel state = new JPanel(new BorderLayout(4, 4));
            state.setBorder(new TitledBorder("State of the library's objects"));
            state.add(scroll, BorderLayout.CENTER);
            state.add(stateControls, BorderLayout.SOUTH);

            JPanel panel = new JPanel(new BorderLayout(4, 4));
            panel.setBorder(new EmptyBorder(4, 4, 4, 4));
            panel.add(settings, BorderLayout.NORTH);
            panel.add(state, BorderLayout.CENTER);
            return panel;
        }

        /** The keyring daemon: stop the one that serves the bus, or start one. */
        private JPanel buildDaemonTab() {
            btnKillKeyring.setForeground(DANGER);
            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 4));
            buttons.add(btnKillKeyring);
            buttons.add(btnStartKeyring);

            JLabel explanation = new JLabel("<html>Stop ends the gnome-keyring daemon that serves this bus, and"
                    + " only that one: every application of the desktop session loses the keyring until a daemon"
                    + " starts again. It is offered while the window is connected to gnome-keyring. Start starts"
                    + " a daemon, and is offered while the window is disconnected. Each asks before it acts.</html>");

            JPanel panel = new JPanel(new BorderLayout(4, 4));
            panel.setBorder(new EmptyBorder(6, 6, 6, 6));
            panel.add(explanation, BorderLayout.NORTH);
            panel.add(buttons, BorderLayout.CENTER);
            return panel;
        }

        private JPanel buildLogPanel() {
            JPanel panel = new JPanel(new BorderLayout(4, 4));
            panel.setBorder(new EmptyBorder(4, 4, 4, 4));
            logArea.setEditable(false);
            // Long lines wrap, as a path or a library message does not fit the width.
            logArea.setLineWrap(true);
            logArea.setWrapStyleWord(true);
            logArea.setFont(Typography.logFont());
            JScrollPane scroll = new JScrollPane(logArea, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
                    ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
            scroll.setPreferredSize(new Dimension(0, LOG_HEIGHT));
            panel.add(scroll, BorderLayout.CENTER);
            cmbLogLevel.setSelectedItem(LibraryLog.Threshold.INFO);
            cmbLogLevel.setToolTipText("The level from which the library's log shows, in the lines that start with \"lib\"");
            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
            buttons.add(new JLabel("Library log:"));
            buttons.add(cmbLogLevel);
            buttons.add(btnClearLog);
            panel.add(buttons, BorderLayout.SOUTH);
            return panel;
        }

        private static GridBagConstraints gbc() {
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.insets = new Insets(3, 6, 3, 6);
            gbc.fill = GridBagConstraints.HORIZONTAL;
            return gbc;
        }

        // ── Actions ───────────────────────────────────────────────────

        private void wireActions() {
            btnConnect.addActionListener(e -> doConnect());
            btnExpand.addItemListener(e -> setBottomExpanded(btnExpand.isSelected()));
            btnDisconnect.addActionListener(e -> doDisconnect());
            btnCancel.addActionListener(e -> {
                log("Cancelling: %s", lblStatus.getText());
                worker.cancel();
            });
            // Collections
            btnOpenCollection.addActionListener(e -> doOpenCollection());
            btnRefreshCollections.addActionListener(e -> doRefreshCollections());
            btnNewCollection.addActionListener(e -> doNewCollection());
            collectionsTable.getSelectionModel().addListSelectionListener(e -> updateControls());
            btnLockCollection.addActionListener(e -> doLockCollection(true));
            btnUnlockCollection.addActionListener(e -> doLockCollection(false));
            btnRenameCollection.addActionListener(e -> doRenameCollection());
            btnCloseCollection.addActionListener(e -> doCloseCollection());
            btnDeleteCollection.addActionListener(e -> doDeleteCollection());
            // Items
            btnSearch.addActionListener(e -> doSearch());
            tfSearch.addActionListener(e -> doSearch());
            cmbSearchMode.addActionListener(e -> updateControls());
            btnShowAll.addActionListener(e -> doListItems());
            btnRefreshItems.addActionListener(e -> doRefreshItems());
            btnNewItem.addActionListener(e -> doNewItem());
            btnDeleteSelected.addActionListener(e -> doDeleteSelected());
            btnReadAll.addActionListener(e -> doReadAll());
            itemsTable.getSelectionModel().addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting() && !rebuildingItems) doShowItemDetail();
            });
            // The selected item
            btnCopyPath.addActionListener(e -> doCopyPath());
            btnRead.addActionListener(e -> doRevealSecret());
            btnShowSecret.addItemListener(e -> {
                secretView.setRevealed(btnShowSecret.isSelected());
                btnShowSecret.setText(btnShowSecret.isSelected() ? "Hide" : "Show");
            });
            btnCopySecret.addActionListener(e -> doCopySecret());
            forgetSecret.setRepeats(false);
            cbReplaceSecret.addItemListener(e -> {
                if (!cbReplaceSecret.isSelected()) pfDetailNewSecret.setText("");
                updateControls();
            });
            btnSaveItem.addActionListener(e -> doSaveItem());
            btnRevertItem.addActionListener(e -> doRevertItem());
            btnLockItem.addActionListener(e -> doLockItem(true));
            btnUnlockItem.addActionListener(e -> doLockItem(false));
            // Library
            cbPrompts.addItemListener(e -> {
                boolean prompting = cbPrompts.isSelected();
                worker.run(prompting ? "Enable prompts" : "Disable prompts", () -> {
                    client.setPrompting(prompting);
                    return null;
                }, ignored -> autoSync());
            });
            spTimeout.addChangeListener(e -> {
                Duration timeout = Duration.ofSeconds(((Number) spTimeout.getValue()).longValue());
                worker.run("Set the timeout", () -> {
                    client.setTimeout(timeout);
                    return null;
                }, ignored -> autoSync());
            });
            btnDebugRefresh.addActionListener(e -> refreshState());
            // Keyring daemon
            btnKillKeyring.addActionListener(e -> killKeyring());
            btnStartKeyring.addActionListener(e -> startKeyring());
            // Log
            btnClearLog.addActionListener(e -> logArea.setText(""));
            cmbLogLevel.addActionListener(e -> {
                LibraryLog.Threshold threshold = (LibraryLog.Threshold) cmbLogLevel.getSelectedItem();
                libraryLog.setThreshold(threshold);
                log("The library's log shows from %s.", threshold);
            });
            refreshItems.setRepeats(false);
            refreshCollections.setRepeats(false);
            client.onChanges(() -> SwingUtilities.invokeLater(() -> {
                if (collectionOpen) refreshItems.restart();
            }), () -> SwingUtilities.invokeLater(() -> {
                if (connected) refreshCollections.restart();
            }));
        }

        /**
         * Shows what the window can do now, and only that. GTK's look draws a disabled button almost
         * as an enabled one: an action that does not apply is hidden, a place that has nothing to
         * show says what to do instead, and while a call runs the window disables what calls the
         * keyring and shows the wait cursor.
         */
        private void updateControls() {
            boolean busy = worker.isBusy();
            boolean session = connected && !busy;
            boolean idle = collectionOpen && !busy;

            // Toolbar: Connect or Disconnect, Cancel while a call runs
            btnDisconnect.setVisible(connected);
            btnConnect.setVisible(!connected);
            btnDisconnect.setEnabled(connected && !busy);
            btnConnect.setEnabled(!connected && !busy);
            btnCancel.setVisible(busy);
            btnCancel.setEnabled(busy);
            setCursor(Cursor.getPredefinedCursor(busy ? Cursor.WAIT_CURSOR : Cursor.DEFAULT_CURSOR));

            // Collections: the list while connected, Open while one is selected
            collectionsCards.show(collectionsArea, connected ? COLLECTIONS_LIST : COLLECTIONS_DISCONNECTED);
            collectionsTable.setEnabled(connected);
            btnOpenCollection.setVisible(collectionsTable.getSelectedRow() >= 0);
            btnOpenCollection.setEnabled(session && collectionsTable.getSelectedRow() >= 0);
            btnRefreshCollections.setEnabled(session);
            btnNewCollection.setEnabled(session);

            // The open collection: Lock where it is unlocked, Unlock where it is locked, both where
            // the provider does not say; no Delete for a default collection, which the library refuses
            itemsCards.show(itemsArea, collectionOpen ? ITEMS_OPEN : ITEMS_NONE);
            btnLockCollection.setVisible(collectionLocked.map(locked -> !locked).orElse(true));
            btnUnlockCollection.setVisible(collectionLocked.orElse(true));
            btnLockCollection.setEnabled(idle);
            btnUnlockCollection.setEnabled(idle);
            btnRenameCollection.setEnabled(idle);
            btnCloseCollection.setEnabled(idle);
            btnDeleteCollection.setVisible(!defaultOpen);
            btnDeleteCollection.setEnabled(idle && !defaultOpen);
            lblDefaultBanner.setVisible(collectionOpen && defaultOpen);
            lblCollectionState.setText(collectionLocked.map(locked -> locked ? "locked" : "unlocked").orElse("lock state unknown"));

            // Search and the item list
            boolean exact = BY_ATTRIBUTES.equals(cmbSearchMode.getSelectedItem());
            lblFuzziness.setVisible(!exact);
            cmbMaxDistance.setVisible(!exact);
            tfSearch.setEnabled(idle);
            cmbSearchMode.setEnabled(idle);
            cmbMaxDistance.setEnabled(idle);
            btnSearch.setEnabled(idle);
            btnShowAll.setVisible(shownQuery.isPresent());
            btnShowAll.setEnabled(idle);
            btnRefreshItems.setEnabled(idle);
            itemsTable.setEnabled(collectionOpen);
            btnNewItem.setEnabled(idle);
            btnReadAll.setEnabled(idle);
            int selected = itemsTable.getSelectedRowCount();
            btnDeleteSelected.setVisible(selected > 0);
            btnDeleteSelected.setEnabled(idle && selected > 0);
            btnDeleteSelected.setText(selected > 1 ? "Delete " + selected + " selected…" : "Delete selected…");

            // The selected item: nothing, several, or one
            Optional<KeyringClient.ItemRow> row = selected == 1 ? selectedRow() : Optional.empty();
            detailCards.show(detailArea, selected == 0 ? DETAIL_NONE : selected > 1 ? DETAIL_MANY : DETAIL_ONE);
            lblDetailMany.setText(selected + " items are selected. Delete them with Delete " + selected
                    + " selected…, or select one to see and change it.");
            tfDetailLabel.setEnabled(idle);
            detailAttributes.setEditable(idle);
            btnRead.setEnabled(idle);
            btnShowSecret.setVisible(secretView.isPresent());
            btnCopySecret.setVisible(secretView.isPresent());
            cbReplaceSecret.setEnabled(idle);
            pfDetailNewSecret.setEnabled(idle && cbReplaceSecret.isSelected());
            btnSaveItem.setEnabled(idle);
            btnRevertItem.setEnabled(idle);
            Optional<Boolean> itemLocked = row.flatMap(KeyringClient.ItemRow::locked);
            btnLockItem.setVisible(itemLocked.map(locked -> !locked).orElse(true));
            btnUnlockItem.setVisible(itemLocked.orElse(true));
            btnLockItem.setEnabled(idle);
            btnUnlockItem.setEnabled(idle);

            // Keyring daemon: Stop only gnome-keyring's, while connected; Start while disconnected
            btnKillKeyring.setVisible(connected && gnomeKeyring);
            btnKillKeyring.setEnabled(connected && gnomeKeyring && !busy);
            btnStartKeyring.setVisible(!connected);
            btnStartKeyring.setEnabled(!connected && !busy);
            btnDebugRefresh.setEnabled(!busy);
        }

        private Worker.Listener workerListener() {
            return new Worker.Listener() {
                @Override
                public void started(String what) {
                    // Short, so that Cancel stays on the toolbar beside it.
                    lblStatus.setText(what + "…");
                    lblStatus.setToolTipText("A dialog of the provider may wait for you. Cancel gives up the wait.");
                    updateControls();
                }

                @Override
                public void failed(String what, Throwable failure) {
                    if (failure instanceof CancellationException) log("%s: cancelled.", what);
                    else log("%s FAILED: %s", what.toUpperCase(Locale.ROOT), exceptionDetail(failure));
                }

                @Override
                public void idle() {
                    lblStatus.setText(READY);
                    lblStatus.setToolTipText(null);
                    updateControls();
                }
            };
        }

        // ── Connect / Disconnect ──────────────────────────────────────

        private void doConnect() {
            record Connection(Optional<List<KeyringClient.CollectionEntry>> collections, boolean gnomeKeyring) {
            }
            worker.run("Connect", () -> {
                Optional<List<KeyringClient.CollectionEntry>> collections = client.connect();
                return new Connection(collections, collections.isPresent() && client.isGnomeKeyring());
            }, connection -> {
                Optional<List<KeyringClient.CollectionEntry>> collections = connection.collections();
                if (collections.isPresent()) {
                    connected = true;
                    gnomeKeyring = connection.gnomeKeyring();
                    showCollections(collections.get());
                    updateConnectionIcon(true);
                    updateControls();
                }
                refreshState();
            });
        }

        private void doRefreshCollections() {
            worker.run("List collections", client::listCollections, this::showCollections);
        }

        /** Shows the collections, and keeps the selected one selected where it is among them. */
        private void showCollections(List<KeyringClient.CollectionEntry> entries) {
            int selectedRow = collectionsTable.getSelectedRow();
            String selected = selectedRow < 0 ? null
                    : collectionEntries.get(collectionsTable.convertRowIndexToModel(selectedRow)).path();
            collectionEntries = List.copyOf(entries);
            collectionsModel.setRowCount(0);
            for (KeyringClient.CollectionEntry entry : entries) {
                String name = displayName(entry.label(), entry.id());
                collectionsModel.addRow(new Object[]{entry.isDefault() ? name + " (default)" : name,
                        entry.locked().map(locked -> locked ? "yes" : "no").orElse("?")});
                // The list tells the open collection's lock state too.
                if (collectionOpen && entry.path().equals(collectionPath)) collectionLocked = entry.locked();
            }
            for (int i = 0; selected != null && i < entries.size(); i++) {
                if (entries.get(i).path().equals(selected)) {
                    int view = collectionsTable.convertRowIndexToView(i);
                    collectionsTable.setRowSelectionInterval(view, view);
                }
            }
            updateControls();
        }

        private void doOpenCollection() {
            int row = collectionsTable.getSelectedRow();
            if (row < 0) {
                log("Select a collection first.");
                return;
            }
            KeyringClient.CollectionEntry entry = collectionEntries.get(collectionsTable.convertRowIndexToModel(row));
            boolean acknowledged = entry.isDefault() && acknowledgeDefaultRisk(entry.label());
            if (entry.isDefault() && !acknowledged) {
                log("Not opened: the risk of the default collection was not acknowledged.");
                return;
            }
            worker.run("Open collection", () -> client.open(entry, acknowledged), this::opened);
        }

        /**
         * Creates a collection through the dialog New collection, which takes a label that no
         * collection of the provider has: an existing one opens from the list.
         */
        private void doNewCollection() {
            java.util.Set<String> labels = new java.util.HashSet<>();
            collectionEntries.forEach(entry -> labels.add(entry.label()));
            Optional<NewCollectionDialog.Result> asked = NewCollectionDialog.ask(this, labels);
            if (asked.isEmpty()) return;
            NewCollectionDialog.Result result = asked.get();
            worker.run("Create collection", () -> {
                try {
                    return client.create(result.label(), CharBuffer.wrap(result.password()));
                } finally {
                    Arrays.fill(result.password(), '\0');
                }
            }, outcome -> {
                opened(outcome);
                doRefreshCollections();
            });
        }

        /**
         * Asks the user to acknowledge the potential risk of damage before a default collection
         * opens: Open stays disabled until the box is ticked.
         *
         * @return whether the user ticked the box and chose Open
         */
        private boolean acknowledgeDefaultRisk(String label) {
            JCheckBox acknowledge = new JCheckBox("I acknowledge the potential risk of damage to this keyring.");
            acknowledge.setName("acknowledge-risk");
            JButton open = new JButton("Open the default collection");
            open.setName("open-default");
            open.setEnabled(false);
            JButton cancel = new JButton("Cancel");
            cancel.setName("cancel-default");
            acknowledge.addItemListener(e -> open.setEnabled(acknowledge.isSelected()));

            JLabel message = new JLabel("<html><body style='width: 380px'>"
                    + "<p><b>\"" + escapeHtml(label) + "\" is a default collection.</b></p><br>"
                    + "<p>It is the keyring of the desktop session: browsers, mail clients and other"
                    + " applications keep their passwords in it, and find them by their attributes."
                    + " Creating, changing or deleting items here can damage what those applications"
                    + " have stored, and a deleted secret cannot be restored.</p><br>"
                    + "<p>Use a collection of its own for testing where you can.</p></body></html>");
            JPanel content = new JPanel(new BorderLayout(0, 10));
            content.add(message, BorderLayout.CENTER);
            content.add(acknowledge, BorderLayout.SOUTH);

            JOptionPane pane = new JOptionPane(content, JOptionPane.WARNING_MESSAGE, JOptionPane.DEFAULT_OPTION,
                    OptionPaneIcons.warning(), new Object[]{open, cancel}, cancel);
            JDialog dialog = pane.createDialog(this, DEFAULT_RISK_TITLE);
            open.addActionListener(e -> {
                pane.setValue(open);
                dialog.dispose();
            });
            cancel.addActionListener(e -> {
                pane.setValue(cancel);
                dialog.dispose();
            });
            dialog.setVisible(true);
            return pane.getValue() == open && acknowledge.isSelected();
        }

        private static String escapeHtml(String text) {
            return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
        }

        /** Shows the collection that an open came to, or what kept it from opening. */
        private void opened(KeyringClient.OpenOutcome outcome) {
            if (outcome.needsAcknowledgement()) {
                log("The collection is a default collection: select it in the list and open it from there.");
                return;
            }
            if (outcome.opened().isEmpty()) return;
            KeyringClient.Opened opened = outcome.opened().get();
            collectionOpen = true;
            defaultOpen = opened.isDefault();
            collectionId = opened.id();
            collectionPath = opened.path() == null ? "" : opened.path();
            collectionLocked = Optional.of(opened.locked());
            collectionName = displayName(opened.label(), opened.id());
            lblCollectionName.setText(collectionName + (opened.isDefault() ? " (default)" : ""));
            showItems(new KeyringClient.ItemListing(List.of(), 0, Optional.empty()));
            clearDetail();
            updateControls();
            // Listing needs no unlock: the window lists a locked collection by its items' properties.
            doListItems();
            autoSync();
        }

        private void doDisconnect() {
            worker.run("Disconnect", () -> {
                client.disconnect();
                return null;
            }, ignored -> {
                disconnected();
                log("Disconnected.");
            });
        }

        /** Closes the open collection and keeps the connection. */
        private void doCloseCollection() {
            worker.run("Close collection", () -> {
                client.close();
                return null;
            }, ignored -> collectionClosed());
        }

        /** Shows the window as it is without a collection. */
        private void collectionClosed() {
            collectionOpen = false;
            listing = null;
            defaultOpen = false;
            collectionName = "";
            collectionPath = "";
            collectionLocked = Optional.empty();
            lblCollectionName.setText(" ");
            showItems(new KeyringClient.ItemListing(List.of(), 0, Optional.empty()));
            clearDetail();
            updateControls();
        }

        /** Shows the window as it is without a connection. */
        private void disconnected() {
            // A refresh that a signal of the closed connection asked for has nothing to refresh.
            refreshItems.stop();
            refreshCollections.stop();
            connected = false;
            gnomeKeyring = false;
            collectionClosed();
            showCollections(List.of());
            updateConnectionIcon(false);
            refreshState();
        }

        /** Gives up a wait for the user, then disconnects on the worker and counts the latch down. */
        private void closed() {
            libraryLog.close();
            worker.cancel();
            worker.run("Close", () -> {
                try {
                    client.disconnect();
                } finally {
                    closeLatch.countDown();
                }
                return null;
            }, ignored -> worker.shutdown());
        }

        // ── The selected item ─────────────────────────────────────────

        /** Empties the fields of the selected item, and forgets a secret that the window has read. */
        private void clearDetail() {
            lblDetailPath.setText(" ");
            lblDetailPath.setToolTipText(null);
            tfDetailLabel.setText("");
            cbReplaceSecret.setSelected(false);
            pfDetailNewSecret.setText("");
            forgetTheSecret();
            detailAttributes.setAttributes(Map.of());
        }

        /** Erases the secret that the window has read, and masks the view again. */
        private void forgetTheSecret() {
            forgetSecret.stop();
            secretView.forget();
            btnShowSecret.setSelected(false);
            updateControls();
        }

        /**
         * Shows the selected item, which the table has read already: its fields where one is
         * selected, a note where several are, and what to do where none is.
         */
        private void doShowItemDetail() {
            Optional<KeyringClient.ItemRow> selected = itemsTable.getSelectedRowCount() == 1 ? selectedRow() : Optional.empty();
            if (selected.isEmpty() || !collectionOpen) {
                clearDetail();
                updateControls();
                return;
            }
            KeyringClient.ItemRow row = selected.get();
            if (!row.path().equals(lblDetailPath.getText())) forgetTheSecret(); // the secret of another item
            lblDetailPath.setText(row.path());
            lblDetailPath.setToolTipText(row.path());
            tfDetailLabel.setText(row.label());
            cbReplaceSecret.setSelected(false);
            pfDetailNewSecret.setText("");
            detailAttributes.setAttributes(row.attributes());
            updateControls();
        }

        private Optional<KeyringClient.ItemRow> selectedRow() {
            int row = itemsTable.getSelectedRow();
            if (row < 0) return Optional.empty();
            return Optional.of(itemRows.get(itemsTable.convertRowIndexToModel(row)));
        }

        /** The path of the one selected item, if one is selected. */
        private Optional<String> detailPath() {
            if (itemsTable.getSelectedRowCount() != 1) return Optional.empty();
            return selectedRow().map(KeyringClient.ItemRow::path);
        }

        private void doCopyPath() {
            detailPath().ifPresent(path -> {
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(path), null);
                log("Copied the path: %s", path);
            });
        }

        private void doRevealSecret() {
            Optional<String> path = detailPath();
            if (path.isEmpty()) return;
            worker.run("Read secret", () -> client.readSecret(path.get()), secret -> {
                forgetTheSecret();
                if (secret.isEmpty()) return;
                if (!path.get().equals(detailPath().orElse(null))) {
                    Arrays.fill(secret.get(), '\0'); // another item is selected meanwhile
                    return;
                }
                secretView.show(secret.get());
                forgetSecret.restart();
                updateControls();
            });
        }

        /**
         * Copies the secret to the clipboard, and clears the clipboard after
         * {@link #CLIPBOARD_MILLIS} unless another copy has replaced it. The clipboard takes only a
         * {@code String}.
         */
        private void doCopySecret() {
            if (!secretView.isPresent()) return;
            char[] copy = secretView.copy();
            StringSelection selection = new StringSelection(new String(copy));
            Arrays.fill(copy, '\0');
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(selection, selection);
            Timer clear = new Timer(CLIPBOARD_MILLIS, e -> {
                try {
                    if (clipboard.isDataFlavorAvailable(DataFlavor.stringFlavor)
                            && selection.getTransferData(DataFlavor.stringFlavor).equals(clipboard.getData(DataFlavor.stringFlavor))) {
                        clipboard.setContents(new StringSelection(""), null);
                        log("Cleared the secret from the clipboard.");
                    }
                } catch (Exception ex) {
                    log("Could not clear the clipboard: %s", ex.getClass().getSimpleName());
                }
            });
            clear.setRepeats(false);
            clear.start();
            log("Copied the secret to the clipboard; it is cleared in %d s.", CLIPBOARD_MILLIS / 1000);
        }

        /**
         * Saves the label and the attributes of the selected item, and its secret where Replace the
         * secret is ticked.
         */
        private void doSaveItem() {
            Optional<String> path = detailPath();
            if (path.isEmpty()) return;
            String label = tfDetailLabel.getText().trim();
            if (label.isEmpty()) {
                log("ERROR: An item needs a label.");
                return;
            }
            boolean replace = cbReplaceSecret.isSelected();
            if (replace && pfDetailNewSecret.getDocument().getLength() == 0) {
                log("ERROR: Type the new secret, or untick Replace the secret.");
                return;
            }
            Map<String, String> attributes = detailAttributes.attributes();
            char[] secret = replace ? pfDetailNewSecret.getPassword() : new char[0];
            pfDetailNewSecret.setText("");
            cbReplaceSecret.setSelected(false);
            worker.run("Save item", () -> {
                try {
                    client.updateItem(path.get(), label, replace ? CharBuffer.wrap(secret) : null, attributes);
                } finally {
                    Arrays.fill(secret, '\0');
                }
                Worker.checkCancelled();
                return listing != null ? listing.call() : client.listItems();
            }, this::showItems);
        }

        /** Puts the selected item's label and attributes back as the table shows them. */
        private void doRevertItem() {
            selectedRow().ifPresent(row -> {
                tfDetailLabel.setText(row.label());
                detailAttributes.setAttributes(row.attributes());
                cbReplaceSecret.setSelected(false);
                pfDetailNewSecret.setText("");
            });
        }

        private void doLockItem(boolean lock) {
            Optional<String> path = detailPath();
            if (path.isEmpty()) return;
            worker.run(lock ? "Lock item" : "Unlock item", () -> {
                if (lock) client.lockItem(path.get());
                else client.unlockItem(path.get());
                Worker.checkCancelled();
                return listing != null ? listing.call() : client.listItems();
            }, this::showItems);
        }

        // ── Items ─────────────────────────────────────────────────────

        /** Creates an item through the dialog New item. */
        private void doNewItem() {
            if (!requireCollection()) return;
            Optional<NewItemDialog.Result> asked = NewItemDialog.ask(this, collectionName);
            if (asked.isEmpty()) return;
            NewItemDialog.Result result = asked.get();
            worker.run("Create item", () -> {
                try {
                    client.createItem(result.label(), CharBuffer.wrap(result.secret()), result.attributes());
                } finally {
                    Arrays.fill(result.secret(), '\0');
                }
                Worker.checkCancelled();
                return client.listItems();
            }, items -> {
                listing = client::listItems; // the table shows every item again
                showItems(items);
                autoSync();
            });
        }

        /** Deletes the selected items, after the user's confirmation and the provider's permission. */
        private void doDeleteSelected() {
            if (!requireCollection()) return;
            List<String> paths = selectedPaths();
            if (paths.isEmpty()) {
                log("Select an item first.");
                return;
            }
            String what = paths.size() == 1
                    ? "Delete the item \"" + selectedRow().map(KeyringClient.ItemRow::label).orElse("?")
                            + "\" from the collection \"" + collectionName + "\"?\n\nPath: " + paths.get(0)
                    : "Delete " + paths.size() + " items from the collection \"" + collectionName + "\"?";
            int confirm = JOptionPane.showConfirmDialog(this, what + "\n\nA deleted secret cannot be restored.",
                    DELETE_ITEMS_TITLE, JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE, OptionPaneIcons.warning());
            if (confirm != JOptionPane.YES_OPTION) return;
            worker.run(paths.size() == 1 ? "Delete item" : "Delete items", () -> {
                if (paths.size() == 1) client.deleteItem(paths.get(0));
                else client.deleteItems(paths);
                Worker.checkCancelled();
                return client.listItems();
            }, items -> {
                listing = client::listItems;
                clearDetail();
                showItems(items);
                autoSync();
            });
        }

        private List<String> selectedPaths() {
            List<String> paths = new java.util.ArrayList<>();
            for (int row : itemsTable.getSelectedRows()) paths.add(itemRows.get(itemsTable.convertRowIndexToModel(row)).path());
            return paths;
        }

        /** Locks the open collection, or unlocks it through the provider's dialog. */
        private void doLockCollection(boolean lock) {
            worker.run(lock ? "Lock collection" : "Unlock collection", () -> {
                if (lock) client.lockCollection();
                else client.unlockCollection();
                Worker.checkCancelled();
                return client.listItems();
            }, items -> {
                listing = client::listItems;
                showItems(items);
                doRefreshCollections();
                autoSync();
            });
        }

        private void doRenameCollection() {
            Object answer = JOptionPane.showInputDialog(this, "New label of the collection \"" + collectionName + "\":",
                    RENAME_TITLE, JOptionPane.QUESTION_MESSAGE, OptionPaneIcons.question(), null, collectionName);
            if (answer == null) return;
            String label = answer.toString().trim();
            if (label.isEmpty()) {
                log("ERROR: A collection needs a label.");
                return;
            }
            worker.run("Rename collection", () -> client.renameCollection(label), renamed -> {
                if (renamed) {
                    collectionName = displayName(label, collectionId);
                    lblCollectionName.setText(collectionName + (defaultOpen ? " (default)" : ""));
                }
                doRefreshCollections();
            });
        }

        /** Lists every item of the open collection, and empties the search, which no longer applies. */
        private void doListItems() {
            if (!requireCollection()) return;
            tfSearch.setText("");
            listing = client::listItems;
            worker.run("List items", listing, this::showItems);
        }

        /** Lists the items again, as the table lists them, after the provider signalled a change. */
        private void doRefreshItems() {
            if (!collectionOpen || listing == null) return;
            worker.run("Refresh items", listing, this::showItems);
        }

        /**
         * Shows the rows, says whether they are all items or what a search found, and keeps the
         * selected items selected where they are among them: the detail, and a secret that it has
         * read, stay.
         */
        private void showItems(KeyringClient.ItemListing shown) {
            List<KeyringClient.ItemRow> rows = shown.rows();
            List<String> selected = selectedPaths();
            rebuildingItems = true;
            try {
                itemRows = List.copyOf(rows);
                itemsModel.setRowCount(0);
                for (KeyringClient.ItemRow row : rows) {
                    String attributes = row.attributes().entrySet().stream()
                            .map(entry -> entry.getKey() + "=" + entry.getValue())
                            .collect(Collectors.joining(", "));
                    itemsModel.addRow(new Object[]{row.label(), attributes, row.path()});
                }
                for (int i = 0; i < rows.size(); i++) {
                    if (selected.contains(rows.get(i).path())) {
                        int view = itemsTable.convertRowIndexToView(i);
                        itemsTable.addRowSelectionInterval(view, view);
                    }
                }
            } finally {
                rebuildingItems = false;
            }
            shownQuery = shown.query();
            lblItemsShown.setText(shown.query()
                    .map(query -> rows.size() + " of " + shown.total() + (shown.total() == 1 ? " item matches " : " items match ") + query + ".")
                    .orElse(rows.size() == 1 ? "1 item." : rows.size() + " items."));
            doShowItemDetail();
        }

        /** Searches the items by the mode, or filters them by exact attributes. */
        private void doSearch() {
            if (!requireCollection()) return;
            String query = tfSearch.getText().trim();
            String mode = (String) cmbSearchMode.getSelectedItem();
            if (BY_ATTRIBUTES.equals(mode)) {
                Optional<Map<String, String>> attributes = parseAttributes(query);
                if (attributes.isEmpty()) return;
                String what = "the attributes " + query;
                listing = () -> client.filter(attributes.get(), what);
                worker.run("Filter", listing, this::showItems);
                return;
            }
            SearchMode searchMode = switch (mode) {
                case "attribute keys" -> SearchMode.BY_ATTRIBUTE_KEY;
                case "attribute values" -> SearchMode.BY_ATTRIBUTE_VALUE;
                case "object ids" -> SearchMode.BY_OBJECT_ID;
                case "object paths" -> SearchMode.BY_OBJECT_PATH;
                default -> SearchMode.BY_NAME;
            };
            int maxDistance = (Integer) cmbMaxDistance.getSelectedItem();
            String what = "\"" + query + "\" in their " + mode + " (fuzziness " + maxDistance + ")";
            listing = () -> client.search(query, searchMode, maxDistance, what);
            worker.run("Search", listing, this::showItems);
        }

        /** The attributes of "key=value, key2=value2", or empty, with an error in the log, for no pair. */
        private Optional<Map<String, String>> parseAttributes(String query) {
            Map<String, String> attributes = new java.util.TreeMap<>();
            for (String pair : query.split(",")) {
                if (pair.isBlank()) continue;
                int equals = pair.indexOf('=');
                if (equals <= 0) {
                    log("ERROR: \"%s\" is no key=value.", pair.trim());
                    return Optional.empty();
                }
                attributes.put(pair.substring(0, equals).trim(), pair.substring(equals + 1).trim());
            }
            if (attributes.isEmpty()) {
                log("ERROR: The filter needs at least one key=value.");
                return Optional.empty();
            }
            return Optional.of(attributes);
        }

        private void doReadAll() {
            if (!requireCollection()) return;
            worker.run("Read all secrets", client::readAllSecrets, read -> autoSync());
        }

        /** Deletes the open collection, after the user's confirmation. */
        private void doDeleteCollection() {
            if (!requireCollection() || defaultOpen) return;
            String name = collectionName;
            int confirm = JOptionPane.showConfirmDialog(this,
                    "Delete the collection \"" + name + "\" and all its items?\n\nThis cannot be undone.",
                    DELETE_COLLECTION_TITLE, JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE, OptionPaneIcons.warning());
            if (confirm != JOptionPane.YES_OPTION) return;
            worker.run("Delete collection", client::deleteCollection, deleted -> {
                if (deleted) {
                    collectionClosed();
                    doRefreshCollections();
                }
            });
        }

        /**
         * Stops gnome-keyring's daemon after the user confirmed it, the process that the bus names
         * as the provider's, no other.
         */
        private void killKeyring() {
            worker.run("Find the keyring daemon", client::providerDaemon, daemon -> {
                if (daemon.isEmpty()) return;
                int confirm = JOptionPane.showConfirmDialog(this,
                        "Stop " + daemon.get().command() + " (process " + daemon.get().pid() + ")?\n\n"
                                + "It serves the Secret Service on this bus. Every application of the desktop\n"
                                + "session loses the keyring until it starts again, and the window disconnects.",
                        KILL_TITLE, JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE, OptionPaneIcons.warning());
                if (confirm != JOptionPane.YES_OPTION) return;
                worker.run("Stop the keyring daemon", () -> client.stop(daemon.get()), stopped -> {
                    disconnected();
                    log("Disconnected.");
                });
            });
        }

        /** Starts gnome-keyring's daemon after the user confirmed it, while the window is disconnected. */
        private void startKeyring() {
            int confirm = JOptionPane.showConfirmDialog(this,
                    "Start gnome-keyring-daemon for the Secret Service of this session?\n\n"
                            + "Where a daemon runs already, it only prints its environment.",
                    START_TITLE, JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE, OptionPaneIcons.question());
            if (confirm != JOptionPane.YES_OPTION) return;
            worker.run("Start the keyring daemon", client::startGnomeKeyring, exit -> { });
        }

        // ── Helpers ───────────────────────────────────────────────

        /** A collection's name in the window: its label, and its id where that differs. */
        private static String displayName(String label, String id) {
            return label.equals(id) ? label : label + " [" + id + "]";
        }

        private boolean requireCollection() {
            if (!collectionOpen) {
                log("No collection is open. Open one first.");
                return false;
            }
            return true;
        }

        private void log(String fmt, Object... args) {
            log(String.format(fmt, args));
        }

        /** Appends the line to the log, from any thread. */
        private void log(String line) {
            String msg = "[" + LocalTime.now().format(TIME_FMT) + "] " + line + System.lineSeparator();
            SwingUtilities.invokeLater(() -> {
                logArea.append(msg);
                logArea.setCaretPosition(logArea.getDocument().getLength());
            });
        }

        // ── Connection status icon ────────────────────────────────────

        private static Icon createCircleIcon(Color color, int size) {
            return new Icon() {
                @Override public void paintIcon(Component c, Graphics g, int x, int y) {
                    Graphics2D g2 = (Graphics2D) g.create();
                    g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                    g2.setColor(color);
                    g2.fillOval(x, y, size, size);
                    g2.dispose();
                }
                @Override public int getIconWidth() { return size; }
                @Override public int getIconHeight() { return size; }
            };
        }

        private static final Icon ICON_ONLINE = createCircleIcon(new Color(0x4CAF50), 12);
        private static final Icon ICON_OFFLINE = createCircleIcon(Color.GRAY, 12);

        private void updateConnectionIcon(boolean connected) {
            lblConnectionStatus.setIcon(connected ? ICON_ONLINE : ICON_OFFLINE);
            lblConnectionStatus.setText(connected ? "Connected" : "Disconnected");
            lblConnectionStatus.setToolTipText(connected ? "Connected" : "Disconnected");
        }

        private static void resetStatusLabel(JLabel label) {
            label.setText("—");
            label.setForeground(Color.GRAY);
        }

        private static void setStatusLabel(JLabel label, boolean value) {
            label.setText(value ? "Yes" : "No");
            label.setForeground(value ? new Color(0x4CAF50) : new Color(0xF44336));
        }

        // ── State refresh ─────────────────────────────────────────

        private void autoSync() {
            if (cbAutoSync.isSelected()) {
                refreshState();
            }
        }

        /** Asks the library's objects for their state on the worker, and shows it. */
        private void refreshState() {
            worker.run("Refresh state", client::state, this::showState);
        }

        private void showState(KeyringClient.State state) {
            if (state.busConnected()) {
                setStatusLabel(lblDbusConnected, true);
                if (state.serviceAvailable()) {
                    setStatusLabel(lblDbusAvailable, true);
                    lblProvider.setText(state.provider());
                    lblProvider.setForeground(new Color(0x4CAF50));
                } else {
                    resetStatusLabel(lblDbusAvailable);
                    resetStatusLabel(lblProvider);
                }
            } else {
                resetStatusLabel(lblDbusConnected);
                resetStatusLabel(lblDbusAvailable);
                resetStatusLabel(lblProvider);
            }
            stateModel.setRowCount(0);
            addRows("System", state.system());
            addRows("Service", state.service());
            addRows("Session", state.session());
            addRows("Collection", state.collection());
        }

        private void addRows(String object, List<KeyringClient.Row> rows) {
            rows.forEach(row -> stateModel.addRow(new Object[]{object, row.property(), row.value()}));
        }

        private static String exceptionDetail(Throwable ex) {
            StringWriter sw = new StringWriter();
            ex.printStackTrace(new PrintWriter(sw));
            // Return first 3 lines for brevity
            String[] lines = sw.toString().split("\\R", 4);
            return String.join("\n", Arrays.copyOf(lines, Math.min(lines.length, 3)));
        }
    }
}

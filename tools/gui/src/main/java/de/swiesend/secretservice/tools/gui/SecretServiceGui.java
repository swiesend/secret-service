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
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {
        }
        SecretServiceFrame frame = new SecretServiceFrame(closed);
        frame.setVisible(true);
        return frame;
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
        static final String KILL_TITLE = "Kill Keyring";
        /** The search mode that lists the items with exactly the attributes "key=value, ...". */
        private static final String BY_ATTRIBUTES = "By Attributes (exact)";
        static final String RENAME_TITLE = "Rename collection";
        /** How long the window waits after a signal of the provider, which come in bursts. */
        private static final int REFRESH_DELAY_MILLIS = 300;
        static final String START_TITLE = "Start Keyring";
        /** How long the window keeps a secret that it has read. */
        private static final int SECRET_SHOWN_MILLIS = 60_000;
        /** How long the clipboard keeps a secret that the window copied there. */
        static final int CLIPBOARD_MILLIS = 30_000;
        private static final char ECHO_CHAR = new JPasswordField().getEchoChar();

        // Collection panel: the provider's collections, and a new one
        private final DefaultTableModel collectionsModel = readOnlyTableModel("Collection", "Locked");
        private final JTable collectionsTable = new JTable(collectionsModel);
        private List<KeyringClient.CollectionEntry> collectionEntries = List.of();
        private final JButton btnOpenCollection = new JButton("Open");
        private final JButton btnRefreshCollections = new JButton("Refresh");
        private final JLabel lblOpenCollection = new JLabel("No collection is open.");
        /** The label of a new collection, which the provider creates, or opens if it has one. */
        private final JTextField tfCollectionLabel = new JTextField(12);
        private final JPasswordField pfCollectionPassword = new JPasswordField(12);
        private final JButton btnCreateCollection = new JButton("Create / open");
        /** Shows while a default collection is open. */
        private final JLabel lblDefaultBanner = new JLabel(
                "Default collection: changes affect every application of the desktop session.");

        // Create-item panel
        private final JTextField tfLabel = new JTextField(20);
        private final JPasswordField pfSecret = new JPasswordField(20);
        private final JCheckBox cbShowNewSecret = new JCheckBox("Show");
        private final AttributesEditor createAttributes = new AttributesEditor("item-attributes");

        // Items list
        private final DefaultTableModel itemsModel = readOnlyTableModel("Label", "Attributes", "Path");
        private final JTable itemsTable = new JTable(itemsModel);
        private List<KeyringClient.ItemRow> itemRows = List.of();
        /** While the table is rebuilt, its selection changes say nothing about the user's. */
        private boolean rebuildingItems = false;
        /** What lists the items that the table shows: all of them, or the last search. */
        private Callable<List<KeyringClient.ItemRow>> listing;
        /** Refresh the items and the collections a moment after the provider signals a change. */
        private final Timer refreshItems = new Timer(REFRESH_DELAY_MILLIS, e -> doRefreshItems());
        private final Timer refreshCollections = new Timer(REFRESH_DELAY_MILLIS, e -> doRefreshCollections());

        // Search bar (items panel)
        private final JTextField tfSearch = new JTextField(14);
        private final JComboBox<String> cmbSearchMode = new JComboBox<>(new String[]{"By Name", "By Attribute Key", "By Attribute Value", "By Object ID", "By Object Path", BY_ATTRIBUTES});
        private final JButton btnReadAll = new JButton("Read all");
        // Library settings
        private final JCheckBox cbPrompts = new JCheckBox("Prompts", true);
        private final JSpinner spTimeout = new JSpinner(new SpinnerNumberModel(120, 1, 3600, 5));
        private final JComboBox<Integer> cmbMaxDistance = new JComboBox<>(new Integer[]{0, 1, 2, 3});
        private final JButton btnSearch = new JButton("Search");

        // Item detail panel (shown on selection)
        /** Read-only, so that the path can be selected and copied. */
        private final JTextField tfDetailPath = new JTextField();
        private final JTextField tfDetailLabel = new JTextField(16);
        /** A new secret for the selected item: empty, the item keeps its secret. */
        private final JPasswordField pfDetailNewSecret = new JPasswordField(16);
        private final AttributesEditor detailAttributes = new AttributesEditor("detail-attributes");
        private final JButton btnSaveItem = new JButton("Save");
        private final JButton btnLockItem = new JButton("Lock");
        private final JButton btnUnlockItem = new JButton("Unlock");
        private final SecretView secretView = new SecretView();
        private final JToggleButton btnShowSecret = new JToggleButton("Show");
        private final JButton btnCopySecret = new JButton("Copy");
        /** Forgets a secret that the window has read, a minute after it read it. */
        private final Timer forgetSecret = new Timer(SECRET_SHOWN_MILLIS, e -> forgetTheSecret());
        // Collection actions
        private final JButton btnLockCollection = new JButton("Lock");
        private final JButton btnUnlockCollection = new JButton("Unlock");
        private final JButton btnRenameCollection = new JButton("Rename");

        // Log area
        private final JTextArea logArea = new JTextArea();
        private final JComboBox<LibraryLog.Threshold> cmbLogLevel = new JComboBox<>(LibraryLog.Threshold.values());
        /** The library's log, in {@link #logArea}. */
        private final LibraryLog libraryLog = new LibraryLog(this::log, LibraryLog.Threshold.INFO);

        // Buttons
        private final JButton btnConnect = new JButton("Connect");
        private final JButton btnDisconnect = new JButton("Disconnect");
        private final JButton btnCreate = new JButton("Create");
        private final JButton btnClearCreate = new JButton("Clear");
        private final JButton btnRead = new JButton("Read Secret");
        private final JButton btnDeleteItem = new JButton("Delete Item");
        private final JButton btnList = new JButton("List All");
        private final JButton btnDeleteCollection = new JButton("Delete Collection");
        private final JButton btnKillKeyring = new JButton("Kill Keyring");
        private final JButton btnStartKeyring = new JButton("Start Keyring");
        private final JButton btnClearLog = new JButton("Clear Log");

        // Debug tab — state tables
        private final DefaultTableModel debugSystemModel = readOnlyTableModel("Property", "Value");
        private final DefaultTableModel debugServiceModel = readOnlyTableModel("Property", "Value");
        private final DefaultTableModel debugSessionModel = readOnlyTableModel("Property", "Value");
        private final DefaultTableModel debugCollectionModel = readOnlyTableModel("Property", "Value");
        private final JButton btnDebugRefresh = new JButton("Refresh State");
        private final JCheckBox cbAutoSync = new JCheckBox("Auto-sync", true);

        // Connection status icon
        private final JLabel lblConnectionStatus = new JLabel();

        // System panel — D-Bus status labels
        private final JLabel lblDbusConnected = new JLabel("—");
        private final JLabel lblDbusAvailable = new JLabel("—");
        private final JLabel lblProvider = new JLabel("—");

        // Busy state: what the worker does, and Cancel, which gives up a wait for the provider
        private static final String READY = "Ready";
        private final JLabel lblStatus = new JLabel(READY);
        private final JButton btnCancel = new JButton("Cancel");

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
            super("Secret Service — System Test");
            this.closeLatch = closeLatch;
            setDefaultCloseOperation(DISPOSE_ON_CLOSE);
            addWindowListener(new WindowAdapter() {
                @Override
                public void windowClosed(WindowEvent e) {
                    closed();
                }
            });
            buildUi();
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
            lblOpenCollection.setName("open-collection-name");
            tfCollectionLabel.setName("collection-label");
            btnCreateCollection.setName("create-collection");
            lblDefaultBanner.setName("default-banner");
            pfCollectionPassword.setName("collection-password");
            tfLabel.setName("item-label");
            pfSecret.setName("item-secret");
            cbShowNewSecret.setName("show-new-secret");
            btnCreate.setName("create-item");
            btnClearCreate.setName("clear-item");
            itemsTable.setName("items");
            tfSearch.setName("search");
            cmbSearchMode.setName("search-mode");
            cmbMaxDistance.setName("search-distance");
            btnSearch.setName("search-items");
            btnList.setName("list-items");
            btnReadAll.setName("read-all");
            cbPrompts.setName("prompts");
            spTimeout.setName("timeout");
            tfDetailPath.setName("detail-path");
            tfDetailLabel.setName("detail-label");
            pfDetailNewSecret.setName("detail-new-secret");
            btnSaveItem.setName("save-item");
            btnLockItem.setName("lock-item");
            btnUnlockItem.setName("unlock-item");
            btnLockCollection.setName("lock-collection");
            btnUnlockCollection.setName("unlock-collection");
            btnRenameCollection.setName("rename-collection");
            secretView.setName("detail-secret");
            btnShowSecret.setName("show-secret");
            btnCopySecret.setName("copy-secret");
            btnRead.setName("read-secret");
            btnDeleteItem.setName("delete-item");
            btnDeleteCollection.setName("delete-collection");
            btnKillKeyring.setName("kill-keyring");
            btnStartKeyring.setName("start-keyring");
            logArea.setName("log");
            cmbLogLevel.setName("log-level");
            btnClearLog.setName("clear-log");
            btnDebugRefresh.setName("refresh-state");
            cbAutoSync.setName("auto-sync");
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

            JTabbedPane bottom = new JTabbedPane();
            bottom.setName("bottom-tabs");
            bottom.addTab("Log", buildLogPanel());
            bottom.addTab("State", buildStateTab());
            bottom.addTab("Danger zone", buildDangerZone());

            JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, work, bottom);
            split.setResizeWeight(1.0); // a taller window gives its height to the items
            split.setBorder(null);
            content.add(split, BorderLayout.CENTER);
            setContentPane(content);
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
            updateConnectionIcon(false);

            JPanel panel = new JPanel(new BorderLayout());
            panel.add(bar, BorderLayout.CENTER);
            panel.add(new JSeparator(), BorderLayout.SOUTH);
            return panel;
        }

        private JPanel buildCollectionPanel() {
            collectionsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            collectionsTable.setFillsViewportHeight(true);
            collectionsTable.getColumnModel().getColumn(1).setMaxWidth(60);
            collectionsTable.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    if (e.getClickCount() == 2 && btnOpenCollection.isEnabled()) doOpenCollection();
                }
            });
            JScrollPane tableScroll = new JScrollPane(collectionsTable);
            tableScroll.setPreferredSize(new Dimension(COLLECTION_PANEL_WIDTH, 120));

            JPanel listButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
            listButtons.add(btnOpenCollection);
            listButtons.add(btnRefreshCollections);

            JPanel existing = new JPanel(new BorderLayout(4, 4));
            existing.add(tableScroll, BorderLayout.CENTER);
            JPanel below = new JPanel(new BorderLayout(4, 4));
            JPanel openButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
            openButtons.add(btnLockCollection);
            openButtons.add(btnUnlockCollection);
            openButtons.add(btnRenameCollection);
            below.add(listButtons, BorderLayout.NORTH);
            below.add(lblOpenCollection, BorderLayout.CENTER);
            below.add(openButtons, BorderLayout.SOUTH);
            existing.add(below, BorderLayout.SOUTH);

            JPanel create = new JPanel(new GridBagLayout());
            create.setBorder(new TitledBorder("New collection"));
            addRow(create, 0, "Label:", tfCollectionLabel);
            addRow(create, 1, "Password:", pfCollectionPassword);
            GridBagConstraints gbc = gbc();
            gbc.gridx = 1; gbc.gridy = 2; gbc.anchor = GridBagConstraints.WEST; gbc.fill = GridBagConstraints.NONE;
            create.add(btnCreateCollection, gbc);
            JLabel hint = new JLabel("<html><small><i>An empty password lets the provider ask for it."
                    + " A label that the provider has opens that collection.</i></small></html>");
            hint.setPreferredSize(new Dimension(COLLECTION_PANEL_WIDTH - 20, 40));
            gbc = gbc();
            gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 2;
            create.add(hint, gbc);

            JPanel panel = new JPanel(new BorderLayout(4, 6));
            panel.setBorder(new TitledBorder("Collections"));
            panel.add(existing, BorderLayout.CENTER);
            panel.add(create, BorderLayout.SOUTH);
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

        private JPanel buildItemsPanel() {
            JPanel panel = new JPanel(new BorderLayout(4, 4));
            panel.setBorder(new TitledBorder("Items"));
            lblDefaultBanner.setOpaque(true);
            lblDefaultBanner.setBackground(DANGER);
            lblDefaultBanner.setForeground(Color.WHITE);
            lblDefaultBanner.setBorder(new EmptyBorder(4, 6, 4, 6));
            lblDefaultBanner.setVisible(false);
            JPanel north = new JPanel(new BorderLayout(4, 4));
            north.add(lblDefaultBanner, BorderLayout.NORTH);
            north.add(buildSearchBar(), BorderLayout.SOUTH);
            panel.add(north, BorderLayout.NORTH);

            // Several rows for Delete; the detail shows the first of them.
            itemsTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
            itemsTable.setFillsViewportHeight(true);
            itemsTable.setAutoCreateRowSorter(true);
            itemsTable.getColumnModel().getColumn(0).setPreferredWidth(140);
            itemsTable.getColumnModel().getColumn(1).setPreferredWidth(200);
            itemsTable.getColumnModel().getColumn(2).setPreferredWidth(260);
            JScrollPane listScroll = new JScrollPane(itemsTable);
            listScroll.setPreferredSize(new Dimension(420, 150));
            listScroll.setMinimumSize(new Dimension(200, 80));

            JTabbedPane itemTabs = new JTabbedPane();
            itemTabs.setName("item-tabs");
            itemTabs.addTab("Selected item", buildDetailPanel());
            itemTabs.addTab("New item", buildCreatePanel());

            JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, listScroll, itemTabs);
            split.setResizeWeight(0.5);
            split.setBorder(null);
            panel.add(split, BorderLayout.CENTER);
            return panel;
        }

        private JPanel buildSearchBar() {
            cmbMaxDistance.setSelectedItem(1);
            cmbMaxDistance.setToolTipText("<html>Fuzzy search tolerance (Levenshtein distance):<br>"
                    + "<b>0</b> - substring match only (fastest, exact)<br>"
                    + "<b>1</b> - tolerates 1 typo / transposition<br>"
                    + "<b>2</b> - tolerates 2 edits<br>"
                    + "<b>3</b> - very loose matching</html>");
            JLabel lblDistance = new JLabel("~");
            lblDistance.setToolTipText("Fuzzy distance: 0 = exact substring, 1-3 = tolerate typos");

            JPanel options = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
            options.add(cmbSearchMode);
            options.add(lblDistance);
            options.add(cmbMaxDistance);
            options.add(btnSearch);
            options.add(btnList);
            btnReadAll.setToolTipText("Reads every secret of the collection through withSecrets, and tells only how many");
            options.add(btnReadAll);

            JPanel bar = new JPanel(new BorderLayout(4, 0));
            bar.add(tfSearch, BorderLayout.CENTER);
            bar.add(options, BorderLayout.EAST);
            return bar;
        }

        private JPanel buildDetailPanel() {
            JPanel form = new JPanel(new GridBagLayout());
            tfDetailPath.setEditable(false);
            tfDetailPath.setBorder(BorderFactory.createEmptyBorder());
            tfDetailPath.setOpaque(false);
            addRow(form, 0, "Path:", tfDetailPath);
            addRow(form, 1, "Label:", tfDetailLabel);

            JPanel secret = new JPanel(new BorderLayout(4, 0));
            secret.add(secretView, BorderLayout.CENTER);
            JPanel secretButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
            secretButtons.add(btnRead);
            secretButtons.add(btnShowSecret);
            secretButtons.add(btnCopySecret);
            secret.add(secretButtons, BorderLayout.EAST);
            addRow(form, 2, "Secret:", secret);
            pfDetailNewSecret.setToolTipText("Leave empty to keep the secret");
            addRow(form, 3, "New secret:", pfDetailNewSecret);

            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
            buttons.add(btnSaveItem);
            buttons.add(btnLockItem);
            buttons.add(btnUnlockItem);
            buttons.add(btnDeleteItem);
            GridBagConstraints gbc = gbc();
            gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2; gbc.anchor = GridBagConstraints.NORTHWEST;
            gbc.fill = GridBagConstraints.NONE; gbc.weighty = 1.0;
            form.add(buttons, gbc);

            JPanel panel = new JPanel(new BorderLayout(6, 0));
            panel.setBorder(new EmptyBorder(2, 2, 2, 2));
            panel.add(form, BorderLayout.CENTER);
            panel.add(detailAttributes, BorderLayout.EAST);
            return panel;
        }

        private JPanel buildCreatePanel() {
            JPanel form = new JPanel(new GridBagLayout());
            addRow(form, 0, "Label:", tfLabel);
            JPanel secret = new JPanel(new BorderLayout(4, 0));
            secret.add(pfSecret, BorderLayout.CENTER);
            secret.add(cbShowNewSecret, BorderLayout.EAST);
            addRow(form, 1, "Secret:", secret);

            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
            buttons.add(btnCreate);
            buttons.add(btnClearCreate);
            GridBagConstraints gbc = gbc();
            gbc.gridx = 1; gbc.gridy = 2; gbc.anchor = GridBagConstraints.NORTHWEST;
            gbc.fill = GridBagConstraints.NONE; gbc.weighty = 1.0;
            form.add(buttons, gbc);

            JPanel panel = new JPanel(new BorderLayout(6, 0));
            panel.setBorder(new EmptyBorder(2, 2, 2, 2));
            panel.add(form, BorderLayout.CENTER);
            panel.add(createAttributes, BorderLayout.EAST);
            return panel;
        }

        private JPanel buildStateTab() {
            JPanel tables = new JPanel(new GridLayout(2, 2, 6, 6));
            tables.add(buildStateSection("System", debugSystemModel));
            tables.add(buildStateSection("Service", debugServiceModel));
            tables.add(buildStateSection("Session", debugSessionModel));
            tables.add(buildStateSection("Collection", debugCollectionModel));

            JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
            cbPrompts.setToolTipText("<html>Whether the library may raise the provider's prompts (enablePrompt, disablePrompt).<br>"
                    + "Without them, the provider alone decides what a call may do.</html>");
            spTimeout.setToolTipText("How long the library waits for a prompt (ServiceInterface.setTimeout)");
            controls.add(new JLabel("Library:"));
            controls.add(cbPrompts);
            controls.add(new JLabel("Timeout (s):"));
            controls.add(spTimeout);
            controls.add(new JSeparator(SwingConstants.VERTICAL));
            controls.add(cbAutoSync);
            controls.add(btnDebugRefresh);

            JPanel panel = new JPanel(new BorderLayout(4, 4));
            panel.setBorder(new EmptyBorder(4, 4, 4, 4));
            panel.add(tables, BorderLayout.CENTER);
            panel.add(controls, BorderLayout.SOUTH);
            return panel;
        }

        private static JPanel buildStateSection(String title, DefaultTableModel model) {
            JPanel panel = new JPanel(new BorderLayout());
            panel.setBorder(new TitledBorder(title));
            JTable table = new JTable(model);
            table.setName("state-" + title.toLowerCase(Locale.ROOT));
            table.setFillsViewportHeight(true);
            JScrollPane scroll = new JScrollPane(table);
            // Each table scrolls within its share: the tab keeps the height of the log.
            scroll.setPreferredSize(new Dimension(200, 40));
            panel.add(scroll, BorderLayout.CENTER);
            return panel;
        }

        private JPanel buildDangerZone() {
            btnDeleteCollection.setForeground(DANGER);
            btnKillKeyring.setForeground(DANGER);
            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 4));
            buttons.add(btnDeleteCollection);
            buttons.add(btnKillKeyring);
            buttons.add(btnStartKeyring);

            JLabel warning = new JLabel("<html>These change the keyring beyond one item, and can affect"
                    + " every application of the desktop session. Each asks before it acts. Kill stops"
                    + " the gnome-keyring daemon that serves this bus, and only that one; Start starts"
                    + " one while the window is disconnected.</html>");
            warning.setForeground(DANGER);

            JPanel panel = new JPanel(new BorderLayout(4, 4));
            panel.setBorder(new EmptyBorder(6, 6, 6, 6));
            panel.add(warning, BorderLayout.NORTH);
            panel.add(buttons, BorderLayout.CENTER);
            return panel;
        }

        private JPanel buildLogPanel() {
            JPanel panel = new JPanel(new BorderLayout(4, 4));
            panel.setBorder(new EmptyBorder(4, 4, 4, 4));
            logArea.setEditable(false);
            logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            JScrollPane scroll = new JScrollPane(logArea);
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
            btnDisconnect.addActionListener(e -> doDisconnect());
            btnOpenCollection.addActionListener(e -> doOpenCollection());
            btnRefreshCollections.addActionListener(e -> doRefreshCollections());
            btnCreateCollection.addActionListener(e -> doCreateCollection());
            tfCollectionLabel.addActionListener(e -> doCreateCollection());
            collectionsTable.getSelectionModel().addListSelectionListener(e -> updateControls());
            btnCancel.addActionListener(e -> {
                log("Cancelling: %s", lblStatus.getText());
                worker.cancel();
            });
            btnCreate.addActionListener(e -> doCreate());
            cbShowNewSecret.addItemListener(e ->
                    pfSecret.setEchoChar(cbShowNewSecret.isSelected() ? (char) 0 : ECHO_CHAR));
            btnShowSecret.addItemListener(e -> secretView.setRevealed(btnShowSecret.isSelected()));
            btnCopySecret.addActionListener(e -> doCopySecret());
            forgetSecret.setRepeats(false);
            btnClearCreate.addActionListener(e -> {
                tfLabel.setText("");
                pfSecret.setText("");
                createAttributes.setAttributes(Map.of());
            });
            btnRead.addActionListener(e -> doRevealSecret());
            btnDeleteItem.addActionListener(e -> doDeleteItem());
            btnSaveItem.addActionListener(e -> doSaveItem());
            btnLockItem.addActionListener(e -> doLockItem(true));
            btnUnlockItem.addActionListener(e -> doLockItem(false));
            btnLockCollection.addActionListener(e -> doLockCollection(true));
            btnUnlockCollection.addActionListener(e -> doLockCollection(false));
            btnRenameCollection.addActionListener(e -> doRenameCollection());
            btnList.addActionListener(e -> doListItems());
            btnReadAll.addActionListener(e -> doReadAll());
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
            btnSearch.addActionListener(e -> doSearch());
            // Allow pressing Enter in the search field to trigger search
            tfSearch.addActionListener(e -> doSearch());
            btnDeleteCollection.addActionListener(e -> doDeleteCollection());
            btnKillKeyring.addActionListener(e -> killKeyring());
            btnStartKeyring.addActionListener(e -> startKeyring());
            btnClearLog.addActionListener(e -> logArea.setText(""));
            cmbLogLevel.addActionListener(e -> {
                LibraryLog.Threshold threshold = (LibraryLog.Threshold) cmbLogLevel.getSelectedItem();
                libraryLog.setThreshold(threshold);
                log("The library's log shows from %s.", threshold);
            });
            itemsTable.getSelectionModel().addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting() && !rebuildingItems) doShowItemDetail();
            });
            refreshItems.setRepeats(false);
            refreshCollections.setRepeats(false);
            client.onChanges(() -> SwingUtilities.invokeLater(() -> {
                if (collectionOpen) refreshItems.restart();
            }), () -> SwingUtilities.invokeLater(() -> {
                if (connected) refreshCollections.restart();
            }));
            btnDebugRefresh.addActionListener(e -> refreshState());
        }

        /**
         * Enables what the window can do now: nothing that calls the keyring while the worker is
         * busy, and the item controls only while a collection is open.
         */
        private void updateControls() {
            boolean busy = worker.isBusy();
            boolean items = collectionOpen && !busy;
            tfLabel.setEnabled(items);
            pfSecret.setEnabled(items);
            cbShowNewSecret.setEnabled(items);
            btnShowSecret.setEnabled(items && secretView.isPresent());
            btnCopySecret.setEnabled(items && secretView.isPresent());
            createAttributes.setEditable(items);
            boolean selected = items && !tfDetailPath.getText().isEmpty();
            tfDetailLabel.setEnabled(selected);
            pfDetailNewSecret.setEnabled(selected);
            detailAttributes.setEditable(selected);
            btnSaveItem.setEnabled(selected);
            btnLockItem.setEnabled(selected);
            btnUnlockItem.setEnabled(selected);
            btnLockCollection.setEnabled(items);
            btnUnlockCollection.setEnabled(items);
            btnRenameCollection.setEnabled(items);
            btnCreate.setEnabled(items);
            btnClearCreate.setEnabled(items);
            btnRead.setEnabled(items);
            btnDeleteItem.setEnabled(items);
            btnList.setEnabled(items);
            btnReadAll.setEnabled(items);
            btnSearch.setEnabled(items);
            tfSearch.setEnabled(items);
            cmbSearchMode.setEnabled(items);
            cmbMaxDistance.setEnabled(items);
            // The library refuses to delete a default collection, and so does the window.
            btnDeleteCollection.setEnabled(items && !defaultOpen);
            itemsTable.setEnabled(items);
            btnDisconnect.setEnabled(connected && !busy);
            btnConnect.setEnabled(!connected && !busy);
            // Only gnome-keyring's daemon, which the window can find; started only where none serves.
            btnKillKeyring.setEnabled(connected && gnomeKeyring && !busy);
            btnStartKeyring.setEnabled(!connected && !busy);
            btnDebugRefresh.setEnabled(!busy);
            btnCancel.setEnabled(busy);
            boolean session = connected && !busy;
            collectionsTable.setEnabled(session);
            btnOpenCollection.setEnabled(session && collectionsTable.getSelectedRow() >= 0);
            btnRefreshCollections.setEnabled(session);
            tfCollectionLabel.setEnabled(session);
            pfCollectionPassword.setEnabled(session);
            btnCreateCollection.setEnabled(session);
            lblDefaultBanner.setVisible(collectionOpen && defaultOpen);
        }

        private Worker.Listener workerListener() {
            return new Worker.Listener() {
                @Override
                public void started(String what) {
                    lblStatus.setText(what + "... (a dialog of the provider may wait for you)");
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

        private void doCreateCollection() {
            String label = tfCollectionLabel.getText().trim();
            if (label.isEmpty()) {
                log("ERROR: A new collection needs a label.");
                return;
            }
            // A label of a default collection opens that one: only after the acknowledgement.
            Optional<KeyringClient.CollectionEntry> listed = collectionEntries.stream()
                    .filter(entry -> entry.label().equals(label))
                    .findFirst();
            boolean acknowledged = false;
            if (listed.isPresent() && listed.get().isDefault()) {
                acknowledged = acknowledgeDefaultRisk(label);
                if (!acknowledged) {
                    log("Not opened: the risk of the default collection was not acknowledged.");
                    return;
                }
            }
            char[] password = pfCollectionPassword.getPassword();
            pfCollectionPassword.setText("");
            boolean finalAcknowledged = acknowledged;
            worker.run("Open collection", () -> {
                try {
                    return client.create(label, CharBuffer.wrap(password), finalAcknowledged);
                } finally {
                    Arrays.fill(password, '\0');
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
                    null, new Object[]{open, cancel}, cancel);
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
            collectionName = displayName(opened.label(), opened.id());
            lblOpenCollection.setText("Open: " + collectionName + (opened.isDefault() ? " (default)" : ""));
            showItems(List.of());
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

        /** Shows the window as it is without a collection. */
        private void collectionClosed() {
            collectionOpen = false;
            listing = null;
            defaultOpen = false;
            collectionName = "";
            lblOpenCollection.setText("No collection is open.");
            showItems(List.of());
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

        // ── Item detail (on selection) ─────────────────────────────

        private void clearDetail() {
            tfDetailPath.setText("");
            tfDetailLabel.setText("");
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

        /** Shows the selected row: the table has read its label and attributes already. */
        private void doShowItemDetail() {
            Optional<KeyringClient.ItemRow> selected = selectedRow();
            if (selected.isEmpty() || !collectionOpen) {
                clearDetail();
                return;
            }
            KeyringClient.ItemRow row = selected.get();
            if (!row.path().equals(tfDetailPath.getText())) forgetTheSecret(); // the secret of another item
            tfDetailPath.setText(row.path());
            tfDetailPath.setCaretPosition(0);
            tfDetailLabel.setText(row.label());
            pfDetailNewSecret.setText("");
            detailAttributes.setAttributes(row.attributes());
            updateControls();
        }

        private Optional<KeyringClient.ItemRow> selectedRow() {
            int row = itemsTable.getSelectedRow();
            if (row < 0) return Optional.empty();
            return Optional.of(itemRows.get(itemsTable.convertRowIndexToModel(row)));
        }

        /** The path of the item that the detail shows, if it shows one. */
        private Optional<String> detailPath() {
            String path = tfDetailPath.getText().trim();
            if (path.isEmpty()) {
                log("Select an item first.");
                return Optional.empty();
            }
            return Optional.of(path);
        }

        private void doRevealSecret() {
            if (!requireCollection()) return;
            Optional<String> path = detailPath();
            if (path.isEmpty()) return;
            worker.run("Read secret", () -> client.readSecret(path.get()), secret -> {
                forgetTheSecret();
                if (secret.isEmpty()) return;
                if (!path.get().equals(tfDetailPath.getText().trim())) {
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

        // ── CRUD ──────────────────────────────────────────────────

        private void doCreate() {
            if (!requireCollection()) return;
            String label = tfLabel.getText().trim();
            if (label.isEmpty() || pfSecret.getDocument().getLength() == 0) {
                log("ERROR: Label and secret are required to create an item.");
                return;
            }
            char[] secret = pfSecret.getPassword();
            pfSecret.setText("");
            Map<String, String> attributes = createAttributes.attributes();
            worker.run("Create item", () -> {
                try {
                    client.createItem(label, CharBuffer.wrap(secret), attributes);
                } finally {
                    Arrays.fill(secret, '\0');
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
        private void doDeleteItem() {
            if (!requireCollection()) return;
            List<String> paths = selectedPaths();
            if (paths.isEmpty()) {
                log("Select an item first.");
                return;
            }
            String what = paths.size() == 1
                    ? "Delete item from collection \"" + collectionName + "\"?\n\n"
                            + "Label: " + tfDetailLabel.getText() + "\n" + "Path:  " + paths.get(0)
                    : "Delete " + paths.size() + " items from collection \"" + collectionName + "\"?";
            int confirm = JOptionPane.showConfirmDialog(this, what,
                    "Confirm Delete Item", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
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

        /** Saves the label, the attributes and, where one is typed, a new secret of the selected item. */
        private void doSaveItem() {
            Optional<String> path = detailPath();
            if (path.isEmpty()) return;
            String label = tfDetailLabel.getText().trim();
            if (label.isEmpty()) {
                log("ERROR: An item needs a label.");
                return;
            }
            Map<String, String> attributes = detailAttributes.attributes();
            char[] secret = pfDetailNewSecret.getPassword();
            pfDetailNewSecret.setText("");
            worker.run("Save item", () -> {
                try {
                    client.updateItem(path.get(), label, secret.length == 0 ? null : CharBuffer.wrap(secret), attributes);
                } finally {
                    Arrays.fill(secret, '\0');
                }
                Worker.checkCancelled();
                return listing != null ? listing.call() : client.listItems();
            }, this::showItems);
        }

        private void doLockItem(boolean lock) {
            Optional<String> path = detailPath();
            if (path.isEmpty()) return;
            worker.run(lock ? "Lock item" : "Unlock item", () -> {
                if (lock) client.lockItem(path.get());
                else client.unlockItem(path.get());
                Worker.checkCancelled();
                return client.listItems();
            }, this::showItems);
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
                    RENAME_TITLE, JOptionPane.QUESTION_MESSAGE, null, null, collectionName);
            if (answer == null) return;
            String label = answer.toString().trim();
            if (label.isEmpty()) {
                log("ERROR: A collection needs a label.");
                return;
            }
            worker.run("Rename collection", () -> client.renameCollection(label), renamed -> {
                if (renamed) {
                    collectionName = displayName(label, collectionId);
                    lblOpenCollection.setText("Open: " + collectionName + (defaultOpen ? " (default)" : ""));
                }
                doRefreshCollections();
            });
        }

        private void doListItems() {
            if (!requireCollection()) return;
            listing = client::listItems;
            worker.run("List items", listing, this::showItems);
        }

        /** Lists the items again, as the table lists them, after the provider signalled a change. */
        private void doRefreshItems() {
            if (!collectionOpen || listing == null) return;
            worker.run("Refresh items", listing, this::showItems);
        }

        /**
         * Shows the rows, and keeps the selected items selected where they are among them: the
         * detail, and a secret that it has read, stay.
         */
        private void showItems(List<KeyringClient.ItemRow> rows) {
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
            doShowItemDetail();
        }

        private void doSearch() {
            if (!requireCollection()) return;
            String query = tfSearch.getText().trim();
            String mode = (String) cmbSearchMode.getSelectedItem();
            if (BY_ATTRIBUTES.equals(mode)) {
                Optional<Map<String, String>> attributes = parseAttributes(query);
                if (attributes.isEmpty()) return;
                listing = () -> client.filter(attributes.get());
                worker.run("Filter", listing, this::showItems);
                return;
            }
            SearchMode searchMode = switch (mode) {
                case "By Attribute Key" -> SearchMode.BY_ATTRIBUTE_KEY;
                case "By Attribute Value" -> SearchMode.BY_ATTRIBUTE_VALUE;
                case "By Object ID" -> SearchMode.BY_OBJECT_ID;
                case "By Object Path" -> SearchMode.BY_OBJECT_PATH;
                default -> SearchMode.BY_NAME;
            };
            int maxDistance = (Integer) cmbMaxDistance.getSelectedItem();
            listing = () -> client.search(query, searchMode, maxDistance);
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

        private void doDeleteCollection() {
            if (!requireCollection()) return;
            String name = collectionName;
            int confirm = JOptionPane.showConfirmDialog(this,
                    "Delete the entire collection \"" + name + "\"?\n\n"
                            + "This cannot be undone!",
                    "Confirm Delete Collection \"" + name + "\"",
                    JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
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
                        KILL_TITLE, JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
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
                    START_TITLE, JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
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
            showRows(debugSystemModel, state.system());
            showRows(debugServiceModel, state.service());
            showRows(debugSessionModel, state.session());
            showRows(debugCollectionModel, state.collection());
        }

        private static void showRows(DefaultTableModel model, List<KeyringClient.Row> rows) {
            model.setRowCount(0);
            rows.forEach(row -> model.addRow(new Object[]{row.property(), row.value()}));
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

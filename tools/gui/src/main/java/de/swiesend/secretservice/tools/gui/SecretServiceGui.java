package de.swiesend.secretservice.tools.gui;

import de.swiesend.secretservice.functional.SearchMode;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.CharBuffer;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
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
 * <p>The GUI allows selecting between the <em>default</em> collection and a custom
 * <em>test</em> collection, and supports creating, reading, listing, and deleting
 * secrets against whichever provider currently serves {@code org.freedesktop.secrets}
 * (gnome-keyring, KeePassXC, KWallet).
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

        // Collection panel
        private final ButtonGroup collectionGroup = new ButtonGroup();
        private final JRadioButton rbDefault = new JRadioButton("Default collection");
        private final JRadioButton rbTest = new JRadioButton("Custom collection", true);
        /** Human-readable label used when creating a collection (gnome-keyring) or for display. */
        private final JTextField tfCollectionLabel = new JTextField(14);
        /** D-Bus collection id (last path segment, e.g. "test"). Used by collectionById(). */
        private final JTextField tfCollectionId = new JTextField("test", 14);
        private final JPasswordField pfCollectionPassword = new JPasswordField(14);

        // Create-item panel
        private final JTextField tfLabel = new JTextField(20);
        private final JTextField tfSecret = new JTextField(20);
        private final JTextField tfAttributeKey = new JTextField(10);
        private final JTextField tfAttributeValue = new JTextField(10);

        // Items list
        private final DefaultListModel<String> itemsModel = new DefaultListModel<>();
        private final JList<String> itemsList = new JList<>(itemsModel);

        // Search bar (items panel)
        private final JTextField tfSearch = new JTextField(14);
        private final JComboBox<String> cmbSearchMode = new JComboBox<>(new String[]{"By Name", "By Attribute Key", "By Attribute Value", "By Object ID", "By Object Path"});
        private final JComboBox<Integer> cmbMaxDistance = new JComboBox<>(new Integer[]{0, 1, 2, 3});
        private final JButton btnSearch = new JButton("Search");

        // Item detail panel (shown on selection)
        private final JLabel lblDetailPath = new JLabel(" ");
        private final JLabel lblDetailLabel = new JLabel(" ");
        private final JLabel lblDetailSecret = new JLabel("********");
        private final DefaultTableModel attributesTableModel = new DefaultTableModel(new String[]{"Key", "Value"}, 0) {
            @Override public boolean isCellEditable(int row, int col) { return false; }
        };
        private final JTable attributesTable = new JTable(attributesTableModel);

        // Log area
        private final JTextArea logArea = new JTextArea(12, 50);

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
        /** Whether a collection is open. */
        private boolean connected = false;
        /** The name of the open collection, for the confirmations. */
        private String collectionName = "";
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
            setMinimumSize(new Dimension(800, 700));
            pack();
            setLocationRelativeTo(null);
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
            rbDefault.setName("collection-default");
            rbTest.setName("collection-custom");
            tfCollectionLabel.setName("collection-label");
            tfCollectionId.setName("collection-id");
            pfCollectionPassword.setName("collection-password");
            tfLabel.setName("item-label");
            tfSecret.setName("item-secret");
            tfAttributeKey.setName("item-attribute-key");
            tfAttributeValue.setName("item-attribute-value");
            btnCreate.setName("create-item");
            btnClearCreate.setName("clear-item");
            itemsList.setName("items");
            tfSearch.setName("search");
            cmbSearchMode.setName("search-mode");
            cmbMaxDistance.setName("search-distance");
            btnSearch.setName("search-items");
            btnList.setName("list-items");
            lblDetailPath.setName("detail-path");
            lblDetailLabel.setName("detail-label");
            lblDetailSecret.setName("detail-secret");
            attributesTable.setName("detail-attributes");
            btnRead.setName("read-secret");
            btnDeleteItem.setName("delete-item");
            btnDeleteCollection.setName("delete-collection");
            btnKillKeyring.setName("kill-keyring");
            btnStartKeyring.setName("start-keyring");
            logArea.setName("log");
            btnClearLog.setName("clear-log");
            btnDebugRefresh.setName("refresh-state");
            cbAutoSync.setName("auto-sync");
        }

        // ── Layout ────────────────────────────────────────────────────

        private void buildUi() {
            JTabbedPane tabs = new JTabbedPane();

            // ── Main tab ──
            JPanel mainTab = new JPanel(new BorderLayout(8, 8));
            mainTab.setBorder(new EmptyBorder(10, 10, 10, 10));

            JPanel topPanel = new JPanel(new BorderLayout(0, 4));
            topPanel.add(buildSystemPanel(), BorderLayout.NORTH);
            topPanel.add(buildCollectionPanel(), BorderLayout.SOUTH);
            mainTab.add(topPanel, BorderLayout.NORTH);
            mainTab.add(buildCenterPanel(), BorderLayout.CENTER);
            mainTab.add(buildLogPanel(), BorderLayout.SOUTH);
            tabs.addTab("Main", mainTab);

            // ── Debug tab ──
            tabs.addTab("Debug", buildDebugTab());

            setContentPane(tabs);
        }

        private JPanel buildSystemPanel() {
            JPanel panel = new JPanel();
            panel.setBorder(new TitledBorder("System"));
            panel.setLayout(new GridBagLayout());
            GridBagConstraints gbc = gbc();

            // Row 0: connection icon + Connect / Disconnect
            gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 6; gbc.anchor = GridBagConstraints.CENTER;
            JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.CENTER, 8, 0));
            btnRow.add(lblConnectionStatus);
            btnRow.add(btnConnect);
            btnRow.add(btnDisconnect);
            btnRow.add(btnCancel);
            panel.add(btnRow, gbc);

            // Row 1: D-Bus status indicators
            gbc.gridwidth = 1;
            gbc.gridx = 0; gbc.gridy = 1; gbc.anchor = GridBagConstraints.EAST;
            panel.add(new JLabel("D-Bus:"), gbc);
            gbc.gridx = 1; gbc.anchor = GridBagConstraints.WEST;
            panel.add(lblDbusConnected, gbc);

            gbc.gridx = 2; gbc.anchor = GridBagConstraints.EAST;
            panel.add(new JLabel("Service:"), gbc);
            gbc.gridx = 3; gbc.anchor = GridBagConstraints.WEST;
            panel.add(lblDbusAvailable, gbc);

            gbc.gridx = 4; gbc.anchor = GridBagConstraints.EAST;
            panel.add(new JLabel("Provider:"), gbc);
            gbc.gridx = 5; gbc.anchor = GridBagConstraints.WEST;
            panel.add(lblProvider, gbc);

            // Row 2: what the worker does
            gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 6; gbc.anchor = GridBagConstraints.CENTER;
            panel.add(lblStatus, gbc);
            gbc.gridwidth = 1;

            updateConnectionIcon(false);
            return panel;
        }

        private JPanel buildCollectionPanel() {
            JPanel panel = new JPanel();
            panel.setBorder(new TitledBorder("Collection"));
            panel.setLayout(new GridBagLayout());
            GridBagConstraints gbc = gbc();

            collectionGroup.add(rbDefault);
            collectionGroup.add(rbTest);

            rbDefault.addActionListener(e -> {
                tfCollectionLabel.setEnabled(false);
                tfCollectionId.setEnabled(false);
                pfCollectionPassword.setEnabled(false);
            });
            rbTest.addActionListener(e -> {
                tfCollectionLabel.setEnabled(true);
                tfCollectionId.setEnabled(true);
                pfCollectionPassword.setEnabled(true);
            });

            gbc.gridx = 0; gbc.gridy = 0;
            panel.add(rbDefault, gbc);
            gbc.gridx = 1;
            panel.add(rbTest, gbc);

            gbc.gridx = 0; gbc.gridy = 1; gbc.anchor = GridBagConstraints.EAST;
            panel.add(new JLabel("Label:"), gbc);
            gbc.gridx = 1; gbc.anchor = GridBagConstraints.WEST;
            panel.add(tfCollectionLabel, gbc);
            gbc.gridx = 2; gbc.anchor = GridBagConstraints.EAST;
            panel.add(new JLabel("ID:"), gbc);
            gbc.gridx = 3; gbc.anchor = GridBagConstraints.WEST;
            panel.add(tfCollectionId, gbc);

            gbc.gridx = 0; gbc.gridy = 2; gbc.anchor = GridBagConstraints.EAST;
            panel.add(new JLabel("Password:"), gbc);
            gbc.gridx = 1; gbc.anchor = GridBagConstraints.WEST;
            panel.add(pfCollectionPassword, gbc);

            JLabel hintId = new JLabel("<html><small><i>ID = D-Bus path segment (e.g. \"test\"). Used when opening an existing collection by id."
                    + " In KeePassXC this is the name of the exposed group.</i></small></html>");
            JLabel hintLabel = new JLabel("<html><small><i>Label = human-readable name (e.g. \"Test\"). Used when creating a new collection."
                    + " In KeePassXC this is the database name.</i></small></html>");
            gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 4; gbc.anchor = GridBagConstraints.WEST;
            panel.add(hintLabel, gbc);
            gbc.gridy = 4;
            panel.add(hintId, gbc);
            gbc.gridwidth = 1;

            return panel;
        }

        private JPanel buildCenterPanel() {
            JPanel panel = new JPanel(new BorderLayout(8, 8));

            // ── Create-item fields ──────────────────────────────────
            JPanel createPanel = new JPanel();
            createPanel.setBorder(new TitledBorder("Create Item"));
            createPanel.setLayout(new GridBagLayout());
            GridBagConstraints gbc = gbc();

            gbc.gridx = 0; gbc.gridy = 0; gbc.anchor = GridBagConstraints.EAST;
            createPanel.add(new JLabel("Label:"), gbc);
            gbc.gridx = 1; gbc.anchor = GridBagConstraints.WEST; gbc.gridwidth = 3;
            createPanel.add(tfLabel, gbc);

            gbc.gridwidth = 1;
            gbc.gridx = 0; gbc.gridy = 1; gbc.anchor = GridBagConstraints.EAST;
            createPanel.add(new JLabel("Secret:"), gbc);
            gbc.gridx = 1; gbc.anchor = GridBagConstraints.WEST; gbc.gridwidth = 3;
            createPanel.add(tfSecret, gbc);

            gbc.gridwidth = 1;
            gbc.gridx = 0; gbc.gridy = 2; gbc.anchor = GridBagConstraints.EAST;
            createPanel.add(new JLabel("Attribute key:"), gbc);
            gbc.gridx = 1; gbc.anchor = GridBagConstraints.WEST;
            createPanel.add(tfAttributeKey, gbc);
            gbc.gridx = 2; gbc.anchor = GridBagConstraints.EAST;
            createPanel.add(new JLabel("value:"), gbc);
            gbc.gridx = 3; gbc.anchor = GridBagConstraints.WEST;
            createPanel.add(tfAttributeValue, gbc);

            gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 4; gbc.anchor = GridBagConstraints.CENTER;
            JPanel createRow = new JPanel(new FlowLayout(FlowLayout.CENTER, 6, 0));
            createRow.add(btnCreate);
            createRow.add(btnClearCreate);
            createPanel.add(createRow, gbc);

            panel.add(createPanel, BorderLayout.NORTH);

            // ── Center split: items list (left) + detail (right) ────
            JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
            splitPane.setResizeWeight(0.45);

            // Items list
            JPanel listPanel = new JPanel(new BorderLayout(4, 4));
            listPanel.setBorder(new TitledBorder("Items (select to inspect)"));
            itemsList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            JScrollPane listScroll = new JScrollPane(itemsList);
            listScroll.setPreferredSize(new Dimension(260, 160));

            // Search bar
            JPanel searchPanel = new JPanel(new BorderLayout(4, 2));
            JPanel searchFields = new JPanel(new BorderLayout(4, 0));
            cmbMaxDistance.setSelectedItem(1);
            cmbMaxDistance.setToolTipText("<html>Fuzzy search tolerance (Levenshtein distance):<br>"
                    + "<b>0</b> – substring match only (fastest, exact)<br>"
                    + "<b>1</b> – tolerates 1 typo / transposition<br>"
                    + "<b>2</b> – tolerates 2 edits<br>"
                    + "<b>3</b> – very loose matching</html>");
            JLabel lblDistance = new JLabel("~");
            lblDistance.setToolTipText("Fuzzy distance: 0 = exact substring, 1-3 = tolerate typos");
            JPanel modeAndDistance = new JPanel(new BorderLayout(2, 0));
            modeAndDistance.add(cmbSearchMode, BorderLayout.CENTER);
            JPanel distancePanel = new JPanel(new BorderLayout(2, 0));
            distancePanel.add(lblDistance, BorderLayout.WEST);
            distancePanel.add(cmbMaxDistance, BorderLayout.CENTER);
            modeAndDistance.add(distancePanel, BorderLayout.EAST);
            searchFields.add(tfSearch, BorderLayout.CENTER);
            searchFields.add(modeAndDistance, BorderLayout.EAST);
            searchPanel.add(searchFields, BorderLayout.CENTER);
            searchPanel.add(btnSearch, BorderLayout.EAST);

            listPanel.add(searchPanel, BorderLayout.NORTH);
            listPanel.add(listScroll, BorderLayout.CENTER);
            listPanel.add(btnList, BorderLayout.SOUTH);
            splitPane.setLeftComponent(listPanel);

            // Item detail
            JPanel detailPanel = new JPanel();
            detailPanel.setBorder(new TitledBorder("Selected Item"));
            detailPanel.setLayout(new GridBagLayout());
            GridBagConstraints dg = gbc();

            dg.gridx = 0; dg.gridy = 0; dg.anchor = GridBagConstraints.EAST;
            detailPanel.add(new JLabel("Path:"), dg);
            dg.gridx = 1; dg.anchor = GridBagConstraints.WEST; dg.weightx = 1.0;
            detailPanel.add(lblDetailPath, dg);

            dg.weightx = 0;
            dg.gridx = 0; dg.gridy = 1; dg.anchor = GridBagConstraints.EAST;
            detailPanel.add(new JLabel("Label:"), dg);
            dg.gridx = 1; dg.anchor = GridBagConstraints.WEST; dg.weightx = 1.0;
            detailPanel.add(lblDetailLabel, dg);

            dg.weightx = 0;
            dg.gridx = 0; dg.gridy = 2; dg.anchor = GridBagConstraints.EAST;
            detailPanel.add(new JLabel("Secret:"), dg);
            dg.gridx = 1; dg.anchor = GridBagConstraints.WEST; dg.weightx = 1.0;
            detailPanel.add(lblDetailSecret, dg);

            dg.weightx = 0;
            dg.gridx = 0; dg.gridy = 3; dg.gridwidth = 2; dg.anchor = GridBagConstraints.CENTER;
            JPanel detailBtnRow = new JPanel(new FlowLayout(FlowLayout.CENTER, 6, 0));
            detailBtnRow.add(btnRead);
            detailPanel.add(detailBtnRow, dg);

            dg.gridx = 0; dg.gridy = 4; dg.gridwidth = 2; dg.weighty = 1.0;
            dg.fill = GridBagConstraints.BOTH;
            JScrollPane attributesScroll = new JScrollPane(attributesTable);
            attributesScroll.setPreferredSize(new Dimension(0, 80));
            attributesTable.setFillsViewportHeight(true);
            detailPanel.add(attributesScroll, dg);

            splitPane.setRightComponent(detailPanel);
            panel.add(splitPane, BorderLayout.CENTER);

            // ── Danger Zone ─────────────────────────────────────────
            JPanel dangerPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 12, 4));
            dangerPanel.setBorder(BorderFactory.createTitledBorder(
                    BorderFactory.createLineBorder(Color.RED), "Danger Zone",
                    TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION,
                    dangerPanel.getFont(), Color.RED));
            btnDeleteItem.setForeground(Color.RED);
            btnDeleteCollection.setForeground(Color.RED);
            dangerPanel.add(btnDeleteItem);
            dangerPanel.add(btnDeleteCollection);
            dangerPanel.add(btnKillKeyring);
            dangerPanel.add(btnStartKeyring);
            panel.add(dangerPanel, BorderLayout.SOUTH);

            return panel;
        }

        // ── Debug tab ─────────────────────────────────────────────────

        private JPanel buildDebugTab() {
            JPanel panel = new JPanel(new BorderLayout(8, 8));
            panel.setBorder(new EmptyBorder(10, 10, 10, 10));

            // Four state sections stacked vertically
            JPanel grid = new JPanel(new GridLayout(4, 1, 8, 8));
            grid.add(buildDebugSection("System", debugSystemModel));
            grid.add(buildDebugSection("Service", debugServiceModel));
            grid.add(buildDebugSection("Session", debugSessionModel));
            grid.add(buildDebugSection("Collection", debugCollectionModel));
            panel.add(grid, BorderLayout.CENTER);

            JPanel bottom = new JPanel(new FlowLayout(FlowLayout.CENTER, 12, 4));
            bottom.add(cbAutoSync);
            bottom.add(btnDebugRefresh);
            panel.add(bottom, BorderLayout.SOUTH);

            return panel;
        }

        private static JPanel buildDebugSection(String title, DefaultTableModel model) {
            JPanel section = new JPanel(new BorderLayout());
            section.setBorder(new TitledBorder(title));
            JTable table = new JTable(model);
            table.setFillsViewportHeight(true);
            table.getColumnModel().getColumn(0).setPreferredWidth(180);
            table.getColumnModel().getColumn(1).setPreferredWidth(260);
            section.add(new JScrollPane(table), BorderLayout.CENTER);
            return section;
        }

        private JPanel buildLogPanel() {
            JPanel panel = new JPanel(new BorderLayout(4, 4));
            panel.setBorder(new TitledBorder("Log"));
            logArea.setEditable(false);
            logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            JScrollPane scroll = new JScrollPane(logArea);
            scroll.setPreferredSize(new Dimension(0, 180));
            panel.add(scroll, BorderLayout.CENTER);
            panel.add(btnClearLog, BorderLayout.SOUTH);
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
            btnCancel.addActionListener(e -> {
                log("Cancelling: %s", lblStatus.getText());
                worker.cancel();
            });
            btnCreate.addActionListener(e -> doCreate());
            btnClearCreate.addActionListener(e -> {
                tfLabel.setText("");
                tfSecret.setText("");
                tfAttributeKey.setText("");
                tfAttributeValue.setText("");
            });
            btnRead.addActionListener(e -> doRevealSecret());
            btnDeleteItem.addActionListener(e -> doDeleteItem());
            btnList.addActionListener(e -> doListItems());
            btnSearch.addActionListener(e -> doSearch());
            // Allow pressing Enter in the search field to trigger search
            tfSearch.addActionListener(e -> doSearch());
            btnDeleteCollection.addActionListener(e -> doDeleteCollection());
            btnKillKeyring.addActionListener(e -> killKeyring());
            btnStartKeyring.addActionListener(e -> startKeyring());
            btnClearLog.addActionListener(e -> logArea.setText(""));
            itemsList.addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting()) doShowItemDetail();
            });
            btnDebugRefresh.addActionListener(e -> refreshState());
        }

        /**
         * Enables what the window can do now: nothing that calls the keyring while the worker is
         * busy, and the item controls only while a collection is open.
         */
        private void updateControls() {
            boolean busy = worker.isBusy();
            boolean items = connected && !busy;
            tfLabel.setEnabled(items);
            tfSecret.setEnabled(items);
            tfAttributeKey.setEnabled(items);
            tfAttributeValue.setEnabled(items);
            btnCreate.setEnabled(items);
            btnClearCreate.setEnabled(items);
            btnRead.setEnabled(items);
            btnDeleteItem.setEnabled(items);
            btnList.setEnabled(items);
            btnSearch.setEnabled(items);
            tfSearch.setEnabled(items);
            cmbSearchMode.setEnabled(items);
            cmbMaxDistance.setEnabled(items);
            btnDeleteCollection.setEnabled(items);
            itemsList.setEnabled(items);
            btnDisconnect.setEnabled(connected && !busy);
            btnConnect.setEnabled(!connected && !busy);
            btnKillKeyring.setEnabled(!busy);
            btnStartKeyring.setEnabled(!busy);
            btnDebugRefresh.setEnabled(!busy);
            btnCancel.setEnabled(busy);
            rbDefault.setEnabled(!connected && !busy);
            rbTest.setEnabled(!connected && !busy);
            boolean customEditable = !connected && !busy && rbTest.isSelected();
            tfCollectionLabel.setEnabled(customEditable);
            tfCollectionId.setEnabled(customEditable);
            pfCollectionPassword.setEnabled(customEditable);
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
            Callable<Optional<KeyringClient.Opened>> connect;
            if (rbDefault.isSelected()) {
                connect = client::connectToDefault;
            } else {
                String id = tfCollectionId.getText().trim();
                String label = tfCollectionLabel.getText().trim();
                if (id.isEmpty() && label.isEmpty()) {
                    log("ERROR: Collection ID or Label must not be empty.");
                    return;
                }
                if (!id.isEmpty()) {
                    connect = () -> client.connectById(id);
                } else {
                    char[] password = pfCollectionPassword.getPassword();
                    connect = () -> {
                        try {
                            return client.connectByLabel(label, CharBuffer.wrap(password));
                        } finally {
                            Arrays.fill(password, '\0');
                        }
                    };
                }
            }
            worker.run("Connect", connect, opened -> {
                if (opened.isPresent()) {
                    connected = true;
                    String label = opened.get().label();
                    String id = opened.get().id();
                    collectionName = rbDefault.isSelected() ? "Default"
                            : label.equals(id) ? label : label + " [" + id + "]";
                    if (!label.equals("?")) tfCollectionLabel.setText(label);
                    if (!id.equals("?")) tfCollectionId.setText(id);
                    updateConnectionIcon(true);
                    updateControls();
                }
                refreshState();
            });
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
        private void disconnected() {
            connected = false;
            collectionName = "";
            itemsModel.clear();
            clearDetail();
            updateConnectionIcon(false);
            updateControls();
            refreshState();
        }

        /** Gives up a wait for the user, then disconnects on the worker and counts the latch down. */
        private void closed() {
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
            lblDetailPath.setText(" ");
            lblDetailLabel.setText(" ");
            lblDetailSecret.setText("********");
            attributesTableModel.setRowCount(0);
        }

        private void doShowItemDetail() {
            String selected = itemsList.getSelectedValue();
            if (selected == null || !connected) {
                clearDetail();
                return;
            }
            worker.run("Read item", () -> client.detail(selected), detail -> {
                lblDetailPath.setText(detail.path());
                lblDetailLabel.setText(detail.label());
                lblDetailSecret.setText("********");  // hidden until Read Secret
                attributesTableModel.setRowCount(0);
                detail.attributes().forEach((key, value) -> attributesTableModel.addRow(new Object[]{key, value}));
            });
        }

        /** The path of the item that the detail shows, if it shows one. */
        private Optional<String> detailPath() {
            String path = lblDetailPath.getText().trim();
            if (path.isEmpty()) {
                log("Select an item first.");
                return Optional.empty();
            }
            return Optional.of(path);
        }

        private void doRevealSecret() {
            if (!requireConnected()) return;
            Optional<String> path = detailPath();
            if (path.isEmpty()) return;
            worker.run("Read secret", () -> client.readSecret(path.get()), secret -> {
                if (secret.isPresent()) {
                    lblDetailSecret.setText(new String(secret.get()));
                    Arrays.fill(secret.get(), '\0');
                } else {
                    lblDetailSecret.setText("<empty>");
                }
            });
        }

        // ── CRUD ──────────────────────────────────────────────────

        private void doCreate() {
            if (!requireConnected()) return;
            String label = tfLabel.getText().trim();
            String secret = tfSecret.getText();
            if (label.isEmpty() || secret.isEmpty()) {
                log("ERROR: Label and secret are required to create an item.");
                return;
            }
            Map<String, String> attributes = buildAttributes();
            worker.run("Create item", () -> {
                client.createItem(label, secret, attributes);
                Worker.checkCancelled();
                return client.listItems();
            }, items -> {
                showItems(items);
                autoSync();
            });
        }

        private void doDeleteItem() {
            if (!requireConnected()) return;
            Optional<String> path = detailPath();
            if (path.isEmpty()) return;
            int confirm = JOptionPane.showConfirmDialog(this,
                    "Delete item from collection \"" + collectionName + "\"?\n\n"
                            + "Label: " + lblDetailLabel.getText() + "\n"
                            + "Path:  " + path.get(),
                    "Confirm Delete Item", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (confirm != JOptionPane.YES_OPTION) return;
            worker.run("Delete item", () -> {
                client.deleteItem(path.get());
                Worker.checkCancelled();
                return client.listItems();
            }, items -> {
                clearDetail();
                showItems(items);
                autoSync();
            });
        }

        private void doListItems() {
            if (!requireConnected()) return;
            worker.run("List items", client::listItems, this::showItems);
        }

        private void showItems(List<String> items) {
            itemsModel.clear();
            items.forEach(itemsModel::addElement);
        }

        private void doSearch() {
            if (!requireConnected()) return;
            String query = tfSearch.getText().trim();
            String mode = (String) cmbSearchMode.getSelectedItem();
            SearchMode searchMode = switch (mode) {
                case "By Attribute Key" -> SearchMode.BY_ATTRIBUTE_KEY;
                case "By Attribute Value" -> SearchMode.BY_ATTRIBUTE_VALUE;
                case "By Object ID" -> SearchMode.BY_OBJECT_ID;
                case "By Object Path" -> SearchMode.BY_OBJECT_PATH;
                default -> SearchMode.BY_NAME;
            };
            int maxDistance = (Integer) cmbMaxDistance.getSelectedItem();
            worker.run("Search", () -> client.search(query, searchMode, maxDistance), this::showItems);
        }

        private void doDeleteCollection() {
            if (!requireConnected()) return;
            String name = collectionName;
            int confirm = JOptionPane.showConfirmDialog(this,
                    "Delete the entire collection \"" + name + "\"?\n\n"
                            + "This cannot be undone!",
                    "Confirm Delete Collection \"" + name + "\"",
                    JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (confirm != JOptionPane.YES_OPTION) return;
            worker.run("Delete collection", client::deleteCollection, deleted -> {
                if (deleted) disconnected();
            });
        }

        private void killKeyring() {
            int confirm = JOptionPane.showConfirmDialog(this,
                    "Kill the gnome-keyring process? This may affect the desktop session.\n\nProceed?",
                    "Kill Keyring", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (confirm != JOptionPane.YES_OPTION) return;
            worker.run("Kill keyring", () -> {
                Process p = new ProcessBuilder("pkill", "-f", "gnome-keyring-daemon").start();
                int rc = p.waitFor();
                log("killKeyring(): pkill returned %d", rc);
                return null;
            }, ignored -> { });
        }

        private void startKeyring() {
            int confirm = JOptionPane.showConfirmDialog(this,
                    "Start the gnome-keyring-daemon for the current user?\n\nProceed?",
                    "Start Keyring", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
            if (confirm != JOptionPane.YES_OPTION) return;
            worker.run("Start keyring", () -> {
                ProcessBuilder pb = new ProcessBuilder("gnome-keyring-daemon", "--start", "--components=secrets,pkcs11,ssh");
                pb.redirectErrorStream(true);
                Process p = pb.start();
                String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                int rc = p.waitFor();
                log("startKeyring(): exit=%d output=%s", rc, out.trim());
                return null;
            }, ignored -> { });
        }

        // ── Helpers ───────────────────────────────────────────────

        private Map<String, String> buildAttributes() {
            String key = tfAttributeKey.getText().trim();
            String value = tfAttributeValue.getText().trim();
            if (!key.isEmpty() && !value.isEmpty()) {
                return Map.of(key, value);
            }
            return Map.of();
        }

        private boolean requireConnected() {
            if (!connected) {
                log("Not connected. Click Connect first.");
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

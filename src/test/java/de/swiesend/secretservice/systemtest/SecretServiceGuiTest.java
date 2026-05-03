package de.swiesend.secretservice.systemtest;

import de.swiesend.secretservice.ProviderDetector;
import de.swiesend.secretservice.functional.SecretService;
import de.swiesend.secretservice.functional.SearchMode;
import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import de.swiesend.secretservice.functional.interfaces.SystemInterface;
import de.swiesend.secretservice.interfaces.Collection.ItemChanged;
import de.swiesend.secretservice.interfaces.Collection.ItemCreated;
import de.swiesend.secretservice.interfaces.Collection.ItemDeleted;
import de.swiesend.secretservice.interfaces.Prompt.Completed;
import de.swiesend.secretservice.interfaces.Service.CollectionChanged;
import de.swiesend.secretservice.interfaces.Service.CollectionCreated;
import de.swiesend.secretservice.interfaces.Service.CollectionDeleted;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.MatteBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Duration;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.*;
import java.util.concurrent.CountDownLatch;

/**
 * Interactive Swing GUI for manual system-level testing of the secret-service library.
 *
 * <p>This test is excluded from the default Maven build. Run it explicitly with:
 * <pre>{@code
 *   mvn test -Psystem-test
 * }</pre>
 *
 * <p>The GUI allows selecting between the <em>default</em> collection and a custom
 * <em>test</em> collection, and supports creating, reading, listing, and deleting secrets.
 */
@Tag("system-test")
public class SecretServiceGuiTest {

    @Test
    @DisplayName("Interactive Secret Service GUI")
    void launchGui() throws InterruptedException {
        // Gate: only launch when a display is available
        if (GraphicsEnvironment.isHeadless()) {
            System.out.println("Headless environment detected — skipping GUI system test.");
            return;
        }

        CountDownLatch latch = new CountDownLatch(1);
        SwingUtilities.invokeLater(() -> {
            applyGnomeTheme();
            SecretServiceFrame frame = new SecretServiceFrame(latch);
            frame.setVisible(true);
        });
        latch.await(); // block until the user closes the window
    }

    /** Apply an Adwaita-inspired flat theme to the Swing UIManager. */
    private static void applyGnomeTheme() {
        // Prefer GTK look-and-feel when running on Linux; fall back gracefully
        try {
            for (UIManager.LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
                if (info.getName().contains("GTK")) {
                    UIManager.setLookAndFeel(info.getClassName());
                    return;
                }
            }
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {}

        // Adwaita palette overrides (applied on top of whatever L&F loaded)
        Color bg     = new Color(0xF6F5F4);
        Color card   = Color.WHITE;
        Color text   = new Color(0x2E3436);
        Color accent = new Color(0x3584E4);

        UIManager.put("Panel.background",          bg);
        UIManager.put("ScrollPane.background",     bg);
        UIManager.put("Viewport.background",       card);
        UIManager.put("Table.background",          card);
        UIManager.put("List.background",           card);
        UIManager.put("TextArea.background",       card);
        UIManager.put("TextField.background",      card);
        UIManager.put("PasswordField.background",  card);
        UIManager.put("ComboBox.background",       card);
        UIManager.put("Label.foreground",          text);
        UIManager.put("Button.focus",              new Color(accent.getRed(), accent.getGreen(), accent.getBlue(), 80));
        UIManager.put("TabbedPane.background",     bg);
        UIManager.put("TabbedPane.selected",       card);
        UIManager.put("SplitPane.background",      bg);
        UIManager.put("TitledBorder.titleColor",   new Color(0x77767B));
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

        // GUI-tracked state
        private boolean wasUnlockedOnce = false;
        private final List<AutoCloseable> signalRegistrations = new ArrayList<>();

        // Functional API references
        private SystemInterface system;
        private ServiceInterface service;
        private SessionInterface session;
        private CollectionInterface collection;
        private final CountDownLatch closeLatch;

        SecretServiceFrame(CountDownLatch closeLatch) {
            super("Secret Service — System Test");
            this.closeLatch = closeLatch;
            setDefaultCloseOperation(DISPOSE_ON_CLOSE);
            addWindowListener(new WindowAdapter() {
                @Override
                public void windowClosed(WindowEvent e) {
                    disconnectQuietly();
                    closeLatch.countDown();
                }
            });
            buildUi();
            wireActions();
            setMinimumSize(new Dimension(800, 700));
            pack();
            setLocationRelativeTo(null);
            setItemControlsEnabled(false);
        }

        private static DefaultTableModel readOnlyTableModel(String... columns) {
            return new DefaultTableModel(columns, 0) {
                @Override public boolean isCellEditable(int row, int col) { return false; }
            };
        }

        // ── Layout ────────────────────────────────────────────────────

        private void buildUi() {
            JTabbedPane tabs = new JTabbedPane();
            tabs.setBorder(new EmptyBorder(0, 0, 0, 0));

            // ── Main tab ──
            JPanel mainTab = new JPanel(new BorderLayout(0, 0));
            mainTab.setBackground(new Color(0xF6F5F4));

            JPanel topPanel = new JPanel(new BorderLayout(0, 0));
            topPanel.setBackground(new Color(0xF6F5F4));
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
            JPanel inner = new JPanel(new GridBagLayout());
            inner.setOpaque(false);
            GridBagConstraints gbc = gbc();

            // Row 0: connection icon + Connect / Disconnect
            gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 6; gbc.anchor = GridBagConstraints.CENTER;
            JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.CENTER, 8, 0));
            btnRow.setOpaque(false);
            styleButton(btnConnect,    new Color(0x3584E4), Color.WHITE);
            styleButton(btnDisconnect, new Color(0xDEDDDA), new Color(0x2E3436));
            btnRow.add(lblConnectionStatus);
            btnRow.add(btnConnect);
            btnRow.add(btnDisconnect);
            inner.add(btnRow, gbc);

            // Row 1: D-Bus status indicators
            gbc.gridwidth = 1;
            gbc.gridx = 0; gbc.gridy = 1; gbc.anchor = GridBagConstraints.EAST;
            inner.add(dimLabel("D-Bus:"), gbc);
            gbc.gridx = 1; gbc.anchor = GridBagConstraints.WEST;
            inner.add(lblDbusConnected, gbc);

            gbc.gridx = 2; gbc.anchor = GridBagConstraints.EAST;
            inner.add(dimLabel("Service:"), gbc);
            gbc.gridx = 3; gbc.anchor = GridBagConstraints.WEST;
            inner.add(lblDbusAvailable, gbc);

            gbc.gridx = 4; gbc.anchor = GridBagConstraints.EAST;
            inner.add(dimLabel("Provider:"), gbc);
            gbc.gridx = 5; gbc.anchor = GridBagConstraints.WEST;
            inner.add(lblProvider, gbc);

            updateConnectionIcon(false);
            return card("System", inner);
        }

        private JPanel buildCollectionPanel() {
            JPanel inner = new JPanel(new GridBagLayout());
            inner.setOpaque(false);
            GridBagConstraints gbc = gbc();

            collectionGroup.add(rbDefault);
            collectionGroup.add(rbTest);
            rbDefault.setOpaque(false);
            rbTest.setOpaque(false);

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
            inner.add(rbDefault, gbc);
            gbc.gridx = 1;
            inner.add(rbTest, gbc);

            gbc.gridx = 0; gbc.gridy = 1; gbc.anchor = GridBagConstraints.EAST;
            inner.add(dimLabel("Label:"), gbc);
            gbc.gridx = 1; gbc.anchor = GridBagConstraints.WEST;
            inner.add(tfCollectionLabel, gbc);
            gbc.gridx = 2; gbc.anchor = GridBagConstraints.EAST;
            inner.add(dimLabel("ID:"), gbc);
            gbc.gridx = 3; gbc.anchor = GridBagConstraints.WEST;
            inner.add(tfCollectionId, gbc);

            gbc.gridx = 0; gbc.gridy = 2; gbc.anchor = GridBagConstraints.EAST;
            inner.add(dimLabel("Password:"), gbc);
            gbc.gridx = 1; gbc.anchor = GridBagConstraints.WEST;
            inner.add(pfCollectionPassword, gbc);

            JLabel hintId  = hintLabel("ID = D-Bus path segment (e.g. \"test\"). Used when opening an existing collection by id."
                    + " In KeePassXC this is the name of the exposed group.");
            JLabel hintLbl = hintLabel("Label = human-readable name (e.g. \"Test\"). Used when creating a new collection."
                    + " In KeePassXC this is the database name.");
            gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 4; gbc.anchor = GridBagConstraints.WEST;
            inner.add(hintLbl, gbc);
            gbc.gridy = 4;
            inner.add(hintId, gbc);
            gbc.gridwidth = 1;

            return card("Collection", inner);
        }

        private JPanel buildCenterPanel() {
            JPanel panel = new JPanel(new BorderLayout(0, 0));
            panel.setBackground(new Color(0xF6F5F4));

            // ── Create-item fields ──────────────────────────────────
            JPanel createInner = new JPanel(new GridBagLayout());
            createInner.setOpaque(false);
            GridBagConstraints gbc = gbc();

            gbc.gridx = 0; gbc.gridy = 0; gbc.anchor = GridBagConstraints.EAST;
            createInner.add(dimLabel("Label:"), gbc);
            gbc.gridx = 1; gbc.anchor = GridBagConstraints.WEST; gbc.gridwidth = 3;
            createInner.add(tfLabel, gbc);

            gbc.gridwidth = 1;
            gbc.gridx = 0; gbc.gridy = 1; gbc.anchor = GridBagConstraints.EAST;
            createInner.add(dimLabel("Secret:"), gbc);
            gbc.gridx = 1; gbc.anchor = GridBagConstraints.WEST; gbc.gridwidth = 3;
            createInner.add(tfSecret, gbc);

            gbc.gridwidth = 1;
            gbc.gridx = 0; gbc.gridy = 2; gbc.anchor = GridBagConstraints.EAST;
            createInner.add(dimLabel("Attribute key:"), gbc);
            gbc.gridx = 1; gbc.anchor = GridBagConstraints.WEST;
            createInner.add(tfAttributeKey, gbc);
            gbc.gridx = 2; gbc.anchor = GridBagConstraints.EAST;
            createInner.add(dimLabel("value:"), gbc);
            gbc.gridx = 3; gbc.anchor = GridBagConstraints.WEST;
            createInner.add(tfAttributeValue, gbc);

            gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 4; gbc.anchor = GridBagConstraints.CENTER;
            JPanel createRow = new JPanel(new FlowLayout(FlowLayout.CENTER, 6, 0));
            createRow.setOpaque(false);
            styleButton(btnCreate,      new Color(0x3584E4), Color.WHITE);
            styleButton(btnClearCreate, new Color(0xDEDDDA), new Color(0x2E3436));
            createRow.add(btnCreate);
            createRow.add(btnClearCreate);
            createInner.add(createRow, gbc);

            panel.add(card("Create Item", createInner), BorderLayout.NORTH);

            // ── Center split: items list (left) + detail (right) ────
            JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
            splitPane.setResizeWeight(0.45);
            splitPane.setBorder(new EmptyBorder(0, 0, 0, 0));

            // Items list
            JPanel listInner = new JPanel(new BorderLayout(4, 4));
            listInner.setOpaque(false);
            itemsList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            JScrollPane listScroll = new JScrollPane(itemsList);
            listScroll.setPreferredSize(new Dimension(260, 160));

            // Search bar
            JPanel searchPanel = new JPanel(new BorderLayout(4, 2));
            searchPanel.setOpaque(false);
            JPanel searchFields = new JPanel(new BorderLayout(4, 0));
            searchFields.setOpaque(false);
            cmbMaxDistance.setSelectedItem(1);
            cmbMaxDistance.setToolTipText("<html>Fuzzy search tolerance (Levenshtein distance):<br>"
                    + "<b>0</b> – substring match only (fastest, exact)<br>"
                    + "<b>1</b> – tolerates 1 typo / transposition<br>"
                    + "<b>2</b> – tolerates 2 edits<br>"
                    + "<b>3</b> – very loose matching</html>");
            JLabel lblDistance = new JLabel("~");
            lblDistance.setToolTipText("Fuzzy distance: 0 = exact substring, 1-3 = tolerate typos");
            JPanel modeAndDistance = new JPanel(new BorderLayout(2, 0));
            modeAndDistance.setOpaque(false);
            modeAndDistance.add(cmbSearchMode, BorderLayout.CENTER);
            JPanel distancePanel = new JPanel(new BorderLayout(2, 0));
            distancePanel.setOpaque(false);
            distancePanel.add(lblDistance, BorderLayout.WEST);
            distancePanel.add(cmbMaxDistance, BorderLayout.CENTER);
            modeAndDistance.add(distancePanel, BorderLayout.EAST);
            searchFields.add(tfSearch, BorderLayout.CENTER);
            searchFields.add(modeAndDistance, BorderLayout.EAST);
            styleButton(btnSearch, new Color(0x3584E4), Color.WHITE);
            searchPanel.add(searchFields, BorderLayout.CENTER);
            searchPanel.add(btnSearch, BorderLayout.EAST);

            listInner.add(searchPanel, BorderLayout.NORTH);
            listInner.add(listScroll, BorderLayout.CENTER);
            styleButton(btnList, new Color(0xDEDDDA), new Color(0x2E3436));
            listInner.add(btnList, BorderLayout.SOUTH);
            splitPane.setLeftComponent(card("Items (select to inspect)", listInner));

            // Item detail
            JPanel detailInner = new JPanel(new GridBagLayout());
            detailInner.setOpaque(false);
            GridBagConstraints dg = gbc();

            dg.gridx = 0; dg.gridy = 0; dg.anchor = GridBagConstraints.EAST;
            detailInner.add(dimLabel("Path:"), dg);
            dg.gridx = 1; dg.anchor = GridBagConstraints.WEST; dg.weightx = 1.0;
            detailInner.add(lblDetailPath, dg);

            dg.weightx = 0;
            dg.gridx = 0; dg.gridy = 1; dg.anchor = GridBagConstraints.EAST;
            detailInner.add(dimLabel("Label:"), dg);
            dg.gridx = 1; dg.anchor = GridBagConstraints.WEST; dg.weightx = 1.0;
            detailInner.add(lblDetailLabel, dg);

            dg.weightx = 0;
            dg.gridx = 0; dg.gridy = 2; dg.anchor = GridBagConstraints.EAST;
            detailInner.add(dimLabel("Secret:"), dg);
            dg.gridx = 1; dg.anchor = GridBagConstraints.WEST; dg.weightx = 1.0;
            detailInner.add(lblDetailSecret, dg);

            dg.weightx = 0;
            dg.gridx = 0; dg.gridy = 3; dg.gridwidth = 2; dg.anchor = GridBagConstraints.CENTER;
            JPanel detailBtnRow = new JPanel(new FlowLayout(FlowLayout.CENTER, 6, 0));
            detailBtnRow.setOpaque(false);
            styleButton(btnRead, new Color(0x3584E4), Color.WHITE);
            detailBtnRow.add(btnRead);
            detailInner.add(detailBtnRow, dg);

            dg.gridx = 0; dg.gridy = 4; dg.gridwidth = 2; dg.weighty = 1.0;
            dg.fill = GridBagConstraints.BOTH;
            JScrollPane attributesScroll = new JScrollPane(attributesTable);
            attributesScroll.setPreferredSize(new Dimension(0, 80));
            attributesTable.setFillsViewportHeight(true);
            detailInner.add(attributesScroll, dg);

            splitPane.setRightComponent(card("Selected Item", detailInner));
            panel.add(splitPane, BorderLayout.CENTER);

            // ── Danger Zone ─────────────────────────────────────────
            JPanel dangerPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 12, 6));
            dangerPanel.setBackground(new Color(0xFFF0EE));
            dangerPanel.setBorder(BorderFactory.createCompoundBorder(
                    new MatteBorder(1, 0, 0, 0, new Color(0xF5C2C7)),
                    new EmptyBorder(2, 8, 2, 8)));
            styleButton(btnDeleteItem,       new Color(0xE01B24), Color.WHITE);
            styleButton(btnDeleteCollection, new Color(0xE01B24), Color.WHITE);
            styleButton(btnKillKeyring,      new Color(0xDEDDDA), new Color(0x2E3436));
            styleButton(btnStartKeyring,     new Color(0xDEDDDA), new Color(0x2E3436));
            dangerPanel.add(btnDeleteItem);
            dangerPanel.add(btnDeleteCollection);
            dangerPanel.add(btnKillKeyring);
            dangerPanel.add(btnStartKeyring);
            panel.add(dangerPanel, BorderLayout.SOUTH);

            return panel;
        }

        // ── Debug tab ─────────────────────────────────────────────────

        private JPanel buildDebugTab() {
            JPanel panel = new JPanel(new BorderLayout(0, 0));
            panel.setBackground(new Color(0xF6F5F4));
            panel.setBorder(new EmptyBorder(4, 4, 4, 4));

            // Four sections stacked vertically: System → Service → Session → Collection
            JPanel stack = new JPanel();
            stack.setOpaque(false);
            stack.setLayout(new BoxLayout(stack, BoxLayout.Y_AXIS));
            stack.add(buildDebugSection("System",     debugSystemModel));
            stack.add(Box.createVerticalStrut(4));
            stack.add(buildDebugSection("Service",    debugServiceModel));
            stack.add(Box.createVerticalStrut(4));
            stack.add(buildDebugSection("Session",    debugSessionModel));
            stack.add(Box.createVerticalStrut(4));
            stack.add(buildDebugSection("Collection", debugCollectionModel));

            JScrollPane scrollPane = new JScrollPane(stack);
            scrollPane.setBorder(new EmptyBorder(0, 0, 0, 0));
            panel.add(scrollPane, BorderLayout.CENTER);

            JPanel bottom = new JPanel(new FlowLayout(FlowLayout.CENTER, 12, 4));
            bottom.setOpaque(false);
            cbAutoSync.setOpaque(false);
            styleButton(btnDebugRefresh, new Color(0x3584E4), Color.WHITE);
            bottom.add(cbAutoSync);
            bottom.add(btnDebugRefresh);
            panel.add(bottom, BorderLayout.SOUTH);

            return panel;
        }

        private static JPanel buildDebugSection(String title, DefaultTableModel model) {
            JTable table = new JTable(model);
            table.setFillsViewportHeight(true);
            table.setRowHeight(22);
            table.getColumnModel().getColumn(0).setPreferredWidth(200);
            table.getColumnModel().getColumn(1).setPreferredWidth(300);
            JScrollPane scroll = new JScrollPane(table);
            scroll.setPreferredSize(new Dimension(0, 110));
            JPanel inner = new JPanel(new BorderLayout());
            inner.setOpaque(false);
            inner.add(scroll, BorderLayout.CENTER);
            JPanel c = card(title, inner);
            c.setMaximumSize(new Dimension(Integer.MAX_VALUE, 150));
            return c;
        }

        private JPanel buildLogPanel() {
            JPanel inner = new JPanel(new BorderLayout(4, 4));
            inner.setOpaque(false);
            logArea.setEditable(false);
            logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            logArea.setBackground(new Color(0x1E1E2E));
            logArea.setForeground(new Color(0xCDD6F4));
            logArea.setCaretColor(new Color(0xCDD6F4));
            JScrollPane scroll = new JScrollPane(logArea);
            scroll.setPreferredSize(new Dimension(0, 160));
            inner.add(scroll, BorderLayout.CENTER);
            styleButton(btnClearLog, new Color(0xDEDDDA), new Color(0x2E3436));
            inner.add(btnClearLog, BorderLayout.SOUTH);
            return card("Log", inner);
        }

        private static GridBagConstraints gbc() {
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.insets = new Insets(4, 8, 4, 8);
            gbc.fill = GridBagConstraints.HORIZONTAL;
            return gbc;
        }

        /** Flat card panel with a bold section title and a subtle border. */
        private static JPanel card(String title, JPanel content) {
            JPanel card = new JPanel(new BorderLayout(0, 4));
            card.setBackground(Color.WHITE);
            card.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(new Color(0xDEDDDA), 1, true),
                    new EmptyBorder(8, 10, 10, 10)));
            JLabel header = new JLabel(title);
            header.setFont(header.getFont().deriveFont(Font.BOLD, 12f));
            header.setForeground(new Color(0x77767B));
            header.setBorder(new EmptyBorder(0, 0, 4, 0));
            card.add(header, BorderLayout.NORTH);
            card.add(content, BorderLayout.CENTER);
            JPanel wrapper = new JPanel(new BorderLayout());
            wrapper.setOpaque(false);
            wrapper.setBorder(new EmptyBorder(4, 8, 4, 8));
            wrapper.add(card);
            return wrapper;
        }

        /** Small muted label for field captions. */
        private static JLabel dimLabel(String text) {
            JLabel l = new JLabel(text);
            l.setForeground(new Color(0x77767B));
            return l;
        }

        /** Small italic hint label. */
        private static JLabel hintLabel(String text) {
            JLabel l = new JLabel("<html><small><i>" + text + "</i></small></html>");
            l.setForeground(new Color(0x9A9996));
            return l;
        }

        /** Flat Adwaita-inspired button styling. */
        private static void styleButton(JButton btn, Color bg, Color fg) {
            btn.setBackground(bg);
            btn.setForeground(fg);
            btn.setOpaque(true);
            btn.setBorderPainted(false);
            btn.setFocusPainted(false);
            btn.setBorder(new EmptyBorder(6, 14, 6, 14));
        }

        // ── Actions ───────────────────────────────────────────────────

        private void wireActions() {
            btnConnect.addActionListener(e -> doConnect());
            btnDisconnect.addActionListener(e -> doDisconnect());
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
            btnDebugRefresh.addActionListener(e -> refreshDebugState());
        }

        private void setItemControlsEnabled(boolean enabled) {
            tfLabel.setEnabled(enabled);
            tfSecret.setEnabled(enabled);
            tfAttributeKey.setEnabled(enabled);
            tfAttributeValue.setEnabled(enabled);
            btnCreate.setEnabled(enabled);
            btnClearCreate.setEnabled(enabled);
            btnRead.setEnabled(enabled);
            btnDeleteItem.setEnabled(enabled);
            btnList.setEnabled(enabled);
            btnSearch.setEnabled(enabled);
            tfSearch.setEnabled(enabled);
            cmbSearchMode.setEnabled(enabled);
            cmbMaxDistance.setEnabled(enabled);
            btnDeleteCollection.setEnabled(enabled);
            itemsList.setEnabled(enabled);
            btnDisconnect.setEnabled(enabled);
            btnConnect.setEnabled(!enabled);
            rbDefault.setEnabled(!enabled);
            rbTest.setEnabled(!enabled);
            boolean customEditable = !enabled && rbTest.isSelected();
            tfCollectionLabel.setEnabled(customEditable);
            tfCollectionId.setEnabled(customEditable);
            pfCollectionPassword.setEnabled(customEditable);
        }

        // ── Connect / Disconnect ──────────────────────────────────────

        private void doConnect() {
            try {
                // 1. Connect to D-Bus
                Optional<SystemInterface> maybeSystem = de.swiesend.secretservice.functional.System.connect();
                if (maybeSystem.isEmpty()) {
                    log("ERROR: Could not connect to D-Bus.");
                    return;
                }
                system = maybeSystem.get();
                log("D-Bus connection established.");
                registerSignalLoggers();

                // 2. Create service (checks availability)
                Optional<ServiceInterface> maybeService = SecretService.create(Optional.of(system));
                if (maybeService.isEmpty()) {
                    log("ERROR: Secret service not available.");
                    system.disconnect();
                    system = null;
                    return;
                }
                service = maybeService.get();
                log("Secret service created. Gnome Keyring: %s", service.isGnomeKeyringAvailable());

                // 3. Open encrypted session
                Optional<SessionInterface> maybeSession = service.openSession();
                if (maybeSession.isEmpty()) {
                    log("ERROR: Could not open session.");
                    closeServiceQuietly();
                    return;
                }
                session = maybeSession.get();
                log("Session opened: %s", session.getId());

                // 4. Open collection
                Optional<CollectionInterface> maybeColl;
                if (rbDefault.isSelected()) {
                    maybeColl = session.defaultCollection();
                } else {
                    String id    = tfCollectionId.getText().trim();
                    String label = tfCollectionLabel.getText().trim();
                    if (id.isEmpty() && label.isEmpty()) {
                        log("ERROR: Collection ID or Label must not be empty.");
                        closeServiceQuietly();
                        return;
                    }
                    if (!id.isEmpty()) {
                        // Open existing collection by D-Bus id (e.g. KeePassXC or gnome-keyring)
                        log("Opening collection by id: %s", id);
                        maybeColl = session.collectionById(id);
                    } else {
                        // Create / open by label + password (gnome-keyring)
                        log("Opening collection by label: %s", label);
                        char[] pw = pfCollectionPassword.getPassword();
                        maybeColl = session.collection(label, Optional.of(new String(pw)));
                        Arrays.fill(pw, '\0');
                    }
                }
                if (maybeColl.isEmpty()) {
                    log("ERROR: Could not open collection.");
                    closeServiceQuietly();
                    return;
                }
                collection = maybeColl.get();
                String collName = collection.getLabel().orElse("?");
                String collId   = collection.getId().orElse("?");
                log("Connected to collection label=\"%s\" id=\"%s\".", collName, collId);
                // Reflect resolved label and id back into the fields
                SwingUtilities.invokeLater(() -> {
                    if (!collName.equals("?")) tfCollectionLabel.setText(collName);
                    if (!collId.equals("?"))   tfCollectionId.setText(collId);
                });

                boolean locked = collection.isLocked();
                if (!locked) wasUnlockedOnce = true;
                log("Locked: %s", locked);
                setItemControlsEnabled(true);
                updateConnectionIcon(true);
                updateDbusStatus();
                autoSync();
            } catch (Exception ex) {
                log("CONNECT FAILED: %s", exceptionDetail(ex));
                closeServiceQuietly();
            }
        }

        private void doDisconnect() {
            disconnectQuietly();
            itemsModel.clear();
            clearDetail();
            setItemControlsEnabled(false);
            updateConnectionIcon(false);
            updateDbusStatus();
            autoSync();
            log("Disconnected.");
        }

        private void disconnectQuietly() {
            unregisterSignalLoggers();
            closeServiceQuietly();
        }

        private void closeServiceQuietly() {
            // Closing the service cascades: sessions → collections → system
            if (service != null) {
                try {
                    service.close();
                } catch (Exception ignored) {
                }
            }
            service = null;
            session = null;
            collection = null;
            system = null;
        }

        // ── Signal logging ──────────────────────────────────────────

        private void registerSignalLoggers() {
            if (system == null || !system.isConnected()) return;
            DBusConnection conn = system.getConnection();
            try {
                signalRegistrations.add(conn.addSigHandler(CollectionCreated.class,
                        s -> log("> CollectionCreated(%s)", s.collection)));
                signalRegistrations.add(conn.addSigHandler(CollectionChanged.class,
                        s -> log("> CollectionChanged(%s)", s.collection)));
                signalRegistrations.add(conn.addSigHandler(CollectionDeleted.class,
                        s -> log("> CollectionDeleted(%s)", s.collection)));
                signalRegistrations.add(conn.addSigHandler(ItemCreated.class,
                        s -> log("> ItemCreated(%s) on %s", s.item, s.getPath())));
                signalRegistrations.add(conn.addSigHandler(ItemChanged.class,
                        s -> log("> ItemChanged(%s) on %s", s.item, s.getPath())));
                signalRegistrations.add(conn.addSigHandler(ItemDeleted.class,
                        s -> log("> ItemDeleted(%s) on %s", s.item, s.getPath())));
                signalRegistrations.add(conn.addSigHandler(Completed.class,
                        s -> log("> Prompt.Completed(%s) dismissed=%s", s.getPath(), s.dismissed)));
                log("Signal loggers registered (7 D-Bus signals).");
            } catch (Exception e) {
                log("WARNING: Could not register signal loggers: %s", e.getMessage());
            }
        }

        private void unregisterSignalLoggers() {
            for (AutoCloseable reg : signalRegistrations) {
                try { reg.close(); } catch (Exception ignored) {}
            }
            signalRegistrations.clear();
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
            if (selected == null || collection == null) {
                clearDetail();
                return;
            }
            doShowItemDetailForPath(selected);
        }

        private void doShowItemDetailForPath(String path) {
            if (path == null || path.isBlank() || collection == null) {
                clearDetail();
                return;
            }
            try {
                String itemLabel = collection.getItemLabel(path).orElse("<unknown>");
                Optional<Map<String, String>> maybeAttrs = collection.getAttributes(path);

                lblDetailPath.setText(path);
                lblDetailLabel.setText(itemLabel);
                lblDetailSecret.setText("********");  // hidden until Read Secret

                attributesTableModel.setRowCount(0);
                maybeAttrs.ifPresent(attrs ->
                    attrs.entrySet().stream()
                            .sorted(Map.Entry.comparingByKey())
                            .forEach(entry -> attributesTableModel.addRow(
                                    new Object[]{entry.getKey(), entry.getValue()})));
                log("Selected item: %s (%s)", itemLabel, path);
            } catch (Exception ex) {
                log("DETAIL FAILED: %s", exceptionDetail(ex));
                clearDetail();
            }
        }

        private void doRevealSecret() {
            if (!requireConnected()) return;
            String path = lblDetailPath.getText().trim();
            if (path.isEmpty() || path.equals(" ")) {
                log("Select an item first.");
                return;
            }
            try {
                Optional<char[]> maybeSecret = collection.getSecret(path);
                if (maybeSecret.isPresent()) {
                    char[] secret = maybeSecret.get();
                    lblDetailSecret.setText(new String(secret));
                    Arrays.fill(secret, '\0');
                    log("Secret revealed for: %s", path);
                } else {
                    lblDetailSecret.setText("<empty>");
                    log("Secret is empty for: %s", path);
                }
            } catch (Exception ex) {
                log("READ SECRET FAILED: %s", exceptionDetail(ex));
            }
        }

        // ── CRUD ──────────────────────────────────────────────────────

        private void doCreate() {
            if (!requireConnected()) return;
            String label = tfLabel.getText().trim();
            String secret = tfSecret.getText();
            if (label.isEmpty() || secret.isEmpty()) {
                log("ERROR: Label and secret are required to create an item.");
                return;
            }
            try {
                Map<String, String> attrs = buildAttributes();
                Optional<String> maybePath = collection.createItem(label, secret,
                        attrs.isEmpty() ? null : attrs);
                if (maybePath.isPresent()) {
                    log("Created item: %s", maybePath.get());
                    doListItems();
                    autoSync();
                } else {
                    log("ERROR: createItem returned empty.");
                }
            } catch (Exception ex) {
                log("CREATE FAILED: %s", exceptionDetail(ex));
            }
        }



        private void doDeleteItem() {
            if (!requireConnected()) return;
            String selected = lblDetailPath.getText().trim();
            if (selected.isEmpty() || selected.equals(" ")) {
                log("Select an item first.");
                return;
            }
            String itemLabel = collection.getItemLabel(selected).orElse("<unknown>");
            int confirm = JOptionPane.showConfirmDialog(this,
                    "Delete item from collection \"" + getCollectionDisplayName() + "\"?\n\n"
                            + "Label: " + itemLabel + "\n"
                            + "Path:  " + selected,
                    "Confirm Delete Item", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (confirm != JOptionPane.YES_OPTION) return;
            try {
                boolean deleted = collection.deleteItem(selected);
                if (deleted) {
                    log("Deleted item: %s", selected);
                } else {
                    log("WARNING: deleteItem returned false for: %s", selected);
                }
                clearDetail();
                doListItems();
                autoSync();
            } catch (Exception ex) {
                log("DELETE ITEM FAILED: %s", exceptionDetail(ex));
            }
        }

        private void doListItems() {
            if (!requireConnected()) return;
            try {
                Optional<List<String>> maybeItems = collection.getItems(Map.of());
                itemsModel.clear();
                if (maybeItems.isPresent()) {
                    List<String> items = maybeItems.get();
                    for (String item : items) {
                        itemsModel.addElement(item);
                    }
                    log("Listed %d item(s).", items.size());
                } else {
                    log("Listed 0 item(s) (empty response).");
                }
            } catch (Exception ex) {
                log("LIST FAILED: %s", exceptionDetail(ex));
            }
        }

        private void doSearch() {
            if (!requireConnected()) return;
            String query = tfSearch.getText().trim();
            String mode  = (String) cmbSearchMode.getSelectedItem();
            try {
                SearchMode searchMode = switch (mode) {
                    case "By Attribute Key"   -> SearchMode.BY_ATTRIBUTE_KEY;
                    case "By Attribute Value" -> SearchMode.BY_ATTRIBUTE_VALUE;
                    case "By Object ID"       -> SearchMode.BY_OBJECT_ID;
                    case "By Object Path"     -> SearchMode.BY_OBJECT_PATH;
                    default                   -> SearchMode.BY_NAME;
                };
                List<String> results = collection.search(query, searchMode, (Integer) cmbMaxDistance.getSelectedItem());
                int total = collection.getItems(Map.of()).map(List::size).orElse(0);
                itemsModel.clear();
                results.forEach(itemsModel::addElement);
                log("Search [%s] \"%s\": %d / %d item(s) matched.", mode, query, results.size(), total);
            } catch (Exception ex) {
                log("SEARCH FAILED: %s", exceptionDetail(ex));
            }
        }

        private void doDeleteCollection() {
            if (!requireConnected()) return;
            String name = getCollectionDisplayName();
            int confirm = JOptionPane.showConfirmDialog(this,
                    "Delete the entire collection \"" + name + "\"?\n\n"
                            + "This cannot be undone!",
                    "Confirm Delete Collection \"" + name + "\"",
                    JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (confirm != JOptionPane.YES_OPTION) return;
            try {
                boolean deleted = collection.delete();
                if (deleted) {
                    log("Collection deleted.");
                } else {
                    log("WARNING: collection.delete() returned false.");
                }
                doDisconnect();
            } catch (Exception ex) {
                log("DELETE COLLECTION FAILED: %s", exceptionDetail(ex));
            }
        }

        private void killKeyring() {
            int confirm = JOptionPane.showConfirmDialog(this,
                    "Kill the gnome-keyring process? This may affect the desktop session.\n\nProceed?",
                    "Kill Keyring", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (confirm != JOptionPane.YES_OPTION) return;
            try {
                ProcessBuilder pb = new ProcessBuilder("pkill", "-f", "gnome-keyring-daemon");
                Process p = pb.start();
                int rc = p.waitFor();
                log("killKeyring(): pkill returned %d", rc);
            } catch (Exception ex) {
                log("KILL KEYRING FAILED: %s", exceptionDetail(ex));
            }
        }

        private void startKeyring() {
            int confirm = JOptionPane.showConfirmDialog(this,
                    "Start the gnome-keyring-daemon for the current user?\n\nProceed?",
                    "Start Keyring", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
            if (confirm != JOptionPane.YES_OPTION) return;
            try {
                ProcessBuilder pb = new ProcessBuilder("gnome-keyring-daemon", "--start", "--components=secrets,pkcs11,ssh");
                pb.redirectErrorStream(true);
                Process p = pb.start();
                java.io.InputStream is = p.getInputStream();
                java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
                String out = s.hasNext() ? s.next() : "";
                int rc = p.waitFor();
                log("startKeyring(): exit=%d output=%s", rc, out.trim());
            } catch (Exception ex) {
                log("START KEYRING FAILED: %s", exceptionDetail(ex));
            }
        }

        // ── Helpers ───────────────────────────────────────────────────

        private Map<String, String> buildAttributes() {
            String key = tfAttributeKey.getText().trim();
            String value = tfAttributeValue.getText().trim();
            if (!key.isEmpty() && !value.isEmpty()) {
                return Map.of(key, value);
            }
            return Map.of();
        }

        private String getCollectionDisplayName() {
            if (rbDefault.isSelected()) return "Default";
            if (collection != null) {
                String lbl = collection.getLabel().orElse(tfCollectionLabel.getText().trim());
                String id  = collection.getId().orElse(tfCollectionId.getText().trim());
                return lbl.equals(id) ? lbl : lbl + " [" + id + "]";
            }
            String lbl = tfCollectionLabel.getText().trim();
            String id  = tfCollectionId.getText().trim();
            if (!lbl.isEmpty() && !id.isEmpty() && !lbl.equals(id)) return lbl + " [" + id + "]";
            return !id.isEmpty() ? id : lbl;
        }

        private boolean requireConnected() {
            if (collection == null) {
                log("Not connected. Click Connect first.");
                return false;
            }
            return true;
        }

        private void log(String fmt, Object... args) {
            String ts = LocalTime.now().format(TIME_FMT);
            String msg = String.format("[%s] %s%n", ts, String.format(fmt, args));
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

        private void updateDbusStatus() {
            boolean connected = system != null && system.isConnected();
            if (connected) {
                setStatusLabel(lblDbusConnected, true);
                if (service != null) {
                    setStatusLabel(lblDbusAvailable, true);
                    String provider = detectProvider();
                    lblProvider.setText(provider);
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
        }

        /** Delegate to {@link ProviderDetector} via the functional API. */
        private String detectProvider() {
            if (service != null) return service.getProvider();
            if (system != null && system.isConnected()) return ProviderDetector.detect(system.getConnection());
            return "N/A";
        }

        private static void resetStatusLabel(JLabel label) {
            label.setText("\u2014");
            label.setForeground(Color.GRAY);
        }

        private static void setStatusLabel(JLabel label, boolean value) {
            label.setText(value ? "Yes" : "No");
            label.setForeground(value ? new Color(0x4CAF50) : new Color(0xF44336));
        }

        // ── Auto-sync helper ─────────────────────────────────────────

        private void autoSync() {
            if (cbAutoSync.isSelected()) {
                refreshDebugState();
            }
        }

        // ── Debug state refresh ────────────────────────────────────

        private void refreshDebugState() {
            refreshSystemState();
            refreshServiceState();
            refreshSessionState();
            refreshCollectionState();
        }

        private void refreshSystemState() {
            debugSystemModel.setRowCount(0);
            debugSystemModel.addRow(new Object[]{"SystemInterface", system != null ? system.getClass().getSimpleName() : "null (not connected)"});
            debugSystemModel.addRow(new Object[]{"isConnected()", system != null ? str(system.isConnected()) : "N/A"});
            if (system != null) {
                DBusConnection conn = system.getConnection();
                debugSystemModel.addRow(new Object[]{"DBusConnection", conn != null ? conn.getClass().getSimpleName() : "null"});
                debugSystemModel.addRow(new Object[]{"DBusConnection.isConnected()", conn != null ? str(conn.isConnected()) : "N/A"});
                debugSystemModel.addRow(new Object[]{"DBusConnection.busAddress", conn != null ? safe(() -> conn.getAddress().toString()) : "N/A"});
            }
        }

        private void refreshServiceState() {
            debugServiceModel.setRowCount(0);
            if (service == null) {
                debugServiceModel.addRow(new Object[]{"ServiceInterface", "null (not connected)"});
                return;
            }
            debugServiceModel.addRow(new Object[]{"ServiceInterface", service.getClass().getSimpleName()});
            debugServiceModel.addRow(new Object[]{"isGnomeKeyringAvailable()", str(service.isGnomeKeyringAvailable())});
            debugServiceModel.addRow(new Object[]{"getTimeout()", formatDuration(service.getTimeout())});
            debugServiceModel.addRow(new Object[]{"getSessions().size()", str(service.getSessions().size())});
            debugServiceModel.addRow(new Object[]{"getService()", service.getService() != null ? service.getService().getObjectPath() : "null"});
        }

        private void refreshSessionState() {
            debugSessionModel.setRowCount(0);
            if (session == null) {
                debugSessionModel.addRow(new Object[]{"SessionInterface", "null (not connected)"});
                return;
            }
            debugSessionModel.addRow(new Object[]{"SessionInterface", session.getClass().getSimpleName()});
            debugSessionModel.addRow(new Object[]{"getId()", str(session.getId())});
            debugSessionModel.addRow(new Object[]{"getSession().getObjectPath()",
                    session.getSession() != null ? session.getSession().getObjectPath() : "null"});
            debugSessionModel.addRow(new Object[]{"getEncryptedSession()",
                    session.getEncryptedSession() != null ? "present" : "null"});
            debugSessionModel.addRow(new Object[]{"getCollections().size()",
                    safe(() -> str(session.getCollections().size()))});
        }

        private void refreshCollectionState() {
            debugCollectionModel.setRowCount(0);
            if (collection == null) {
                debugCollectionModel.addRow(new Object[]{"CollectionInterface", "null (not connected)"});
                return;
            }
            debugCollectionModel.addRow(new Object[]{"CollectionInterface", collection.getClass().getSimpleName()});
            debugCollectionModel.addRow(new Object[]{"getLabel()", collection.getLabel().orElse("<empty>")});
            debugCollectionModel.addRow(new Object[]{"getId()", collection.getId().orElse("<empty>")});
            boolean locked = collection.isLocked();
            if (!locked) wasUnlockedOnce = true;
            debugCollectionModel.addRow(new Object[]{"isLocked()", str(locked)});
            debugCollectionModel.addRow(new Object[]{"wasUnlockedOnce", str(wasUnlockedOnce)});
        }

        // ── Formatting helpers ─────────────────────────────────────────

        private static String str(Object value) {
            return String.valueOf(value);
        }

        private static String formatDuration(Duration d) {
            if (d == null) return "null";
            return d.getSeconds() + "s (" + d.toMillis() + "ms)";
        }

        @FunctionalInterface
        private interface SafeSupplier<T> { T get() throws Exception; }

        private static <T> String safe(SafeSupplier<T> supplier) {
            try {
                return str(supplier.get());
            } catch (Exception e) {
                return "<error: " + e.getClass().getSimpleName() + ">";
            }
        }

        private static String exceptionDetail(Exception ex) {
            StringWriter sw = new StringWriter();
            ex.printStackTrace(new PrintWriter(sw));
            // Return first 3 lines for brevity
            String[] lines = sw.toString().split("\\R", 4);
            return String.join("\n", Arrays.copyOf(lines, Math.min(lines.length, 3)));
        }
    }
}

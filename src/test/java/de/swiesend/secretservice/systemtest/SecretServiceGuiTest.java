package de.swiesend.secretservice.systemtest;

import de.swiesend.secretservice.functional.interfaces.CollectionInterface;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import de.swiesend.secretservice.functional.interfaces.SystemInterface;
import de.swiesend.secretservice.simple.SimpleCollection;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Field;
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
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception ignored) {
            }
            SecretServiceFrame frame = new SecretServiceFrame(latch);
            frame.setVisible(true);
        });
        latch.await(); // block until the user closes the window
    }

    // ─── GUI implementation ───────────────────────────────────────────────

    static final class SecretServiceFrame extends JFrame {

        private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm:ss");

        // Collection panel
        private final ButtonGroup collectionGroup = new ButtonGroup();
        private final JRadioButton rbDefault = new JRadioButton("Default collection");
        private final JRadioButton rbTest = new JRadioButton("Test collection", true);
        private final JTextField tfCollectionLabel = new JTextField("test", 14);
        private final JPasswordField pfCollectionPassword = new JPasswordField("test", 14);

        // Create-item panel
        private final JTextField tfLabel = new JTextField(20);
        private final JTextField tfSecret = new JTextField(20);
        private final JTextField tfAttrKey = new JTextField(10);
        private final JTextField tfAttrValue = new JTextField(10);

        // Items list
        private final DefaultListModel<String> itemsModel = new DefaultListModel<>();
        private final JList<String> itemsList = new JList<>(itemsModel);

        // Item detail panel (shown on selection)
        private final JLabel lblDetailPath = new JLabel(" ");
        private final JLabel lblDetailLabel = new JLabel(" ");
        private final JLabel lblDetailSecret = new JLabel("********");
        private final DefaultTableModel attrsTableModel = new DefaultTableModel(new String[]{"Key", "Value"}, 0) {
            @Override public boolean isCellEditable(int row, int col) { return false; }
        };
        private final JTable attrsTable = new JTable(attrsTableModel);

        // Log area
        private final JTextArea logArea = new JTextArea(12, 50);

        // Buttons
        private final JButton btnConnect = new JButton("Connect");
        private final JButton btnDisconnect = new JButton("Disconnect");
        private final JButton btnCreate = new JButton("Create");
        private final JButton btnClearCreate = new JButton("Clear");
        private final JButton btnRead = new JButton("Read Secret");
        private final JButton btnDeleteItem = new JButton("Delete Item");
        private final JButton btnList = new JButton("List Items");
        private final JButton btnDeleteCollection = new JButton("Delete Collection");
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

        // GUI-tracked state
        private boolean wasUnlockedOnce = false;

        private SimpleCollection collection;
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

            // ── Main tab ──
            JPanel mainTab = new JPanel(new BorderLayout(8, 8));
            mainTab.setBorder(new EmptyBorder(10, 10, 10, 10));
            mainTab.add(buildCollectionPanel(), BorderLayout.NORTH);
            mainTab.add(buildCenterPanel(), BorderLayout.CENTER);
            mainTab.add(buildLogPanel(), BorderLayout.SOUTH);
            tabs.addTab("Main", mainTab);

            // ── Debug tab ──
            tabs.addTab("Debug", buildDebugTab());

            setContentPane(tabs);
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
                pfCollectionPassword.setEnabled(false);
            });
            rbTest.addActionListener(e -> {
                tfCollectionLabel.setEnabled(true);
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

            gbc.gridx = 0; gbc.gridy = 2; gbc.anchor = GridBagConstraints.EAST;
            panel.add(new JLabel("Password:"), gbc);
            gbc.gridx = 1; gbc.anchor = GridBagConstraints.WEST;
            panel.add(pfCollectionPassword, gbc);

            gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 2; gbc.anchor = GridBagConstraints.CENTER;
            JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.CENTER, 8, 0));
            btnRow.add(lblConnectionStatus);
            btnRow.add(btnConnect);
            btnRow.add(btnDisconnect);
            panel.add(btnRow, gbc);

            updateConnectionIcon(false);
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
            createPanel.add(new JLabel("Attr key:"), gbc);
            gbc.gridx = 1; gbc.anchor = GridBagConstraints.WEST;
            createPanel.add(tfAttrKey, gbc);
            gbc.gridx = 2; gbc.anchor = GridBagConstraints.EAST;
            createPanel.add(new JLabel("value:"), gbc);
            gbc.gridx = 3; gbc.anchor = GridBagConstraints.WEST;
            createPanel.add(tfAttrValue, gbc);

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
            lblDetailPath.setFont(lblDetailPath.getFont().deriveFont(Font.PLAIN));
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
            JScrollPane attrsScroll = new JScrollPane(attrsTable);
            attrsScroll.setPreferredSize(new Dimension(0, 80));
            attrsTable.setFillsViewportHeight(true);
            detailPanel.add(attrsScroll, dg);

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
            panel.add(dangerPanel, BorderLayout.SOUTH);

            return panel;
        }

        // ── Debug tab ─────────────────────────────────────────────────

        private JPanel buildDebugTab() {
            JPanel panel = new JPanel(new BorderLayout(8, 8));
            panel.setBorder(new EmptyBorder(10, 10, 10, 10));

            // Four state sections in a 2×2 grid
            JPanel grid = new JPanel(new GridLayout(2, 2, 8, 8));
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
            btnCreate.addActionListener(e -> doCreate());
            btnClearCreate.addActionListener(e -> {
                tfLabel.setText("");
                tfSecret.setText("");
                tfAttrKey.setText("");
                tfAttrValue.setText("");
            });
            btnRead.addActionListener(e -> doRevealSecret());
            btnDeleteItem.addActionListener(e -> doDeleteItem());
            btnList.addActionListener(e -> doListItems());
            btnDeleteCollection.addActionListener(e -> doDeleteCollection());
            btnClearLog.addActionListener(e -> logArea.setText(""));
            itemsList.addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting()) doShowItemDetail();
            });
            btnDebugRefresh.addActionListener(e -> refreshDebugState());
        }

        private void setItemControlsEnabled(boolean enabled) {
            tfLabel.setEnabled(enabled);
            tfSecret.setEnabled(enabled);
            tfAttrKey.setEnabled(enabled);
            tfAttrValue.setEnabled(enabled);
            btnCreate.setEnabled(enabled);
            btnClearCreate.setEnabled(enabled);
            btnRead.setEnabled(enabled);
            btnDeleteItem.setEnabled(enabled);
            btnList.setEnabled(enabled);
            btnDeleteCollection.setEnabled(enabled);
            itemsList.setEnabled(enabled);
            btnDisconnect.setEnabled(enabled);
            btnConnect.setEnabled(!enabled);
            rbDefault.setEnabled(!enabled);
            rbTest.setEnabled(!enabled);
            tfCollectionLabel.setEnabled(!enabled && rbTest.isSelected());
            pfCollectionPassword.setEnabled(!enabled && rbTest.isSelected());
        }

        // ── Connect / Disconnect ──────────────────────────────────────

        private void doConnect() {
            try {
                if (rbDefault.isSelected()) {
                    collection = new SimpleCollection();
                    log("Connected to the default collection.");
                } else {
                    String label = tfCollectionLabel.getText().trim();
                    char[] pw = pfCollectionPassword.getPassword();
                    if (label.isEmpty()) {
                        log("ERROR: Collection label must not be empty.");
                        return;
                    }
                    collection = new SimpleCollection(label, new String(pw));
                    Arrays.fill(pw, '\0');
                    log("Connected to collection \"%s\".", label);
                }
                boolean locked = collection.isLocked();
                if (!locked) wasUnlockedOnce = true;
                log("Locked: %s", locked);
                setItemControlsEnabled(true);
                updateConnectionIcon(true);
                autoSync();
            } catch (IOException ex) {
                log("CONNECT FAILED: %s", exceptionDetail(ex));
            }
        }

        private void doDisconnect() {
            disconnectQuietly();
            itemsModel.clear();
            clearDetail();
            setItemControlsEnabled(false);
            updateConnectionIcon(false);
            autoSync();
            log("Disconnected.");
        }

        private void disconnectQuietly() {
            if (collection != null) {
                try {
                    collection.close();
                } catch (Exception ignored) {
                }
                collection = null;
            }
        }

        // ── Item detail (on selection) ─────────────────────────────

        private void clearDetail() {
            lblDetailPath.setText(" ");
            lblDetailLabel.setText(" ");
            lblDetailSecret.setText("********");
            attrsTableModel.setRowCount(0);
        }

        private void doShowItemDetail() {
            String selected = itemsList.getSelectedValue();
            if (selected == null || collection == null) {
                clearDetail();
                return;
            }
            try {
                String itemLabel = collection.getLabel(selected);
                Map<String, String> attrs = collection.getAttributes(selected);

                lblDetailPath.setText(selected);
                lblDetailLabel.setText(itemLabel != null ? itemLabel : "<unknown>");
                lblDetailSecret.setText("********");  // hidden until Read Secret

                attrsTableModel.setRowCount(0);
                if (attrs != null) {
                    // Sort keys for stable display
                    attrs.entrySet().stream()
                            .sorted(Map.Entry.comparingByKey())
                            .forEach(entry -> attrsTableModel.addRow(
                                    new Object[]{entry.getKey(), entry.getValue()}));
                }
                log("Selected item: %s (%s)", itemLabel, selected);
            } catch (Exception ex) {
                log("DETAIL FAILED: %s", exceptionDetail(ex));
                clearDetail();
            }
        }

        private void doRevealSecret() {
            if (!requireConnected()) return;
            String selected = itemsList.getSelectedValue();
            if (selected == null) {
                log("Select an item from the list first.");
                return;
            }
            try {
                char[] secret = collection.getSecret(selected);
                if (secret != null) {
                    lblDetailSecret.setText(new String(secret));
                    Arrays.fill(secret, '\0');
                    log("Secret revealed for: %s", selected);
                } else {
                    lblDetailSecret.setText("<null>");
                    log("Secret is null for: %s", selected);
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
                String path = collection.createItem(label, secret, attrs.isEmpty() ? null : attrs);
                if (path != null) {
                    log("Created item: %s", path);
                    doListItems();
                    autoSync();
                } else {
                    log("ERROR: createItem returned null.");
                }
            } catch (Exception ex) {
                log("CREATE FAILED: %s", exceptionDetail(ex));
            }
        }



        private void doDeleteItem() {
            if (!requireConnected()) return;
            String selected = itemsList.getSelectedValue();
            if (selected == null) {
                log("Select an item from the list first.");
                return;
            }
            String itemLabel = collection.getLabel(selected);
            int confirm = JOptionPane.showConfirmDialog(this,
                    "Delete item from collection \"" + getCollectionDisplayName() + "\"?\n\n"
                            + "Label: " + itemLabel + "\n"
                            + "Path:  " + selected,
                    "Confirm Delete Item", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (confirm != JOptionPane.YES_OPTION) return;
            try {
                collection.deleteItem(selected);
                log("Deleted item: %s", selected);
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
                // Always list all items in the collection (empty map = no filter)
                List<String> items = collection.getItems(Map.of());
                itemsModel.clear();
                if (items != null) {
                    for (String item : items) {
                        itemsModel.addElement(item);
                    }
                    log("Listed %d item(s).", items.size());
                } else {
                    log("Listed 0 item(s) (null response).");
                }
            } catch (Exception ex) {
                log("LIST FAILED: %s", exceptionDetail(ex));
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
                collection.delete();
                log("Collection deleted.");
                doDisconnect();
            } catch (Exception ex) {
                log("DELETE COLLECTION FAILED: %s", exceptionDetail(ex));
            }
        }

        // ── Helpers ───────────────────────────────────────────────────

        private Map<String, String> buildAttributes() {
            String key = tfAttrKey.getText().trim();
            String value = tfAttrValue.getText().trim();
            if (!key.isEmpty() && !value.isEmpty()) {
                return Map.of(key, value);
            }
            return Map.of();
        }

        private String getCollectionDisplayName() {
            if (rbDefault.isSelected()) {
                return "Default";
            }
            return tfCollectionLabel.getText().trim();
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
            debugSystemModel.addRow(new Object[]{"SimpleCollection.isConnected()", str(SimpleCollection.isConnected())});
            debugSystemModel.addRow(new Object[]{"SimpleCollection.isAvailable()", str(SimpleCollection.isAvailable())});
            debugSystemModel.addRow(new Object[]{"SimpleCollection.isGnomeKeyringAvailable()", str(SimpleCollection.isGnomeKeyringAvailable())});

            // Access the static DBusConnection via reflection
            DBusConnection conn = getPrivateStaticField(SimpleCollection.class, "connection", DBusConnection.class);
            debugSystemModel.addRow(new Object[]{"DBusConnection", conn != null ? conn.getClass().getSimpleName() : "null"});
            debugSystemModel.addRow(new Object[]{"DBusConnection.isConnected()", conn != null ? str(conn.isConnected()) : "N/A"});
            debugSystemModel.addRow(new Object[]{"DBusConnection.busAddress", conn != null ? safe(() -> conn.getAddress().toString()) : "N/A"});
        }

        private void refreshServiceState() {
            debugServiceModel.setRowCount(0);
            ServiceInterface svc = getPrivateField(collection, "service", ServiceInterface.class);
            if (svc == null) {
                debugServiceModel.addRow(new Object[]{"ServiceInterface", "null (not connected)"});
                return;
            }
            debugServiceModel.addRow(new Object[]{"ServiceInterface", svc.getClass().getSimpleName()});
            debugServiceModel.addRow(new Object[]{"isGnomeKeyringAvailable()", str(svc.isGnomeKeyringAvailable())});
            debugServiceModel.addRow(new Object[]{"getTimeout()", formatDuration(svc.getTimeout())});
            debugServiceModel.addRow(new Object[]{"getSessions().size()", str(svc.getSessions().size())});
            debugServiceModel.addRow(new Object[]{"getService()", svc.getService() != null ? svc.getService().getObjectPath() : "null"});
        }

        private void refreshSessionState() {
            debugSessionModel.setRowCount(0);
            SessionInterface sess = getPrivateField(collection, "session", SessionInterface.class);
            if (sess == null) {
                debugSessionModel.addRow(new Object[]{"SessionInterface", "null (not connected)"});
                return;
            }
            debugSessionModel.addRow(new Object[]{"SessionInterface", sess.getClass().getSimpleName()});
            debugSessionModel.addRow(new Object[]{"getId()", str(sess.getId())});
            debugSessionModel.addRow(new Object[]{"getSession().getObjectPath()",
                    sess.getSession() != null ? sess.getSession().getObjectPath() : "null"});
            debugSessionModel.addRow(new Object[]{"getEncryptedSession()",
                    sess.getEncryptedSession() != null ? "present" : "null"});
            debugSessionModel.addRow(new Object[]{"getCollections().size()",
                    safe(() -> str(sess.getCollections().size()))});
        }

        private void refreshCollectionState() {
            debugCollectionModel.setRowCount(0);
            CollectionInterface col = getPrivateField(collection, "delegate", CollectionInterface.class);
            if (col == null) {
                debugCollectionModel.addRow(new Object[]{"CollectionInterface", "null (not connected)"});
                return;
            }
            debugCollectionModel.addRow(new Object[]{"CollectionInterface", col.getClass().getSimpleName()});
            debugCollectionModel.addRow(new Object[]{"getLabel()", col.getLabel().orElse("<empty>")});
            debugCollectionModel.addRow(new Object[]{"getId()", col.getId().orElse("<empty>")});
            boolean locked = col.isLocked();
            if (!locked) wasUnlockedOnce = true;
            debugCollectionModel.addRow(new Object[]{"isLocked()", str(locked)});
            debugCollectionModel.addRow(new Object[]{"wasUnlockedOnce", str(wasUnlockedOnce)});
        }

        // ── Reflection helpers ─────────────────────────────────────────

        @SuppressWarnings("unchecked")
        private static <T> T getPrivateField(Object target, String fieldName, Class<T> type) {
            if (target == null) return null;
            try {
                Class<?> clazz = target.getClass();
                // Walk up the hierarchy to find the field
                while (clazz != null) {
                    try {
                        Field f = clazz.getDeclaredField(fieldName);
                        f.setAccessible(true);
                        return type.cast(f.get(target));
                    } catch (NoSuchFieldException e) {
                        clazz = clazz.getSuperclass();
                    }
                }
            } catch (Exception ignored) {
            }
            return null;
        }

        @SuppressWarnings("unchecked")
        private static <T> T getPrivateStaticField(Class<?> clazz, String fieldName, Class<T> type) {
            try {
                Field f = clazz.getDeclaredField(fieldName);
                f.setAccessible(true);
                return type.cast(f.get(null));
            } catch (Exception ignored) {
            }
            return null;
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

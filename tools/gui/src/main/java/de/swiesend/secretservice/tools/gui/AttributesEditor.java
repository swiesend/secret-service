package de.swiesend.secretservice.tools.gui;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.util.Map;
import java.util.TreeMap;

/** The attributes of an item, as a table of keys and values with buttons that add and remove a row. */
final class AttributesEditor extends JPanel {

    private boolean editable = true;
    private final DefaultTableModel model = new DefaultTableModel(new String[]{"Key", "Value"}, 0) {
        @Override
        public boolean isCellEditable(int row, int column) {
            return editable;
        }
    };
    private final JTable table = new JTable(model);
    private final JButton add = new JButton("Add");
    private final JButton remove = new JButton("Remove");

    /** @param name the prefix of the names by which the test finds the table and its buttons */
    AttributesEditor(String name) {
        super(new BorderLayout(4, 4));
        setBorder(new TitledBorder("Attributes"));
        table.setName(name);
        add.setName(name + "-add");
        remove.setName(name + "-remove");
        table.setFillsViewportHeight(true);
        table.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);
        JScrollPane scroll = new JScrollPane(table);
        scroll.setPreferredSize(new Dimension(240, 60));
        add(scroll, BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        buttons.add(add);
        buttons.add(remove);
        add(buttons, BorderLayout.SOUTH);

        add.addActionListener(e -> {
            stopEditing();
            model.addRow(new Object[]{"", ""});
            int row = model.getRowCount() - 1;
            table.setRowSelectionInterval(row, row);
            table.editCellAt(row, 0);
            table.requestFocusInWindow();
        });
        remove.addActionListener(e -> {
            stopEditing();
            int[] rows = table.getSelectedRows();
            for (int i = rows.length - 1; i >= 0; i--) model.removeRow(rows[i]);
        });
    }

    /** The attributes, by key: rows with a blank key do not count. */
    Map<String, String> attributes() {
        stopEditing();
        Map<String, String> attributes = new TreeMap<>();
        for (int row = 0; row < model.getRowCount(); row++) {
            String key = String.valueOf(model.getValueAt(row, 0)).trim();
            if (!key.isEmpty()) attributes.put(key, String.valueOf(model.getValueAt(row, 1)));
        }
        return attributes;
    }

    void setAttributes(Map<String, String> attributes) {
        stopEditing();
        model.setRowCount(0);
        attributes.forEach((key, value) -> model.addRow(new Object[]{key, value}));
    }

    void setEditable(boolean editable) {
        stopEditing();
        this.editable = editable;
        add.setEnabled(editable);
        remove.setEnabled(editable);
        table.setEnabled(editable);
    }

    private void stopEditing() {
        if (table.isEditing()) table.getCellEditor().stopCellEditing();
    }
}

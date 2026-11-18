package de.swiesend.secretservice.tools.gui;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import java.awt.Dimension;

/**
 * A tabbed pane with a component in the free corner of its tab row, to the right of the tabs.
 * Swing's tabbed pane has no place of its own for one.
 */
final class CornerPanel extends JPanel {

    private final JTabbedPane tabs;
    private final JComponent corner;

    CornerPanel(JTabbedPane tabs, JComponent corner) {
        super(null);
        this.tabs = tabs;
        this.corner = corner;
        add(corner); // first: painted over the tabbed pane
        add(tabs);
    }

    @Override
    public void doLayout() {
        tabs.setBounds(0, 0, getWidth(), getHeight());
        Dimension size = corner.getPreferredSize();
        int row = tabs.getTabCount() > 0 ? tabs.getBoundsAt(0).height : size.height;
        int height = Math.min(size.height, Math.max(row, 1));
        corner.setBounds(getWidth() - size.width - 2, 0, size.width, height);
    }

    @Override
    public Dimension getPreferredSize() {
        return tabs.getPreferredSize();
    }

    @Override
    public Dimension getMinimumSize() {
        return tabs.getMinimumSize();
    }

    @Override
    public boolean isOptimizedDrawingEnabled() {
        return false; // the corner overlaps the tabbed pane
    }
}

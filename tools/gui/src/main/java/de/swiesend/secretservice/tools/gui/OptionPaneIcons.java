package de.swiesend.secretservice.tools.gui;

import javax.swing.Icon;
import javax.swing.UIManager;
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Polygon;
import java.awt.RenderingHints;

/**
 * The signs of the dialogs, for a look that has none. GTK's look takes them from GTK's stock icons,
 * which GTK 3 no longer has, and leaves its warnings and questions without a sign. Its dialogs
 * look the sign up in GTK's style, not in {@link UIManager}: the GUI hands each dialog its sign.
 */
final class OptionPaneIcons {

    private static final int SIZE = 40;

    private OptionPaneIcons() {
    }

    /** Puts a drawn sign where the look has none. */
    static void fillIn() {
        fillIn("OptionPane.warningIcon", new Sign(new Color(0xE5A50A), "!", true));
        fillIn("OptionPane.questionIcon", new Sign(new Color(0x3584E4), "?", false));
        fillIn("OptionPane.informationIcon", new Sign(new Color(0x3584E4), "i", false));
        fillIn("OptionPane.errorIcon", new Sign(new Color(0xC01C28), "!", false));
    }

    /** The look's sign of a warning, or the drawn one. */
    static Icon warning() {
        return UIManager.getIcon("OptionPane.warningIcon");
    }

    /** The look's sign of a question, or the drawn one. */
    static Icon question() {
        return UIManager.getIcon("OptionPane.questionIcon");
    }

    private static void fillIn(String key, Icon icon) {
        if (UIManager.getIcon(key) == null) UIManager.put(key, icon);
    }

    /** A triangle or a circle in the colour, with the mark in white. */
    private record Sign(Color color, String mark, boolean triangle) implements Icon {

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            g2.setColor(color);
            if (triangle) {
                Polygon shape = new Polygon(new int[]{x + SIZE / 2, x + SIZE - 1, x}, new int[]{y + 2, y + SIZE - 3, y + SIZE - 3}, 3);
                g2.setStroke(new BasicStroke(3f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
                g2.fillPolygon(shape);
                g2.drawPolygon(shape);
            } else {
                g2.fillOval(x, y, SIZE - 1, SIZE - 1);
            }
            g2.setColor(Color.WHITE);
            g2.setFont(new Font(Font.SANS_SERIF, Font.BOLD, SIZE / 2));
            FontMetrics metrics = g2.getFontMetrics();
            int markX = x + (SIZE - metrics.stringWidth(mark)) / 2;
            int markY = y + (triangle ? SIZE * 3 / 4 + 1 : (SIZE + metrics.getAscent() - metrics.getDescent()) / 2);
            g2.drawString(mark, markX, markY);
            g2.dispose();
        }

        @Override
        public int getIconWidth() {
            return SIZE;
        }

        @Override
        public int getIconHeight() {
            return SIZE;
        }
    }
}

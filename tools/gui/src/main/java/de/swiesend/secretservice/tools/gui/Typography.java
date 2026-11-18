package de.swiesend.secretservice.tools.gui;

import javax.swing.JTable;
import javax.swing.UIManager;
import javax.swing.plaf.FontUIResource;
import java.awt.Component;
import java.awt.Container;
import java.awt.Font;

/**
 * How the GUI sets its text: crisp, with titles that stand out from the text under them, and in
 * the desktop's own font and size otherwise.
 */
final class Typography {

    /** The JVM's switch for the anti-aliasing of text, which AWT reads when it starts. */
    static final String ANTIALIASING = "awt.useSystemAAFontSettings";

    private Typography() {
    }

    /**
     * Smooths text with the screen's subpixels, which draws it crisper and darker than grey
     * smoothing. The JVM takes the desktop's choice only where the desktop announces one, as GNOME
     * does through GTK's settings; elsewhere, and in the CI container, it smooths in grey. A value
     * that {@code -Dawt.useSystemAAFontSettings} gives stays, for a screen whose subpixels are not
     * in the usual order. Called before AWT starts: later, it changes nothing.
     */
    static void smoothText() {
        if (System.getProperty(ANTIALIASING) == null) System.setProperty(ANTIALIASING, "lcd");
    }

    /** Titles of panels in bold, after the look is set. */
    static void boldTitles() {
        UIManager.put("TitledBorder.font", new FontUIResource(titleFont()));
    }

    /** The desktop's font in bold, for titles and table headers. */
    static Font titleFont() {
        return UIManager.getFont("Label.font").deriveFont(Font.BOLD);
    }

    /**
     * The table headers under {@code root} in bold. GTK's look takes a header's font from GTK's
     * style unless the header has a font of its own.
     */
    static void boldTableHeaders(Component root) {
        if (root instanceof JTable table && table.getTableHeader() != null) {
            table.getTableHeader().setFont(titleFont());
        }
        if (root instanceof Container container) {
            for (Component child : container.getComponents()) boldTableHeaders(child);
        }
        if (root instanceof javax.swing.JScrollPane scroll && scroll.getViewport().getView() != null) {
            boldTableHeaders(scroll.getViewport().getView());
        }
    }

    /** A monospaced font one point under the desktop's, at least 12, for the log. */
    static Font logFont() {
        int size = Math.max(12, UIManager.getFont("Label.font").getSize() - 1);
        return new Font(Font.MONOSPACED, Font.PLAIN, size);
    }
}

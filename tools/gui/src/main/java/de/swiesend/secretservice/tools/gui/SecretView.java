package de.swiesend.secretservice.tools.gui;

import javax.swing.JComponent;
import javax.swing.UIManager;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.util.Arrays;

/**
 * Shows a secret that the window has read, masked until it is revealed. It keeps the secret in a
 * {@code char[]} of its own, which it paints with {@link Graphics#drawChars} and erases when it
 * forgets it: a text component would keep the secret in a {@code String}, which nobody erases.
 */
final class SecretView extends JComponent {

    private static final char MASK = '•';
    private static final String NOT_READ = "(not read)";

    private char[] secret = new char[0];
    private boolean present = false;
    private boolean revealed = false;

    SecretView() {
        setFont(UIManager.getFont("Label.font"));
        setForeground(UIManager.getColor("Label.foreground"));
    }

    /** Shows the secret, masked, and takes the array over: the view erases it when it forgets it. */
    void show(char[] owned) {
        forget();
        secret = owned;
        present = true;
        repaint();
    }

    /** Erases the secret, and masks the view. */
    void forget() {
        Arrays.fill(secret, '\0');
        secret = new char[0];
        present = false;
        revealed = false;
        repaint();
    }

    boolean isPresent() {
        return present;
    }

    boolean isRevealed() {
        return revealed;
    }

    void setRevealed(boolean revealed) {
        this.revealed = present && revealed;
        repaint();
    }

    /** A copy of the secret, which the caller erases. */
    char[] copy() {
        return secret.clone();
    }

    /** Whether the view holds that secret. For the test, which compares without a copy. */
    boolean holds(CharSequence expected) {
        if (!present || expected.length() != secret.length) return false;
        for (int i = 0; i < secret.length; i++) {
            if (secret[i] != expected.charAt(i)) return false;
        }
        return true;
    }

    @Override
    public Dimension getPreferredSize() {
        FontMetrics metrics = getFontMetrics(getFont());
        return new Dimension(200, metrics.getHeight() + 2);
    }

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        FontMetrics metrics = g.getFontMetrics(getFont());
        int baseline = (getHeight() - metrics.getHeight()) / 2 + metrics.getAscent();
        g.setFont(getFont());
        if (!present) {
            g.setColor(Color.GRAY);
            g.drawString(NOT_READ, 0, baseline);
        } else if (revealed) {
            g.setColor(getForeground());
            g.drawChars(secret, 0, secret.length, 0, baseline);
        } else {
            char[] mask = new char[Math.min(secret.length, 64)];
            Arrays.fill(mask, MASK);
            g.setColor(getForeground());
            g.drawChars(mask, 0, mask.length, 0, baseline);
        }
    }
}

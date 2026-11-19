package de.swiesend.secretservice.tools.gui;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Window;
import java.util.Map;
import java.util.Optional;

/** Asks for a new item of the open collection: its label, its secret and its attributes. */
final class NewItemDialog extends JDialog {

    static final String TITLE = "New item";

    /** @param secret the caller erases it */
    record Result(String label, char[] secret, Map<String, String> attributes) {
    }

    private static final char ECHO = new JPasswordField().getEchoChar();

    private final JTextField label = new JTextField(24);
    private final JPasswordField secret = new JPasswordField(24);
    private final JLabel message = new JLabel(" ");
    private final JButton create = new JButton("Create");
    private final AttributesEditor attributes = new AttributesEditor("new-item-attributes");
    private Result result;

    private NewItemDialog(Window owner, String collection) {
        super(owner, TITLE, ModalityType.APPLICATION_MODAL);
        label.setName("new-item-label");
        secret.setName("new-item-secret");
        message.setName("new-item-message");
        create.setName("new-item-create");
        JCheckBox show = new JCheckBox("Show");
        show.setName("new-item-show");
        JButton cancel = new JButton("Cancel");
        cancel.setName("new-item-cancel");
        show.addItemListener(e -> secret.setEchoChar(show.isSelected() ? (char) 0 : ECHO));

        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 6, 4, 6);
        c.anchor = GridBagConstraints.WEST;
        c.gridx = 0; c.gridy = 0; c.gridwidth = 3;
        form.add(new JLabel("In the collection \"" + collection + "\""), c);
        c.gridwidth = 1; c.gridy = 1;
        form.add(new JLabel("Label:"), c);
        c.gridx = 1; c.gridwidth = 2; c.fill = GridBagConstraints.HORIZONTAL; c.weightx = 1;
        form.add(label, c);
        c.gridx = 0; c.gridy = 2; c.gridwidth = 1; c.fill = GridBagConstraints.NONE; c.weightx = 0;
        form.add(new JLabel("Secret:"), c);
        c.gridx = 1; c.fill = GridBagConstraints.HORIZONTAL; c.weightx = 1;
        form.add(secret, c);
        c.gridx = 2; c.fill = GridBagConstraints.NONE; c.weightx = 0;
        form.add(show, c);
        c.gridx = 0; c.gridy = 3; c.gridwidth = 3; c.fill = GridBagConstraints.BOTH; c.weighty = 1;
        form.add(attributes, c);
        c.gridy = 4; c.weighty = 0; c.fill = GridBagConstraints.HORIZONTAL;
        message.setForeground(new Color(0xC01C28));
        form.add(message, c);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        buttons.add(cancel);
        buttons.add(create);

        JPanel content = new JPanel(new BorderLayout(0, 8));
        content.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        content.add(form, BorderLayout.CENTER);
        content.add(buttons, BorderLayout.SOUTH);
        setContentPane(content);

        DocumentListener validate = new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { validateInput(); }
            @Override public void removeUpdate(DocumentEvent e) { validateInput(); }
            @Override public void changedUpdate(DocumentEvent e) { validateInput(); }
        };
        label.getDocument().addDocumentListener(validate);
        secret.getDocument().addDocumentListener(validate);
        create.addActionListener(e -> {
            result = new Result(label.getText().trim(), secret.getPassword(), attributes.attributes());
            dispose();
        });
        cancel.addActionListener(e -> dispose());
        validateInput();
        pack();
        setLocationRelativeTo(owner);
    }

    private void validateInput() {
        String problem;
        if (label.getText().trim().isEmpty()) problem = "Give the item a label.";
        else if (secret.getDocument().getLength() == 0) problem = "Type the secret.";
        else problem = null;
        message.setText(problem == null ? " " : problem);
        create.setEnabled(problem == null);
    }

    /**
     * Shows the dialog and waits for the user.
     *
     * @param collection the name of the open collection, which the dialog names
     * @return the new item, or empty where the user cancelled
     */
    static Optional<Result> ask(Window owner, String collection) {
        NewItemDialog dialog = new NewItemDialog(owner, collection);
        dialog.setVisible(true);
        dialog.secret.setText("");
        return Optional.ofNullable(dialog.result);
    }
}

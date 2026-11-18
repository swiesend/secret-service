package de.swiesend.secretservice.tools.gui;

import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
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
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;

/**
 * Asks for a new collection: its label, which no collection of the provider may have, and whether
 * the provider asks for the password in its own dialog or the user gives it here.
 */
final class NewCollectionDialog extends JDialog {

    static final String TITLE = "New collection";

    /** @param password empty where the provider asks for it; the caller erases it */
    record Result(String label, char[] password) {
    }

    private final Set<String> existingLabels;
    private final JTextField label = new JTextField(22);
    private final JRadioButton providerAsks = new JRadioButton("The provider asks for the password in its own dialog", true);
    private final JRadioButton passwordHere = new JRadioButton("Set the password here:");
    private final JPasswordField password = new JPasswordField(22);
    private final JLabel message = new JLabel(" ");
    private final JButton create = new JButton("Create");
    private Result result;

    private NewCollectionDialog(Window owner, Set<String> existingLabels) {
        super(owner, TITLE, ModalityType.APPLICATION_MODAL);
        this.existingLabels = existingLabels;
        label.setName("new-collection-label");
        providerAsks.setName("new-collection-provider-asks");
        passwordHere.setName("new-collection-set-password");
        password.setName("new-collection-password");
        message.setName("new-collection-message");
        create.setName("new-collection-create");
        JButton cancel = new JButton("Cancel");
        cancel.setName("new-collection-cancel");

        ButtonGroup choice = new ButtonGroup();
        choice.add(providerAsks);
        choice.add(passwordHere);
        passwordHere.setToolTipText("gnome-keyring creates the collection with it, without its dialog");

        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 6, 4, 6);
        c.anchor = GridBagConstraints.WEST;
        c.gridx = 0; c.gridy = 0;
        form.add(new JLabel("Label:"), c);
        c.gridx = 1; c.fill = GridBagConstraints.HORIZONTAL; c.weightx = 1;
        form.add(label, c);
        c.gridx = 0; c.gridy = 1; c.gridwidth = 2; c.fill = GridBagConstraints.NONE; c.weightx = 0;
        form.add(new JLabel("Password:"), c);
        c.gridy = 2; c.insets = new Insets(0, 18, 0, 6);
        form.add(providerAsks, c);
        c.gridy = 3;
        form.add(passwordHere, c);
        c.gridy = 4; c.insets = new Insets(0, 42, 4, 6); c.fill = GridBagConstraints.HORIZONTAL;
        form.add(password, c);
        c.gridy = 5; c.insets = new Insets(8, 6, 4, 6);
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
        getRootPane().setDefaultButton(create);

        DocumentListener validate = new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { validateInput(); }
            @Override public void removeUpdate(DocumentEvent e) { validateInput(); }
            @Override public void changedUpdate(DocumentEvent e) { validateInput(); }
        };
        label.getDocument().addDocumentListener(validate);
        password.getDocument().addDocumentListener(validate);
        providerAsks.addItemListener(e -> validateInput());
        passwordHere.addItemListener(e -> validateInput());
        create.addActionListener(e -> {
            char[] typed = password.getPassword();
            result = new Result(label.getText().trim(), passwordHere.isSelected() ? typed : new char[0]);
            if (!passwordHere.isSelected()) Arrays.fill(typed, '\0');
            dispose();
        });
        cancel.addActionListener(e -> dispose());
        validateInput();
        pack();
        setLocationRelativeTo(owner);
    }

    /** Enables Create where the input makes a new collection, and says what is missing otherwise. */
    private void validateInput() {
        password.setEnabled(passwordHere.isSelected());
        String name = label.getText().trim();
        String problem;
        if (name.isEmpty()) problem = "Give the collection a label.";
        else if (existingLabels.contains(name)) problem = "A collection has this label: open it from the list.";
        else if (passwordHere.isSelected() && password.getDocument().getLength() == 0) problem = "Type the password, or let the provider ask for it.";
        else problem = null;
        message.setText(problem == null ? " " : problem);
        create.setEnabled(problem == null);
    }

    /**
     * Shows the dialog and waits for the user.
     *
     * @param existingLabels the labels of the provider's collections
     * @return the new collection, or empty where the user cancelled
     */
    static Optional<Result> ask(Window owner, Set<String> existingLabels) {
        NewCollectionDialog dialog = new NewCollectionDialog(owner, existingLabels);
        dialog.setVisible(true);
        dialog.password.setText("");
        return Optional.ofNullable(dialog.result);
    }
}

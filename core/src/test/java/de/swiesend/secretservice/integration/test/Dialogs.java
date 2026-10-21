package de.swiesend.secretservice.integration.test;

/**
 * The flags of the tests that need a user, for {@code @EnabledIfSystemProperty}: someone who
 * answers the provider's dialogs, and for most of them a keyring of the run's own, whose login
 * collection they lock and write into. The gnome-keyring-dialogs leg of the system tests workflow
 * offers both and sets both flags, which nothing else sets. On a developer's desktop these tests
 * skip, and so they never touch the user's keyring.
 *
 * <ul>
 *   <li>{@code -Dsecret-service.system-test.dialogs-answered=true}: someone answers the
 *       dialogs.</li>
 *   <li>{@code -Dsecret-service.system-test.default-collection=throwaway}: the default collection
 *       belongs to a keyring of the run's own.</li>
 * </ul>
 */
public final class Dialogs {

    /** Someone answers the provider's dialogs where this system property is {@code true}. */
    public static final String ANSWERED = "secret-service.system-test.dialogs-answered";

    /**
     * The default collection belongs to a keyring of the run's own where this system property is
     * {@code throwaway}.
     */
    public static final String DEFAULT_COLLECTION = "secret-service.system-test.default-collection";

    /** Why a test that locks or writes into the default collection skips without that keyring. */
    public static final String NOT_A_THROWAWAY_KEYRING = "Changes the user's default collection";

    /**
     * The environment variable with the directory through which a test controls the dialog
     * answerer of the gnome-keyring-dialogs container, which sets it, for
     * {@code @EnabledIfEnvironmentVariable}: see {@link #hold()}.
     */
    public static final String CONTROL = "SECRET_SERVICE_DIALOG_CONTROL";

    /** Why a test that controls the dialog answerer skips without it. */
    public static final String NO_ANSWERER_TO_CONTROL = "Needs the dialog answerer of the gnome-keyring-dialogs container";

    /** Keeps the answerer from the dialogs that come up from now on, as a user who is away. */
    public static void hold() throws java.io.IOException {
        java.nio.file.Files.writeString(control().resolve("hold"), "");
    }

    /** Lets the answerer answer the dialogs again, the ones that it held back among them. */
    public static void release() throws java.io.IOException {
        java.nio.file.Files.deleteIfExists(control().resolve("hold"));
    }

    /**
     * Has the answerer cancel the dialog on the screen, as a user who refuses it, also while it
     * holds back.
     *
     * @return whether it did within ten seconds
     */
    public static boolean cancelTheDialog() throws java.io.IOException, InterruptedException {
        java.nio.file.Path cancel = control().resolve("cancel");
        java.nio.file.Files.writeString(cancel, "");
        long deadline = System.nanoTime() + 10_000_000_000L;
        while (java.nio.file.Files.exists(cancel) && System.nanoTime() < deadline) Thread.sleep(100);
        return !java.nio.file.Files.exists(cancel);
    }

    private static java.nio.file.Path control() {
        return java.nio.file.Path.of(System.getenv(CONTROL));
    }

    private Dialogs() {
    }
}

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

    private Dialogs() {
    }
}

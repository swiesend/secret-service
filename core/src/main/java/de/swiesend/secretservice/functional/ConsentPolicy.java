package de.swiesend.secretservice.functional;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;

/**
 * What a collection asks before an operation that reveals or destroys many secrets.
 *
 * <p>A policy gives each {@link Operation} a {@link Requirement}. The collection checks it after the
 * operation's own argument and scope checks, and before the first call that has an effect, so a
 * call that will be refused anyway never asks first.</p>
 *
 * <p>{@link #none()} is the default: the library asks nobody, and the provider prompts only on its
 * own terms, for example to unlock a locked keyring. {@link #legacy()} is the behaviour of 3.x,
 * for a caller who wants it.</p>
 *
 * <p>A policy is immutable. {@link #require}, {@link #remember} and the factory methods return new
 * policies.</p>
 *
 * <p>No policy protects the keyring against another process of the same user: such a process can
 * read an unlocked keyring without this library (CVE-2018-19358). A consent protects the user
 * against the calling application's own mistakes, and lets the user see what it does.</p>
 */
public final class ConsentPolicy {

    /** The operations that a policy can put behind a consent. */
    public enum Operation {
        /** {@code getSecrets()} and {@code withSecrets()}: every secret of the collection. */
        READ_ALL,
        /** {@code deleteItem(path)}. */
        DELETE_ONE,
        /** {@code deleteItems(paths)}. One consent covers the whole call. */
        DELETE_MANY
    }

    /** What must happen before an operation runs. */
    public enum Requirement {
        /** Nothing: the operation runs as soon as its arguments are checked. */
        NONE,
        /**
         * The provider's unlock dialog: the collection is locked and unlocked again, so that the
         * provider asks for the keyring password. The dialog names the keyring, not the operation,
         * and while it is open the keyring is locked for every other application too. A collection
         * opened with a master password unlocks with it, without a dialog: the password stands for
         * the consent.
         */
        PROVIDER_PROMPT
    }

    /** What to do when a requirement cannot be met at all, as distinct from a refusal. */
    public enum WhenUnavailable {
        /**
         * Run the operation anyway. A provider that needs a prompt to lock, such as KeePassXC, can
         * never show the unlock dialog that {@link Requirement#PROVIDER_PROMPT} relies on.
         */
        PROCEED,
        /** Refuse the operation, as if the user had said no. */
        REFUSE
    }

    /** {@link #remember} with this value keeps a consent until the collection is closed. */
    public static final Duration UNTIL_CLOSED = ChronoUnit.FOREVER.getDuration();

    private record Rule(Requirement requirement, WhenUnavailable whenUnavailable) {
    }

    private static final Rule NO_CONSENT = new Rule(Requirement.NONE, WhenUnavailable.REFUSE);

    private final Map<Operation, Rule> rules;
    private final Duration remember;

    private ConsentPolicy(Map<Operation, Rule> rules, Duration remember) {
        this.rules = rules;
        this.remember = remember;
    }

    /** Asks nobody before any operation. The default of every collection. */
    public static ConsentPolicy none() {
        return new ConsentPolicy(new EnumMap<>(Operation.class), Duration.ZERO);
    }

    /**
     * The behaviour of 3.x: reading every secret needs the provider's dialog and is refused when the
     * provider cannot show it; deleting asks the provider too, but goes ahead when it cannot. A
     * consent lasts until the collection is closed.
     */
    public static ConsentPolicy legacy() {
        return none()
                .require(Operation.READ_ALL, Requirement.PROVIDER_PROMPT, WhenUnavailable.REFUSE)
                .require(Operation.DELETE_ONE, Requirement.PROVIDER_PROMPT, WhenUnavailable.PROCEED)
                .require(Operation.DELETE_MANY, Requirement.PROVIDER_PROMPT, WhenUnavailable.PROCEED)
                .remember(UNTIL_CLOSED);
    }

    /** Puts {@code operation} behind {@code requirement}, refused when it cannot be met. */
    public ConsentPolicy require(Operation operation, Requirement requirement) {
        return require(operation, requirement, WhenUnavailable.REFUSE);
    }

    /** Puts {@code operation} behind {@code requirement}, and says what to do when it cannot be met. */
    public ConsentPolicy require(Operation operation, Requirement requirement, WhenUnavailable whenUnavailable) {
        Objects.requireNonNull(operation, "operation");
        Objects.requireNonNull(requirement, "requirement");
        Objects.requireNonNull(whenUnavailable, "whenUnavailable");
        Map<Operation, Rule> next = new EnumMap<>(Operation.class);
        next.putAll(rules);
        if (requirement == Requirement.NONE) {
            // Not stored: nothing can be unavailable, so the rule is the same as no rule.
            next.remove(operation);
        } else {
            next.put(operation, new Rule(requirement, whenUnavailable));
        }
        return new ConsentPolicy(next, remember);
    }

    /**
     * How long a granted consent covers later operations of the same kind on the same collection
     * object: {@link Duration#ZERO}, the default, asks every time; {@link #UNTIL_CLOSED} asks once.
     * A provider's dialog covers every operation that requires one, because it proves the same
     * thing for all of them.
     */
    public ConsentPolicy remember(Duration duration) {
        Objects.requireNonNull(duration, "duration");
        if (duration.isNegative()) throw new IllegalArgumentException("duration must not be negative");
        return new ConsentPolicy(rules, duration);
    }

    /** What {@code operation} requires. */
    public Requirement requirement(Operation operation) {
        return rules.getOrDefault(Objects.requireNonNull(operation, "operation"), NO_CONSENT).requirement();
    }

    /** What happens when the requirement of {@code operation} cannot be met. */
    public WhenUnavailable whenUnavailable(Operation operation) {
        return rules.getOrDefault(Objects.requireNonNull(operation, "operation"), NO_CONSENT).whenUnavailable();
    }

    /** How long a granted consent is remembered. */
    public Duration remembered() {
        return remember;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof ConsentPolicy that && rules.equals(that.rules) && remember.equals(that.remember);
    }

    @Override
    public int hashCode() {
        return Objects.hash(rules, remember);
    }

    @Override
    public String toString() {
        return "ConsentPolicy" + rules + (remember.equals(UNTIL_CLOSED) ? " until closed" : " for " + remember);
    }
}

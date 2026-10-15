package de.swiesend.secretservice;

import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

/**
 * The answer of a call that can fail: a value, or the {@link Failure} that says why there is none.
 * The methods named {@code ...Checked} answer with it, where their plain counterparts answer
 * {@link Optional#empty()} or {@code false} and only log the reason.
 *
 * @param <T> the type of the value
 * @since 4.0.0
 */
public final class Result<T> {

    private final T value;
    private final Failure failure;

    private Result(T value, Failure failure) {
        this.value = value;
        this.failure = failure;
    }

    /** A success, with its value: null where the method says that a success can have none. */
    public static <T> Result<T> ok(T value) {
        return new Result<>(value, null);
    }

    public static <T> Result<T> failed(Failure failure) {
        return new Result<>(null, Objects.requireNonNull(failure, "failure must not be null"));
    }

    public static <T> Result<T> failed(Failure.Reason reason, String message) {
        return failed(Failure.of(reason, message));
    }

    public boolean isOk() {
        return failure == null;
    }

    /**
     * The value: empty when the call failed, or succeeded without one. It is what the plain
     * counterpart of the method answers.
     */
    public Optional<T> value() {
        return Optional.ofNullable(value);
    }

    /** Why the call failed: empty when it succeeded. */
    public Optional<Failure> failure() {
        return Optional.ofNullable(failure);
    }

    /** The reason of the failure: empty when the call succeeded. */
    public Optional<Failure.Reason> reason() {
        return failure().map(Failure::reason);
    }

    /**
     * The value mapped, when there is one. A success without a value stays one, and a failure stays
     * the same failure.
     */
    public <U> Result<U> map(Function<? super T, ? extends U> mapper) {
        Objects.requireNonNull(mapper, "mapper must not be null");
        if (!isOk()) return failed(failure);
        return ok(value == null ? null : mapper.apply(value));
    }

    /**
     * The result that the value maps to, when there is one. A success without a value stays one,
     * and a failure stays the same failure.
     */
    public <U> Result<U> flatMap(Function<? super T, Result<U>> mapper) {
        Objects.requireNonNull(mapper, "mapper must not be null");
        if (!isOk()) return failed(failure);
        if (value == null) return ok(null);
        return Objects.requireNonNull(mapper.apply(value), "the mapper's result must not be null");
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Result<?> other
                && Objects.equals(value, other.value) && Objects.equals(failure, other.failure);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value, failure);
    }

    /** Names the failure, or that the call succeeded, but not the value, which can be a secret. */
    @Override
    public String toString() {
        return isOk() ? "Result[ok]" : "Result[" + failure + "]";
    }
}

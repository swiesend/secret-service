package de.swiesend.secretservice.hardened.providers;

import de.swiesend.secretservice.hardened.KeyMaterialProvider;
import de.swiesend.secretservice.hardened.ThreatCoverage;

import java.util.Objects;
import java.util.Optional;

/**
 * Decorator that forces {@link Mode#NO_TOTP} on another provider. Use in CI or contexts
 * where a TOTP seed is genuinely unavailable; makes the intent explicit and greppable.
 */
public final class NoTotpKeyMaterialProvider implements KeyMaterialProvider {

    private final KeyMaterialProvider delegate;

    public NoTotpKeyMaterialProvider(KeyMaterialProvider delegate) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
    }

    @Override public char[] getPepper() { return delegate.getPepper(); }

    @Override public Optional<byte[]> getTotpSeed() { return Optional.empty(); }

    @Override public Mode mode() { return Mode.NO_TOTP; }

    @Override public ThreatCoverage threatCoverage() { return delegate.threatCoverage(); }
}

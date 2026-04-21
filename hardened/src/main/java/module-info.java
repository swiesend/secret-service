/**
 * Opt-in application-layer encryption wrapper around
 * {@code de.swiesend.secretservice}.
 *
 * <p>Uses the standard {@code javax.crypto.KEM} API (JEP 452, JDK 21+).
 * BouncyCastle is required only on JDK 21-23 for ML-KEM-768; it is declared
 * {@code requires static} so the module loads when the dep is absent
 * (post-quantum then degrades to X25519-only).</p>
 */
module de.swiesend.secretservice.hardened {
    requires transitive de.swiesend.secretservice;
    requires at.favre.lib.hkdf;
    requires org.slf4j;
    requires static org.bouncycastle.provider;

    exports de.swiesend.secretservice.hardened;
    exports de.swiesend.secretservice.hardened.providers;
}

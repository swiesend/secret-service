/**
 * Opt-in application-layer encryption wrapper around
 * {@code de.swiesend.secretservice}.
 *
 * <p>Targets JDK 25. Post-quantum ML-KEM-768 uses the stock SunJCE provider via the standard
 * {@code javax.crypto.KEM} API (JEP 496), so no third-party crypto provider is needed for the KEM.
 * BouncyCastle is required only by the optional {@code Argon2KeyMaterialProvider} (Argon2id has no
 * JDK-native implementation); it is declared {@code requires static} so the module loads when the
 * dependency is absent -- only code paths that use Argon2 need it on the classpath.</p>
 */
module de.swiesend.secretservice.hardened {
    requires transitive de.swiesend.secretservice;
    requires org.slf4j;
    requires static org.bouncycastle.provider;  // optional: Argon2KeyMaterialProvider only
    requires java.management;   // ManagementFactory in HardenedHealthCheck

    exports de.swiesend.secretservice.hardened;
    exports de.swiesend.secretservice.hardened.providers;
}

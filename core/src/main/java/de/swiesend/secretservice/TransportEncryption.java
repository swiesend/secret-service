package de.swiesend.secretservice;

import at.favre.lib.hkdf.HKDF;
import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
import org.freedesktop.dbus.connections.impl.DBusConnectionBuilder;
import org.freedesktop.dbus.exceptions.DBusException;
import org.freedesktop.dbus.types.Variant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Optional;

public class TransportEncryption implements AutoCloseable {

    public static final int PRIVATE_VALUE_BITS = 1024;
    public static final int AES_BITS = 128;
    private static final Logger log = LoggerFactory.getLogger(TransportEncryption.class);
    private de.swiesend.secretservice.Service service;
    private DHParameterSpec dhParameters = null;
    private KeyPair keypair = null;
    private PublicKey publicKey = null;
    private PrivateKey privateKey = null;
    private SessionKey sessionKey = null;
    private byte[] yb = null;

    private Session session = null;

    public TransportEncryption() throws DBusException {
        DBusConnection connection = DBusConnectionBuilder.forSessionBus().withShared(false).build();
        this.service = new Service(connection);
    }

    public TransportEncryption(DBusConnection connection) {
        this.service = new Service(connection);
    }

    public TransportEncryption(de.swiesend.secretservice.Service service) {
        this.service = service;
    }

    static private BigInteger fromBinary(byte[] bytes) {
        return new BigInteger(1, bytes);
    }

    static private int toBytes(int bits) {
        return bits / 8;
    }

    public Optional<InitializedSession> initialize() {

        try {
            // create dh parameter specification with prime, generator and bits
            BigInteger prime = fromBinary(Static.RFC_2409.SecondOakleyGroup.PRIME);
            BigInteger generator = fromBinary(Static.RFC_2409.SecondOakleyGroup.GENERATOR);
            dhParameters = new DHParameterSpec(prime, generator, PRIVATE_VALUE_BITS);

            // generate DH keys from specification
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(Static.Algorithm.DIFFIE_HELLMAN);
            keyPairGenerator.initialize(dhParameters);
            keypair = keyPairGenerator.generateKeyPair();
            publicKey = keypair.getPublic();
            privateKey = keypair.getPrivate();

            return Optional.of(new InitializedSession());
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            log.error("The secret service could not be initialized as the service does not provide the expected transport encryption algorithm.", e);
            return Optional.empty();
        }
    }

    public Service getService() {
        return service;
    }

    public Session getSession() {
        return session;
    }

    /**
     * Erases the session key and drops the DH private key. Encryption and decryption through this
     * session fail afterwards.
     */
    public void clear() {
        // The JDK cannot erase a DH private key: destroy() throws DestroyFailedException, and the
        // exponent is an immutable BigInteger. Clearing a copy from getEncoded() would change
        // nothing, so dropping the references is all there is to do.
        privateKey = null;
        keypair = null;
        if (sessionKey != null) {
            sessionKey.destroy();
            sessionKey = null;
        }
    }

    /**
     * The AES session key, as a key that can really be erased. A {@code SecretKeySpec} cannot:
     * its {@code destroy()} throws {@code DestroyFailedException}, and its {@code getEncoded()}
     * returns a copy, so nothing reaches the bytes it holds.
     */
    static final class SessionKey implements SecretKey {
        @java.io.Serial
        private static final long serialVersionUID = 1L;
        private final byte[] key;
        private volatile boolean destroyed = false;

        SessionKey(byte[] key) {
            this.key = key.clone();
        }

        @Override
        public String getAlgorithm() {
            return Static.Algorithm.AES;
        }

        @Override
        public String getFormat() {
            return "RAW";
        }

        // Both synchronized: a copy taken while destroy() runs would be partly zeroed, and a secret
        // encrypted under it could be read by anyone on the bus. Now a copy is whole or refused.
        @Override
        public synchronized byte[] getEncoded() {
            if (destroyed) throw new IllegalStateException("The session key has been destroyed.");
            return key.clone();
        }

        @Override
        public synchronized void destroy() {
            Arrays.fill(key, (byte) 0);
            destroyed = true;
        }

        @Override
        public boolean isDestroyed() {
            return destroyed;
        }
    }

    @Override
    public void close() {
        clear();
        if (session != null) session.close();
    }

    public class InitializedSession {

        public Optional<OpenedSession> openSession() {
            if (keypair == null) {
                throw new IllegalStateException("Missing own keypair. Call TransportEncryption.initialize() first.");
            }
            // The public keys are transferred as an array of bytes representing an unsigned integer of arbitrary size,
            // most-significant byte first (e.g., the integer 32768 is represented as the 2-byte string 0x80 0x00)
            BigInteger ya = ((DHPublicKey) publicKey).getY();

            // open session with "Client DH pub key as an array of bytes" without prime or generator
            return service.openSession(
                    Static.Algorithm.DH_IETF1024_SHA256_AES128_CBC_PKCS7,
                    new Variant<>(ya.toByteArray())
            ).flatMap(pair -> {
                // transform peer's raw Y to a public key
                yb = Static.Utils.toByteArray(pair.a.getValue());

                DBusPath sessionPath = pair.b;
                session = new Session(sessionPath, service);
                return Optional.of(new OpenedSession());
            });
        }
    }

    public class OpenedSession {
        public Optional<EncryptedSession> generateSessionKey() {
            if (yb == null) {
                throw new IllegalStateException("Missing peer public key. Call Initialized.openSession() first.");
            }
            byte[] rawSessionKey = null;
            byte[] pseudoRandomKey = null;
            byte[] keyingMaterial = null;
            try {
                DHPublicKeySpec dhPublicKeySpec = new DHPublicKeySpec(fromBinary(yb), dhParameters.getP(), dhParameters.getG());
                KeyFactory keyFactory = KeyFactory.getInstance(Static.Algorithm.DIFFIE_HELLMAN);
                DHPublicKey peerPublicKey = (DHPublicKey) keyFactory.generatePublic(dhPublicKeySpec);

                KeyAgreement keyAgreement = KeyAgreement.getInstance(Static.Algorithm.DIFFIE_HELLMAN);
                keyAgreement.init(privateKey);
                keyAgreement.doPhase(peerPublicKey, true);
                rawSessionKey = keyAgreement.generateSecret();

                // HKDF digest into a 128-bit key by extract and expand with "NULL salt and empty info"
                // see: https://standards.freedesktop.org/secret-service/0.2/ch07s03.html
                pseudoRandomKey = HKDF.fromHmacSha256().extract((byte[]) null, rawSessionKey);
                keyingMaterial = HKDF.fromHmacSha256().expand(pseudoRandomKey, null, toBytes(AES_BITS));

                // A second call would otherwise leave the previous key's bytes behind.
                if (sessionKey != null) sessionKey.destroy();
                sessionKey = new SessionKey(keyingMaterial);
                return Optional.of(new EncryptedSession());
            } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException e) {
                log.error("Could not generate a new session key for the current session", e);
                return Optional.empty();
            } finally {
                // The DH shared secret and both HKDF stages are key material. SessionKey holds its
                // own copy, so all three can go as soon as it exists.
                if (rawSessionKey != null) Secret.clear(rawSessionKey);
                if (pseudoRandomKey != null) Secret.clear(pseudoRandomKey);
                if (keyingMaterial != null) Secret.clear(keyingMaterial);
            }
        }

    }

    public class EncryptedSession {

        public Session getSession() {
            return session;
        }

        /** Erases the session key and closes the D-Bus session; see {@link TransportEncryption#close()}. */
        public void close() {
            TransportEncryption.this.close();
        }

        /**
         * Encrypt a CharSequence. The byte representation is cleared after encryption.
         * Note: the CharSequence parameter itself cannot be reliably cleared since it may be
         * an immutable String. Callers handling sensitive data should prefer the byte[]-based
         * overload or use the withSecret() callback API which manages cleanup automatically.
         */
        public Optional<Secret> encrypt(CharSequence plain) {
            final byte[] bytes = Secret.toBytes(plain);
            Optional<Secret> secret = encrypt(bytes, StandardCharsets.UTF_8);
            Secret.clear(bytes);
            return secret;
        }

        public Optional<Secret> encrypt(byte[] plain, Charset charset) {

            if (Static.Utils.isNullOrEmpty(plain)) return Optional.empty();

            try {
                if (service == null) {
                    log.error("Missing session. Call Initialized.openSession() first.");
                    return Optional.empty();
                }
                // Read once: clear() can drop the key while this runs.
                final SessionKey key = sessionKey;
                if (key == null) {
                    log.error("Missing session key. Call Opened.generateSessionKey() first.");
                    return Optional.empty();
                }

                // secret.parameter - 16 byte AES initialization vector
                final byte[] salt = new byte[toBytes(AES_BITS)];
                SecureRandom random = SecureRandom.getInstance(Static.Algorithm.SHA1_PRNG);
                random.nextBytes(salt);
                IvParameterSpec ivSpec = new IvParameterSpec(salt);

                Cipher cipher = Cipher.getInstance(Static.Algorithm.AES_CBC_PKCS5);
                cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

                String contentType = Secret.createContentType(charset);

                return Optional.of(new Secret(session.getPath(), ivSpec.getIV(), cipher.doFinal(plain), contentType));
            } catch (InvalidAlgorithmParameterException |
                     InvalidKeyException |
                     NoSuchPaddingException |
                     BadPaddingException |
                     IllegalBlockSizeException |
                     NoSuchAlgorithmException e) {
                log.error("Could not encrypt the secret", e);
            } catch (IllegalStateException e) {
                // The key was destroyed after it was read above: the session closed meanwhile.
                log.error("The session was closed while a secret was being encrypted.");
            } finally {
                Secret.clear(plain);
            }
            return Optional.empty();
        }

        public Optional<char[]> decrypt(Secret secret) {

            if (secret == null) return Optional.empty();

            // Read once: clear() can drop the key while this runs.
            final SessionKey key = sessionKey;
            if (key == null) {
                log.error("Missing session key. Call Opened.generateSessionKey() first.");
                return Optional.empty();
            }
            byte[] decrypted = new byte[0];
            try {
                IvParameterSpec ivSpec = new IvParameterSpec(secret.getSecretParameters());
                Cipher cipher = Cipher.getInstance(Static.Algorithm.AES_CBC_PKCS5);
                cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
                decrypted = cipher.doFinal(secret.getSecretValue());
                return Optional.of(Secret.toChars(decrypted));
            } catch (InvalidAlgorithmParameterException |
                     InvalidKeyException |
                     NoSuchPaddingException |
                     BadPaddingException |
                     IllegalBlockSizeException |
                     NoSuchAlgorithmException e) {
                log.error("Could not decrypt the secret", e);
                return Optional.empty();
            } catch (IllegalStateException e) {
                // The key was destroyed after it was read above: the session closed meanwhile.
                log.error("The session was closed while a secret was being decrypted.");
                return Optional.empty();
            } finally {
                Secret.clear(decrypted);
            }
        }
    }
}

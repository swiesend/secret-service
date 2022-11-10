package de.swiesend.secretservice;

import at.favre.lib.hkdf.HKDF;
import org.freedesktop.dbus.ObjectPath;
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
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Optional;

public class TransportEncryption implements AutoCloseable {

    public static final int PRIVATE_VALUE_BITS = 1024;
    public static final int AES_BITS = 128;
    private static final Logger log = LoggerFactory.getLogger(TransportEncryption.class);
    private de.swiesend.secretservice.Service service; // TODO: should adhere to the interface
    private DHParameterSpec dhParameters = null;
    private KeyPair keypair = null;
    private PublicKey publicKey = null;
    private PrivateKey privateKey = null;
    private SecretKey sessionKey = null;
    private byte[] yb = null;

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

    public void clear() {
        if (privateKey != null) try {
            privateKey.destroy();
        } catch (DestroyFailedException e) {
            Secret.clear(privateKey.getEncoded());
        }
        if (sessionKey != null) try {
            sessionKey.destroy();
        } catch (DestroyFailedException e) {
            Secret.clear(sessionKey.getEncoded());
        }
    }

    @Override
    public void close() {
        clear();
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
                    new Variant(ya.toByteArray())
            ).flatMap(pair -> {
                // transform peer's raw Y to a public key
                yb = pair.a.getValue();
                return Optional.of(new OpenedSession());
            });
        }
    }

    public class OpenedSession {
        public Optional<EncryptedSession> generateSessionKey() {
            if (yb == null) {
                throw new IllegalStateException("Missing peer public key. Call Initialized.openSession() first.");
            }
            try {
                DHPublicKeySpec dhPublicKeySpec = new DHPublicKeySpec(fromBinary(yb), dhParameters.getP(), dhParameters.getG());
                KeyFactory keyFactory = KeyFactory.getInstance(Static.Algorithm.DIFFIE_HELLMAN);
                DHPublicKey peerPublicKey = (DHPublicKey) keyFactory.generatePublic(dhPublicKeySpec);

                KeyAgreement keyAgreement = KeyAgreement.getInstance(Static.Algorithm.DIFFIE_HELLMAN);
                keyAgreement.init(privateKey);
                keyAgreement.doPhase(peerPublicKey, true);
                byte[] rawSessionKey = keyAgreement.generateSecret();

                // HKDF digest into a 128-bit key by extract and expand with "NULL salt and empty info"
                // see: https://standards.freedesktop.org/secret-service/0.2/ch07s03.html
                byte[] pseudoRandomKey = HKDF.fromHmacSha256().extract((byte[]) null, rawSessionKey);
                byte[] keyingMaterial = HKDF.fromHmacSha256().expand(pseudoRandomKey, null, toBytes(AES_BITS));

                sessionKey = new SecretKeySpec(keyingMaterial, Static.Algorithm.AES);

                if (sessionKey != null) {
                    return Optional.of(new EncryptedSession());
                } else {
                    return Optional.empty();
                }
            } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException e) {
                log.error("Could not generate a new session key for the current session", e);
                return Optional.empty();
            }
        }

    }

    public class EncryptedSession {
        public Secret encrypt(CharSequence plain) throws NoSuchAlgorithmException, NoSuchPaddingException,
                InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

            final byte[] bytes = Secret.toBytes(plain);
            try {
                return encrypt(bytes, StandardCharsets.UTF_8);
            } finally {
                Secret.clear(bytes);
            }
        }

        public Secret encrypt(byte[] plain, Charset charset) throws NoSuchAlgorithmException, NoSuchPaddingException,
                InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

            if (plain == null) return null;

            if (service == null) {
                throw new IllegalStateException("Missing session. Call Initialized.openSession() first.");
            }
            if (sessionKey == null) {
                throw new IllegalStateException("Missing session key. Call Opened.generateSessionKey() first.");
            }

            // secret.parameter - 16 byte AES initialization vector
            final byte[] salt = new byte[toBytes(AES_BITS)];
            SecureRandom random = SecureRandom.getInstance(Static.Algorithm.SHA1_PRNG);
            random.nextBytes(salt);
            IvParameterSpec ivSpec = new IvParameterSpec(salt);

            Cipher cipher = Cipher.getInstance(Static.Algorithm.AES_CBC_PKCS5);
            cipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivSpec);

            String contentType = Secret.createContentType(charset);

            return new Secret(service.getSession().getPath(), ivSpec.getIV(), cipher.doFinal(plain), contentType);
        }

        public char[] decrypt(Secret secret) throws NoSuchPaddingException,
                NoSuchAlgorithmException,
                InvalidAlgorithmParameterException,
                InvalidKeyException,
                BadPaddingException,
                IllegalBlockSizeException {

            if (secret == null) return null;

            if (sessionKey == null) {
                throw new IllegalStateException("Missing session key. Call Opened.generateSessionKey() first.");
            }

            IvParameterSpec ivSpec = new IvParameterSpec(secret.getSecretParameters());
            Cipher cipher = Cipher.getInstance(Static.Algorithm.AES_CBC_PKCS5);
            cipher.init(Cipher.DECRYPT_MODE, sessionKey, ivSpec);
            final byte[] decrypted = cipher.doFinal(secret.getSecretValue());
            try {
                return Secret.toChars(decrypted);
            } finally {
                Secret.clear(decrypted);
            }
        }
    }
}

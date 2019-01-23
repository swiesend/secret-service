package org.freedesktop.Secret;

import at.favre.lib.crypto.HKDF;
import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.connections.impl.DBusConnection;
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
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

public class TransportEncryption {

    Logger log = LoggerFactory.getLogger(getClass());

    private Service service = null;

    private DHParameterSpec dhParameters = null;
    private KeyPair keypair = null;
    private PublicKey publicKey = null;
    private PrivateKey privateKey = null;
    private DHPublicKey peerPublicKey = null;
    private SecretKey sessionKey = null;

    private BigInteger ya = null;
    private BigInteger yb = null;

    public static final int PRIVATE_VALUE_BITS = 1024;
    public static final int AES_BITS = 128;
    private int HEX = 16;


    public TransportEncryption() {
        // open connection to DBus
        DBusConnection connection = null;
        try {
            connection = DBusConnection.getConnection(DBusConnection.DBusBusType.SESSION);
        } catch (DBusException e) {
            log.error(e.toString(), e.getCause());
        }
        this.service = new Service(connection);
    }

    public TransportEncryption(Service service) {
        this.service = service;
    }

    static private BigInteger fromBinary(byte[] bytes) {
        return new BigInteger(1, bytes);
    }

    static private int toBytes(int bits) {
        return bits / 8;
    }

    public void initialize() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {

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
    }

    public void openSession() {
        if (keypair == null) {
            throw new IllegalStateException("Missing own keypair. Call initialize() first.");
        }

        // The public keys are transferred as an array of bytes representing an unsigned integer of arbitrary size,
        // most-significant byte first (e.g., the integer 32768 is represented as the 2-byte string 0x80 0x00)
        ya = ((DHPublicKey) publicKey).getY();

        // open session with "Client DH pub key as an array of bytes" without prime or generator
        Pair<Variant<byte[]>, ObjectPath> osResponse = service.openSession(
                Static.Algorithm.DH_IETF_1024_SHA_256_AES_128_CBC_PKCS_7, new Variant(ya.toByteArray()));

        // transform peer's raw Y to a public key
        byte[] result = osResponse.a.getValue();
        yb = fromBinary(result);

        ObjectPath session = osResponse.b;
        log.info("opened session: " + session.getPath());

        log.info("bits: " + ya.bitLength() + ",         public-key (ya): " + ya.toString(HEX));
        log.info("bits: " + yb.bitLength() + ",         public-key (yb): " + yb.toString(HEX));
        log.info("bits: " + dhParameters.getP().bitLength() + ",               prime (p): " + dhParameters.getP().toString(HEX));
        log.info("bits: " + dhParameters.getP().bitLength() + ",           generator (g): " + dhParameters.getG().toString(HEX));
    }

    public void generateSessionKey() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {

        if (yb == null) {
            throw new IllegalStateException("Missing peer public key. Call openSession() first.");
        }

        DHPublicKeySpec dhPublicKeySpec = new DHPublicKeySpec(yb, dhParameters.getP(), dhParameters.getG());
        KeyFactory keyFactory = KeyFactory.getInstance(Static.Algorithm.DIFFIE_HELLMAN);
        peerPublicKey = (DHPublicKey) keyFactory.generatePublic(dhPublicKeySpec);

        KeyAgreement keyAgreement = KeyAgreement.getInstance(Static.Algorithm.DIFFIE_HELLMAN);
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(peerPublicKey, true);
        byte[] rawSessionKey = keyAgreement.generateSecret();
        BigInteger zz = fromBinary(rawSessionKey);
        log.info("bits: " + zz.bitLength() + ",    raw session-key (zz): " + zz.toString(HEX));

        // HKDF digest into a 128-bit key by extract and expand with "NULL salt and empty info"
        // see: https://standards.freedesktop.org/secret-service/ch07s03.html
        byte[] pseudoRandomKey = HKDF.fromHmacSha256().extract(null, rawSessionKey);
        byte[] keyingMaterial = HKDF.fromHmacSha256().expand(pseudoRandomKey, null, toBytes(AES_BITS));

        sessionKey = new SecretKeySpec(keyingMaterial, Static.Algorithm.AES);

        BigInteger X = fromBinary(sessionKey.getEncoded());
        log.info("bits: " + X.bitLength() + ", digested session-key (x): " + X.toString(HEX));
    }


    public Secret encrypt(String plain) throws NoSuchAlgorithmException,
            NoSuchPaddingException,
            InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        return encrypt(plain, StandardCharsets.UTF_8);
    }

    public Secret encrypt(String plain, Charset charset) throws NoSuchAlgorithmException,
            NoSuchPaddingException,
            InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        if (service == null) {
            throw new IllegalStateException("Missing session. Call openSession() first.");
        }
        if (sessionKey == null) {
            throw new IllegalStateException("Missing session key. Call generateSessionKey() first.");
        }

        // secret.parameter - 16 byte AES initialization vector
        byte[] salt = new byte[toBytes(AES_BITS)];
        SecureRandom random = SecureRandom.getInstance(Static.Algorithm.SHA1_PRNG);
        random.nextBytes(salt);
        IvParameterSpec ivSpec = new IvParameterSpec(salt);

        Cipher cipher = Cipher.getInstance(Static.Algorithm.AES_CBC_PKCS5);
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivSpec);
        byte[] encrypted = cipher.doFinal(plain.getBytes());

        String contentType = Secret.createContentType(charset);

        return new Secret(service.getSession().getPath(), ivSpec.getIV(), encrypted, contentType);
    }

    public String decrypt(Secret secret) throws NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidAlgorithmParameterException,
            InvalidKeyException,
            BadPaddingException,
            IllegalBlockSizeException {

        if (sessionKey == null) {
            throw new IllegalStateException("Missing session key. Call generateSessionKey() first.");
        }

        IvParameterSpec ivSpec = new IvParameterSpec(secret.getSecretParameters());
        byte[] encrypted = secret.getSecretValue();

        Cipher cipher = Cipher.getInstance(Static.Algorithm.AES_CBC_PKCS5);
        cipher.init(Cipher.DECRYPT_MODE, sessionKey, ivSpec);
        byte[] decrypted = cipher.doFinal(encrypted);

        return new String(decrypted);
    }

    public Service getService() {
        return service;
    }
}

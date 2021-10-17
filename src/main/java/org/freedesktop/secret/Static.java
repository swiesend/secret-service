package org.freedesktop.secret;

import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.ObjectPath;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

public class Static {

    public static final Duration DEFAULT_PROMPT_TIMEOUT = Duration.ofSeconds(120);

    public static boolean isNullOrEmpty(final CharSequence cs) {
        return cs == null || cs.toString().trim().isEmpty();
    }

    public static boolean isNullOrEmpty(final String s) {
        return s == null || s.trim().isEmpty();
    }

    public static class DBus {

        public static final Long DEFAULT_DELAY_MILLIS = 100L;
        public static final Long MAX_DELAY_MILLIS = 2000L;

        public static class Service {
            public static final String DBUS = "org.freedesktop.DBus";
        }

        public static class ObjectPaths {
            public static final String DBUS = "/org/freedesktop/DBus";
        }

        public static class Interfaces {
            public static final String DBUS = "org.freedesktop.DBus";
            public static final String DBUS_PROPERTIES = "org.freedesktop.DBus.Properties";
        }
    }

    public static class Service {
        public static final String SECRETS = "org.freedesktop.secrets";
    }

    public static class ObjectPaths {

        /**
         * The object path for the service.
         */
        public static final String SECRETS = "/org/freedesktop/secrets";
        public static final String SESSION = "/org/freedesktop/secrets/session";

        public static final String ALIASES = "/org/freedesktop/secrets/aliases";
        public static final String DEFAULT_COLLECTION = "/org/freedesktop/secrets/aliases/default";

        public static final String COLLECTION = "/org/freedesktop/secrets/collection";
        public static final String SESSION_COLLECTION = "/org/freedesktop/secrets/collection/session";
        public static final String LOGIN_COLLECTION = "/org/freedesktop/secrets/collection/login";

        public static final String PROMPT = "/org/freedesktop/secrets/prompt";

        /**
         * The object path for a collection, where xxxx represents a possibly encoded or truncated version of the
         * initial label of the collection.
         *
         * @param name the encoded name of the collection
         * @return path of the collection
         *
         * <code>
         * /org/freedesktop/secrets/collection/xxxx
         * </code>
         */
        public static String collection(String name) {
            return COLLECTION + "/" + name;
        }

        /**
         * The object path for an item, where xxxx is the collection (above) and iiii is an auto-generated item
         * specific identifier.
         *
         * @param collection the encoded name of the collection
         * @param item_id    the encoded name of the item
         * @return path of the item
         *
         * <code>
         * /org/freedesktop/secrets/collection/xxxx/iiii
         * </code>
         */
        public static String item(String collection, String item_id) {
            return COLLECTION + "/" + collection + "/" + item_id;
        }

        /**
         * The object path for a session, where ssss is an auto-generated session specific identifier.
         *
         * @param session_id the current id of the session
         * @return path of the session
         *
         * <code>
         * /org/freedesktop/secrets/session/ssss
         * </code>
         */
        public static String session(String session_id) {
            return SESSION + "/" + session_id;
        }

        /**
         * The object path for a prompt, where pppp is the window_id.
         *
         * @param window_id id of the current prompt's window
         * @return path of the prompt
         *
         * <code>
         * /org/freedesktop/secrets/prompt/pppp
         * </code>
         */
        public static String prompt(String window_id) {
            return PROMPT + "/" + window_id;
        }

    }

    public static class Interfaces {

        /**
         * The Secret Service manages all the sessions and collections.
         */
        public static final String SERVICE = "org.freedesktop.Secret.Service";

        /**
         * A collection of items containing secrets.
         */
        public static final String COLLECTION = "org.freedesktop.Secret.Collection";

        /**
         * An item contains a secret, lookup attributes and has a label.
         */
        public static final String ITEM = "org.freedesktop.Secret.Item";

        /**
         * A session tracks state between the service and a client application.
         */
        public static final String SESSION = "org.freedesktop.Secret.Session";

        /**
         * A prompt necessary to complete an operation.
         */
        public static final String PROMPT = "org.freedesktop.Secret.Prompt";

    }

    public static class Algorithm {
        public static final String PLAIN = "plain";
        public static final String DH_IETF1024_SHA256_AES128_CBC_PKCS7 = "dh-ietf1024-sha256-aes128-cbc-pkcs7";
        public static final String DIFFIE_HELLMAN = "DH";
        public static final String AES = "AES";
        public static final String AES_CBC_PKCS5 = "AES/CBC/PKCS5Padding";
        public static final String SHA1_PRNG = "SHA1PRNG";
    }

    public static class Secret {
        public static final String GENERIC_TYPE = "org.freedesktop.Secret.Generic";
    }

    public static class Convert {

        public static byte[] toByteArray(List<Byte> list) {
            byte[] result = new byte[list.size()];
            for (int i = 0; i < list.size(); i++) {
                result[i] = list.get(i).byteValue();
            }
            return result;
        }

        public static String toString(byte[] bytes) {
            return new String(bytes, StandardCharsets.UTF_8);
        }

        public static ObjectPath toObjectPath(String path) {
            return new ObjectPath("", path);
        }

        public static List<String> toStrings(List<ObjectPath> paths) {
            ArrayList<String> ps = new ArrayList();
            for (ObjectPath p : paths) {
                ps.add(p.getPath());
            }
            return ps;
        }

        public static List<DBusPath> toDBusPaths(List<ObjectPath> paths) {
            ArrayList<DBusPath> ps = new ArrayList();
            for (ObjectPath p : paths) {
                ps.add(p);
            }
            return ps;
        }

    }

    /**
     * RFC 2409: https://tools.ietf.org/html/rfc2409
     */
    public static class RFC_2409 {

        /**
         * RFC 2409: https://tools.ietf.org/html/rfc2409#section-6.2
         */
        public static class SecondOakleyGroup {

            public static final byte[] PRIME = new byte[]{
                    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xC9, (byte) 0x0F, (byte) 0xDA, (byte) 0xA2, (byte) 0x21, (byte) 0x68, (byte) 0xC2, (byte) 0x34,
                    (byte) 0xC4, (byte) 0xC6, (byte) 0x62, (byte) 0x8B, (byte) 0x80, (byte) 0xDC, (byte) 0x1C, (byte) 0xD1,
                    (byte) 0x29, (byte) 0x02, (byte) 0x4E, (byte) 0x08, (byte) 0x8A, (byte) 0x67, (byte) 0xCC, (byte) 0x74,
                    (byte) 0x02, (byte) 0x0B, (byte) 0xBE, (byte) 0xA6, (byte) 0x3B, (byte) 0x13, (byte) 0x9B, (byte) 0x22,
                    (byte) 0x51, (byte) 0x4A, (byte) 0x08, (byte) 0x79, (byte) 0x8E, (byte) 0x34, (byte) 0x04, (byte) 0xDD,
                    (byte) 0xEF, (byte) 0x95, (byte) 0x19, (byte) 0xB3, (byte) 0xCD, (byte) 0x3A, (byte) 0x43, (byte) 0x1B,
                    (byte) 0x30, (byte) 0x2B, (byte) 0x0A, (byte) 0x6D, (byte) 0xF2, (byte) 0x5F, (byte) 0x14, (byte) 0x37,
                    (byte) 0x4F, (byte) 0xE1, (byte) 0x35, (byte) 0x6D, (byte) 0x6D, (byte) 0x51, (byte) 0xC2, (byte) 0x45,
                    (byte) 0xE4, (byte) 0x85, (byte) 0xB5, (byte) 0x76, (byte) 0x62, (byte) 0x5E, (byte) 0x7E, (byte) 0xC6,
                    (byte) 0xF4, (byte) 0x4C, (byte) 0x42, (byte) 0xE9, (byte) 0xA6, (byte) 0x37, (byte) 0xED, (byte) 0x6B,
                    (byte) 0x0B, (byte) 0xFF, (byte) 0x5C, (byte) 0xB6, (byte) 0xF4, (byte) 0x06, (byte) 0xB7, (byte) 0xED,
                    (byte) 0xEE, (byte) 0x38, (byte) 0x6B, (byte) 0xFB, (byte) 0x5A, (byte) 0x89, (byte) 0x9F, (byte) 0xA5,
                    (byte) 0xAE, (byte) 0x9F, (byte) 0x24, (byte) 0x11, (byte) 0x7C, (byte) 0x4B, (byte) 0x1F, (byte) 0xE6,
                    (byte) 0x49, (byte) 0x28, (byte) 0x66, (byte) 0x51, (byte) 0xEC, (byte) 0xE6, (byte) 0x53, (byte) 0x81,
                    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            };

            public static final byte[] GENERATOR = new byte[]{(byte) 0x02};

        }

    }

}

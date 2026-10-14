package de.swiesend.secretservice;

import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.Struct;
import org.freedesktop.dbus.annotations.Position;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;

public final class Secret extends Struct implements AutoCloseable {

    // NOTE: the specification defines the default content_type differently with "text/plain; charset=utf8"
    //  see: https://specifications.freedesktop.org/secret-service/0.2/types.html
    public static final String TEXT_PLAIN_CHARSET_UTF_8 = "text/plain; charset=utf-8";
    public static final String TEXT_PLAIN = "text/plain";
    private static final String CHARSET = "charset=";
    @Position(0)
    private final DBusPath session;
    @Position(1)
    private final byte[] parameters;
    @Position(2)
    private final byte[] value;
    @Position(3)
    private final String contentType;
    private String mimeType = null;
    private Charset charset = null;


    public Secret(DBusPath session, byte[] value) {
        this.session = session;
        this.parameters = "".getBytes();
        this.value = value;
        this.contentType = TEXT_PLAIN_CHARSET_UTF_8;
        this.mimeType = TEXT_PLAIN;
        this.charset = StandardCharsets.UTF_8;
    }

    public Secret(DBusPath session, byte[] parameters, byte[] value) {
        this.session = session;
        if (parameters == null) {
            this.parameters = "".getBytes();
        } else {
            this.parameters = parameters;
        }
        this.value = value;
        this.contentType = TEXT_PLAIN_CHARSET_UTF_8;
        this.mimeType = TEXT_PLAIN;
        this.charset = StandardCharsets.UTF_8;
    }

    public Secret(DBusPath session, byte[] parameters, byte[] value, String contentType) {
        this.session = requireNonNull(session);
        if (parameters == null) {
            this.parameters = "".getBytes();
        } else {
            this.parameters = parameters;
        }
        this.value = requireNonNull(value);
        if (contentType == null || contentType.isEmpty()) {
            this.contentType = TEXT_PLAIN_CHARSET_UTF_8;
            this.mimeType = TEXT_PLAIN;
            this.charset = StandardCharsets.UTF_8;
        } else {
            parseContentType(contentType);
            if (charset == null) {
                this.contentType = mimeType;
            } else {
                this.contentType = createContentType(mimeType, charset);
            }
        }
    }

    public Secret(DBusPath session, byte[] parameters, byte[] value, Charset charset) {
        this.session = requireNonNull(session);
        if (parameters == null) {
            this.parameters = "".getBytes();
        } else {
            this.parameters = parameters;
        }
        this.value = requireNonNull(value);
        this.contentType = createContentType(charset);
        parseContentType(this.contentType);
    }

    static public String createContentType(String mimeType, Charset charset) {
        return mimeType + "; " + CHARSET + charset.name().toLowerCase();
    }

    static public String createContentType(Charset charset) {
        return TEXT_PLAIN + "; " + CHARSET + charset.name().toLowerCase();
    }

    static public byte[] toBytes(CharSequence passphrase) {
        return toUtf8(CharBuffer.wrap(passphrase));
    }

    static public byte[] toBytes(char[] passphrase) {
        return toUtf8(CharBuffer.wrap(passphrase));
    }

    /**
     * Encodes into one buffer sized for the worst case, so the encoder never outgrows it.
     * {@code Charset.encode} starts at 1.1 bytes per char, and when that is too small it copies
     * into a larger buffer and drops the old one without erasing it: for a secret that is not
     * plain ASCII, a partial copy of it stayed on the heap.
     */
    private static byte[] toUtf8(CharBuffer chars) {
        // The same replacement for unpaired surrogates as Charset.encode.
        CharsetEncoder encoder = StandardCharsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPLACE)
                .onUnmappableCharacter(CodingErrorAction.REPLACE);
        final ByteBuffer encoded = ByteBuffer.allocate(
                Math.toIntExact((long) Math.ceil(chars.remaining() * (double) encoder.maxBytesPerChar())));
        try {
            CoderResult result = encoder.encode(chars, encoded, true);
            if (result.isUnderflow()) result = encoder.flush(encoded);
            if (!result.isUnderflow()) {
                throw new IllegalStateException("The UTF-8 encoder outgrew its worst-case buffer: " + result);
            }
            encoded.flip();
            final byte[] bytes = new byte[encoded.remaining()];
            encoded.get(bytes);
            return bytes;
        } finally {
            clear(encoded);
        }
    }

    static public char[] toChars(byte[] bytes) {
        return toChars(bytes, StandardCharsets.UTF_8);
    }

    /**
     * Decodes {@code bytes} in {@code charset}, or in UTF-8, the specification's default, when it
     * is null, and erases {@code bytes}. Into one buffer sized for the worst case: a decoder that
     * outgrows its first buffer copies into a larger one and drops the first without erasing it.
     */
    static public char[] toChars(byte[] bytes, Charset charset) {
        // The same replacement for malformed input as Charset.decode.
        CharsetDecoder decoder = (charset == null ? StandardCharsets.UTF_8 : charset).newDecoder()
                .onMalformedInput(CodingErrorAction.REPLACE)
                .onUnmappableCharacter(CodingErrorAction.REPLACE);
        ByteBuffer encoded = ByteBuffer.wrap(bytes);
        final CharBuffer decoded = CharBuffer.allocate(
                Math.toIntExact((long) Math.ceil(bytes.length * (double) decoder.maxCharsPerByte())));
        try {
            CoderResult result = decoder.decode(encoded, decoded, true);
            if (result.isUnderflow()) result = decoder.flush(decoded);
            if (!result.isUnderflow()) {
                throw new IllegalStateException("The " + decoder.charset() + " decoder outgrew its worst-case buffer: " + result);
            }
            decoded.flip();
            final char[] chars = new char[decoded.remaining()];
            decoded.get(chars);
            return chars;
        } finally {
            clear(encoded);
            clear(decoded);
        }
    }

    static public boolean clear(byte[] bytes) {
        Arrays.fill(bytes, (byte) 0);
        try {
            for (byte b : bytes) {
                assert ((byte) 0 == b);
            }
        } catch (AssertionError e) {
            return false;
        }
        return true;
    }

    static public boolean clear(ByteBuffer buffer) {
        final byte[] zeros = new byte[buffer.limit()];
        Arrays.fill(zeros, (byte) 0);
        buffer.rewind();
        buffer.put(zeros);
        try {
            for (byte b : buffer.array()) {
                assert ((byte) 0 == b);
            }
        } catch (AssertionError e) {
            return false;
        }
        return true;
    }

    static public boolean clear(CharBuffer buffer) {
        final char[] zeros = new char[buffer.limit()];
        Arrays.fill(zeros, (char) 0);
        buffer.rewind();
        buffer.put(zeros);
        try {
            for (char c : buffer.array()) {
                assert ((char) 0 == c);
            }
        } catch (AssertionError e) {
            return false;
        }
        return true;
    }

    private void parseContentType(String contentType) {
        String pattern = "[\\s\\\"\\;\\,]";
        List<String> split = Arrays.asList(contentType.split(pattern));
        List<String> filtered = split.stream()
                .filter(s -> !(s.isEmpty() || s.length() == 1))
                .collect(Collectors.toList());

        if (filtered.size() > 0) {
            mimeType = filtered.get(0);
        } else {
            mimeType = TEXT_PLAIN;
        }

        if (filtered.size() == 2 && filtered.get(1).startsWith(CHARSET)) {
            try {
                // As it is: charset names are case-insensitive, and upper-casing in the default
                // locale turned the i of iso-8859-1 into a dotted capital I under a Turkish one,
                // which no charset name may contain.
                charset = Charset.forName(filtered.get(1).substring(CHARSET.length()));
            } catch (IllegalArgumentException e) {
                // An illegal or unsupported name, from the application that stored the secret. It
                // must not make the secret unreadable: read it as having no charset.
                charset = null;
            }
        } else {
            charset = null;
        }
    }

    public boolean clear() {
        return clear(value);
    }

    @Override
    public void close() {
        clear();
    }

    public DBusPath getSession() {
        return session;
    }

    public byte[] getSecretValue() {
        return value;
    }

    public byte[] getSecretParameters() {
        return parameters;
    }

    public String getContentType() {
        return contentType;
    }

    public String getMimeType() {
        return mimeType;
    }

    public Charset getCharset() {
        return charset;
    }

}
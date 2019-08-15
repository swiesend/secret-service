package org.freedesktop.secret;

import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.Struct;
import org.freedesktop.dbus.annotations.Position;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;

public final class Secret extends Struct implements AutoCloseable {

    @Position(0)
    private final ObjectPath session;
    @Position(1)
    private final byte[] parameters;
    @Position(2)
    private final byte[] value;
    @Position(3)
    private final String contentType;

    private String mimeType = null;
    private Charset charset = null;

    // NOTE: the specification defines the default content_type differently with "text/plain; charset=utf8"
    //  see: https://standards.freedesktop.org/secret-service/ch14.html
    public static final String TEXT_PLAIN_CHARSET_UTF_8 = "text/plain; charset=utf-8";
    public static final String TEXT_PLAIN = "text/plain";
    private static final String CHARSET = "charset=";

    public Secret(ObjectPath session, byte[] value) {
        this.session = session;
        this.parameters = "".getBytes();
        this.value = value;
        this.contentType = TEXT_PLAIN_CHARSET_UTF_8;
        this.mimeType = TEXT_PLAIN;
        this.charset = StandardCharsets.UTF_8;
    }

    public Secret(ObjectPath session, byte[] parameters, byte[] value) {
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

    public Secret(ObjectPath session, byte[] parameters, byte[] value, String contentType) {
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

    public Secret(ObjectPath session, byte[] parameters, byte[] value, Charset charset) {
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

    private void parseContentType(String contentType) {
        String pattern = "[\\s\\\"\\;\\,]";
        List<String> split = Arrays.asList(contentType.split(pattern));
        List<String> filtered = split.stream().
                filter(s -> !(s.isEmpty() || s.length() == 1)).
                collect(Collectors.toList());

        if (filtered.size() > 0) {
            mimeType = filtered.get(0);
        } else {
            mimeType = TEXT_PLAIN;
        }

        if (filtered.size() == 2 && filtered.get(1).startsWith(CHARSET)) {
            charset = Charset.forName(filtered.get(1).substring(CHARSET.length()).toUpperCase());
        } else {
            charset = null;
        }
    }

    static public String createContentType(String mimeType, Charset charset) {
        return mimeType + "; " + CHARSET + charset.name().toLowerCase();
    }

    static public String createContentType(Charset charset) {
        return TEXT_PLAIN + "; " + CHARSET + charset.name().toLowerCase();
    }

    static public byte[] toBytes(CharSequence passphrase) {
        final ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(passphrase));
        final byte[] bytes = new byte[encoded.remaining()];
        encoded.get(bytes);
        try {
            return bytes;
        } finally {
            clear(encoded);
        }
    }

    static public byte[] toBytes(char[] passphrase) {
        final ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(passphrase));
        final byte[] bytes = new byte[encoded.remaining()];
        encoded.get(bytes);
        try {
            return bytes;
        } finally {
            clear(encoded);
        }
    }

    static public char[] toChars(byte[] bytes){
        ByteBuffer encoded = ByteBuffer.wrap(bytes);
        CharBuffer decoded = StandardCharsets.UTF_8.decode(encoded);
        final char[] chars = new char[decoded.remaining()];
        decoded.get(chars);
        try {
            return chars;
        } finally {
            clear(encoded);
            clear(decoded);
        }
    }

    static public void clear(byte[] bytes) {
        Arrays.fill(bytes, (byte) 0);
        for(byte b: bytes) {
            assert((byte) 0 == b);
        }
    }

    static public void clear(ByteBuffer buffer) {
        final byte[] zeros = new byte[buffer.limit()];
        Arrays.fill(zeros, (byte) 0);
        buffer.rewind();
        buffer.put(zeros);
        for(byte b: buffer.array()) {
            assert((byte) 0 == b);
        }
    }

    static public void clear(CharBuffer buffer) {
        final char[] zeros = new char[buffer.limit()];
        Arrays.fill(zeros, (char) 0);
        buffer.rewind();
        buffer.put(zeros);
        for(char c: buffer.array()) {
            assert((char) 0 == c);
        }
    }

    public void clear() {
        clear(parameters);
        clear(value);
    }

    @Override
    public void close() {
        clear();
    }

    public ObjectPath getSession() {
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
package org.freedesktop.secret;

import org.freedesktop.dbus.ObjectPath;
import org.freedesktop.dbus.Struct;
import org.freedesktop.dbus.annotations.Position;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;

public final class Secret extends Struct {

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


    static public String createContentType(String mimeType, Charset charset) {
        return mimeType + "; " + CHARSET + charset.name().toLowerCase();
    }

    static public String createContentType(Charset charset) {
        return TEXT_PLAIN + "; " + CHARSET + charset.name().toLowerCase();
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
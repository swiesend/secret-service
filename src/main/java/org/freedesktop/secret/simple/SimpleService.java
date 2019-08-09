package org.freedesktop.secret.simple;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

public class SimpleService {

    private static final Logger log = LoggerFactory.getLogger(SimpleService.class);

    public Optional<SimpleCollection> connect() {
        try {
            SimpleCollection keyring = new SimpleCollection();
            return Optional.of(keyring);
        } catch (Exception e) {
            log.error(e.toString(), e.getCause());
            return Optional.empty();
        }
    }

    public Optional<SimpleCollection> connect(String label, CharSequence password) {
        try {
            SimpleCollection keyring = new SimpleCollection(label, password);
            return Optional.of(keyring);
        } catch (Exception e) {
            log.error(e.toString(), e.getCause());
            return Optional.empty();
        }
    }

}

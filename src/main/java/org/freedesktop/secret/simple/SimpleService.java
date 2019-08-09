package org.freedesktop.secret.simple;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

public class SimpleService {

    private static final Logger log = LoggerFactory.getLogger(SimpleService.class);

    /**
     * Connect to the default collection.
     */
    public Optional<SimpleCollection> connect() {
        try {
            SimpleCollection keyring = new SimpleCollection();
            return Optional.of(keyring);
        } catch (Exception e) {
            log.error(e.toString(), e.getCause());
            return Optional.empty();
        }
    }

    /**
     * Connect to a user specified collection.
     *
     * @param label     The displayable label of the collection
     *
     *                  <p>
     *                      NOTE: The 'label' of a collection may differ from the 'id' of a collection. The 'id' is
     *                      assigned by the Secret Service and used in the DBus object path of a collection or item.
     *                  <p>
     *
     *                  A SimpleCollection can't handle collections with the same label, but different ids correctly.
     *
     * @param password  Password of the collection
     */
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

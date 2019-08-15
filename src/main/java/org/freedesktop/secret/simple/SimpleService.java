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
     *                  <br>
     *                  <br>
     *                  <p>
     *                      <b>NOTE:</b> The <i>label</i> of a collection may differ from the <i>id</i> of a collection. The <i>id</i> is
     *                      assigned by the Secret Service and used as unique identifier in the DBus <i>object path</i> of
     *                      a collection or item.
     *                  <p/>
     *                  A <code>SimpleCollection</code> can <b>not</b> handle different collections with the same <i>label</i>.
     *
     * @param password  The password of the collection
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

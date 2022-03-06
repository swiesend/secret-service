package org.freedesktop.secret.simple.interfaces;

import java.util.Optional;

public interface SessionInterface extends AutoCloseable {

    Optional<Boolean> clear();

    Optional<CollectionInterface> collection(String label, CharSequence password);

    Optional<CollectionInterface> defaultCollection();

}

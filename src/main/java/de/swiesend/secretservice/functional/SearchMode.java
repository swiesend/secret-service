package de.swiesend.secretservice.functional;

/**
 * Defines how {@link de.swiesend.secretservice.functional.Collection#search(String, SearchMode)}
 * matches items against a query string.
 */
public enum SearchMode {
    /** Match against the item's human-readable label. */
    BY_NAME,
    /** Match against any attribute key of the item. */
    BY_ATTRIBUTE_KEY,
    /** Match against any attribute value of the item. */
    BY_ATTRIBUTE_VALUE,
    /** Match against the last path segment (object id) of the item's D-Bus path. */
    BY_OBJECT_ID,
    /** Match anywhere in the full D-Bus object path. */
    BY_OBJECT_PATH
}

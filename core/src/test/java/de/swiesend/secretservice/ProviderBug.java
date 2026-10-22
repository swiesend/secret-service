package de.swiesend.secretservice;

/**
 * The known bugs of the Secret Service providers: where one departs from the specification, or
 * fails, in a way that a client meets. A reported bug links its report; the others were found and
 * analysed here and are not reported upstream.
 *
 * <p>{@link FakeSecretService#reproduce} makes the fake provider behave as a provider with the bug
 * does, for a bug marked {@link Fake#ON_REQUEST}, and the fake follows the specification there
 * otherwise. It always behaves as a bug marked {@link Fake#ALWAYS} describes, and does not
 * reproduce one marked {@link Fake#NOT_REPRODUCED}, whose description says why.</p>
 *
 * <p>A test that checks how the library copes with a bug turns the bug on; the description of each
 * bug names what the library does about it.</p>
 */
public enum ProviderBug {

    // ---- gnome-keyring -----------------------------------------------------------------------

    /**
     * A client's {@code Dismiss} of an unlock prompt whose dialog is on the screen aborts the
     * daemon: {@code perform_next_unlock: assertion failed: (!self->current)}. Every client loses
     * its session, and the daemon that D-Bus starts next has the login keyring locked. Also
     * reported as GNOME #64 and #144, Launchpad #1891800 and #2107534, and Fedora 2417856, 2484409
     * and 2499356; reproduced here on 40 and 46.1. Fixed by commit 4eacdcf0. The library dismisses
     * a prompt that nobody answers within its timeout, 120 seconds by default, which meets it.
     */
    GNOME_KEYRING_ABORTS_ON_A_DISMISSED_UNLOCK_DIALOG(Provider.GNOME_KEYRING, Status.FIXED,
            "3.0.3 to 50.0; fixed in 51.0", "https://gitlab.gnome.org/GNOME/gnome-keyring/-/issues/37", Fake.ON_REQUEST),

    /**
     * A client's {@code Dismiss} of an unlock prompt while another unlock prompt's dialog is on the
     * screen aborts the daemon as well: a prompt that waits behind that dialog, or one that was
     * never shown. Its completion takes the first prompt off the unlock queue, the one whose dialog
     * shows, and asserts that nothing is in progress there; the fix of #37 clears only the
     * dismissed prompt's own state. Reproduced here on 40, 46.1 and 51.1. The library dismisses a
     * prompt that nobody answers within its timeout, also one that waits behind another
     * application's dialog, and with prompting disabled it dismisses an unlock prompt that it does
     * not show.
     */
    GNOME_KEYRING_ABORTS_ON_A_DISMISSED_WAITING_UNLOCK(Provider.GNOME_KEYRING, Status.UNREPORTED,
            "3.0.3 to 51.1", null, Fake.ON_REQUEST),

    /**
     * Since the fix of #37, a client's {@code Dismiss} of an unlock prompt whose dialog is on the
     * screen leaves the dialog there, and the unlock prompt that waits behind it never completes,
     * also once the user answers the dialog. The dismissed prompt's call completes when the user
     * answers, and it takes the waiting prompt off the unlock queue in its own place, without
     * resuming it ("unlock prompt queue is out of sync with prompts"); a prompt that waits behind
     * that one is never resumed either. The answer still unlocks the collection, and an unlock
     * prompt that comes later works. Reproduced here on 51.1.
     */
    GNOME_KEYRING_STRANDS_THE_UNLOCKS_BEHIND_A_DISMISSED_DIALOG(Provider.GNOME_KEYRING, Status.UNREPORTED,
            "51.0 and 51.1", null, Fake.ON_REQUEST),

    /**
     * {@code GetSecret} gives every secret the content type {@code text/plain}: gnome-keyring stores
     * none (read from its code, {@code gkd-secret-secret.c}). The library reads {@code text/plain}
     * as UTF-8, as libsecret writes it ({@code SecretContentTypeTest}).
     */
    GNOME_KEYRING_GIVES_EVERY_SECRET_AS_TEXT_PLAIN(Provider.GNOME_KEYRING, Status.UNREPORTED,
            "46.1 and 51.1", null, Fake.ON_REQUEST),

    /**
     * Any client reads the secrets of an unlocked collection, without a prompt. gnome-keyring's
     * developers dispute it: the desktop's applications all run as the same user. The library asks
     * the user before it reads all secrets of a collection or deletes from it: it locks the
     * collection and unlocks it through the dialog ({@code UserPermissionTest}).
     */
    GNOME_KEYRING_ANY_CLIENT_READS_AN_UNLOCKED_COLLECTION(Provider.GNOME_KEYRING, Status.REPORTED,
            "every version", "https://nvd.nist.gov/vuln/detail/CVE-2018-19358", Fake.ALWAYS),

    /**
     * Three or more unlock prompts of a collection at once: when the user dismisses the dialog,
     * the other prompts get no answer, and the daemon unlocks nothing more until it restarts. A fix
     * is proposed in its merge request !92. Not reproduced: its cause in
     * {@code perform_next_unlock()} is not analysed here.
     */
    GNOME_KEYRING_PARALLEL_UNLOCKS_BREAK_THE_QUEUE(Provider.GNOME_KEYRING, Status.REPORTED,
            "46.2 to 51.1", "https://gitlab.gnome.org/GNOME/gnome-keyring/-/issues/160", Fake.NOT_REPRODUCED),

    /**
     * About one prompt in 256 that creates a collection is dismissed after the user has answered
     * its dialog: "couldn't create new collection: Cannot import an invalid key". The daemon gets
     * the password from its prompter through a key exchange of their own, and hashes all 192 bytes
     * of the shared secret, where the prompter's gcr 3 hashes it without its leading zero bytes; a
     * secret whose top byte is zero gives each side a key of its own. An unlock dialog is not
     * affected, as gcr does both sides of its exchange, and gcr 4.3 pads the secret in its
     * libgcrypt backend. Reported by its symptom only; reproduced here on 40 and 51.1, where 9 of
     * 3000 creates failed. Not reproduced: a client sees a cancel, and the fake cancels every
     * create. The library cannot tell the two apart; {@code ServiceTest}, where someone answers
     * every dialog, creates once more.
     */
    GNOME_KEYRING_DISMISSES_AN_ANSWERED_CREATE_PROMPT(Provider.GNOME_KEYRING, Status.REPORTED,
            "40.0 and 51.1, with gcr 3.40 and 3.41", "https://gitlab.gnome.org/GNOME/gnome-keyring/-/issues/167", Fake.NOT_REPRODUCED),

    /**
     * A call of {@code Prompt}, {@code Dismiss} or {@code Close} on another connection's prompt or
     * session gets two replies: the error, and the error that its handler's unhandled return gives.
     * Fixed by commit 9000777b. Not reproduced: the library calls them on its own objects only.
     */
    GNOME_KEYRING_ANSWERS_ANOTHER_CONNECTIONS_CALL_TWICE(Provider.GNOME_KEYRING, Status.FIXED,
            "46.1; fixed in 51.0", null, Fake.NOT_REPRODUCED),

    /**
     * The login keyring that gnome-keyring creates at the user's first login is listed in
     * {@code Collections}, but no object is exported at its path until the daemon restarts. Fixed by
     * commit 8fb9c2a6. Not reproduced: the library cannot reach a collection that is not on the
     * bus.
     */
    GNOME_KEYRING_EXPORTS_A_NEW_LOGIN_KEYRING_ONLY_AFTER_A_RESTART(Provider.GNOME_KEYRING, Status.FIXED,
            "up to 50.0; fixed in 51.0", "https://gitlab.gnome.org/GNOME/gnome-keyring/-/issues/137", Fake.NOT_REPRODUCED),

    /**
     * {@code Collection.Delete} deletes a locked collection, and its keyring file, without an
     * unlock; the specification says that a locked collection cannot be modified. Not reproduced:
     * the library deletes what it is asked to delete, and refuses only the default collection.
     */
    GNOME_KEYRING_DELETES_A_LOCKED_COLLECTION(Provider.GNOME_KEYRING, Status.UNREPORTED,
            "46.1 and 51.1", null, Fake.NOT_REPRODUCED),

    /**
     * {@code CreateItem} with {@code replace} replaces the most recently changed item whose
     * attributes include the new item's, also one that has more attributes; the specification
     * replaces an item with the same attributes. Not reproduced: the library never asks to replace.
     */
    GNOME_KEYRING_REPLACES_AN_ITEM_WITH_MORE_ATTRIBUTES(Provider.GNOME_KEYRING, Status.UNREPORTED,
            "46.1 and 51.1", null, Fake.NOT_REPRODUCED),

    /**
     * The default collection's alias path, {@code /org/freedesktop/secrets/aliases/default}, is no
     * object of its own: gnome-keyring passes calls on it to the collection, and sends the
     * collection's signals from the collection's own path only. A client that listens on the alias
     * path hears none. Not reproduced: the library resolves the alias with {@code ReadAlias} and
     * listens on the collection's path.
     */
    GNOME_KEYRING_SIGNALS_ONLY_FROM_THE_COLLECTION_NOT_ITS_ALIAS(Provider.GNOME_KEYRING, Status.UNREPORTED,
            "46.1 and 51.1", null, Fake.NOT_REPRODUCED),

    // ---- KeePassXC ---------------------------------------------------------------------------

    /**
     * The items of a locked database are not on the bus: {@code SearchItems} and {@code Items} give
     * none, and their paths are unknown objects. The specification lists the locked items as such.
     * The library unlocks the collection before it lists or reads ({@code SearchResultTest}).
     */
    KEEPASSXC_HIDES_THE_ITEMS_OF_A_LOCKED_DATABASE(Provider.KEEPASSXC, Status.UNREPORTED,
            "2.7.6 and 2.7.12", null, Fake.ON_REQUEST),

    /**
     * {@code SearchItems} with no attributes finds no item, where gnome-keyring and KWallet find
     * every item; the specification leaves it open. The library lists all items through
     * {@code Items} ({@code SearchResultTest}).
     */
    KEEPASSXC_AN_EMPTY_SEARCH_FINDS_NOTHING(Provider.KEEPASSXC, Status.UNREPORTED,
            "2.7.6 and 2.7.12", null, Fake.ON_REQUEST),

    /**
     * A secret stored as {@code text/plain} with a charset comes back as {@code text/plain}, its
     * charset dropped: KeePassXC keeps it in the entry's password field. The library reads
     * {@code text/plain} as UTF-8 ({@code SecretContentTypeTest}).
     */
    KEEPASSXC_DROPS_THE_CHARSET(Provider.KEEPASSXC, Status.UNREPORTED,
            "2.7.6 and 2.7.12", null, Fake.ON_REQUEST),

    /**
     * A new label or new attributes for an item that the user has not allowed the client to read
     * are taken: KeePassXC checks only whether the database is locked, where the specification
     * answers {@code IsLocked}. It refuses the secret. The library unlocks a locked item before it
     * changes it ({@code UpdateItemTest}).
     */
    KEEPASSXC_CHANGES_AN_ITEM_IT_HAS_NOT_ALLOWED(Provider.KEEPASSXC, Status.UNREPORTED,
            "2.7.6 and 2.7.12", null, Fake.ON_REQUEST),

    /**
     * Any connection uses and closes any session, where the specification binds a session to the
     * connection that opened it. The fake has one session for every connection.
     */
    KEEPASSXC_ANY_CONNECTION_USES_ANY_SESSION(Provider.KEEPASSXC, Status.UNREPORTED,
            "2.7.6 and 2.7.12", null, Fake.ALWAYS),

    /**
     * New attributes are merged into the item's old ones, so that an attribute can never be
     * removed. Not reproduced: the fake keeps no attributes, and the library cannot remove one on
     * KeePassXC either.
     */
    KEEPASSXC_MERGES_NEW_ATTRIBUTES_INTO_THE_OLD(Provider.KEEPASSXC, Status.UNREPORTED,
            "2.7.6 and 2.7.12", null, Fake.NOT_REPRODUCED),

    /**
     * A search that names KeePassXC's own attribute {@code Uuid} or {@code Path} ignores every other
     * attribute of the search. Not reproduced: the library searches with what it is given.
     */
    KEEPASSXC_A_UUID_OR_PATH_SEARCH_IGNORES_THE_OTHER_ATTRIBUTES(Provider.KEEPASSXC, Status.UNREPORTED,
            "2.7.6 and 2.7.12", null, Fake.NOT_REPRODUCED),

    /**
     * {@code Item.Delete} moves the entry to the database's recycle bin, after a prompt, and
     * {@code Collection.Delete} only closes the database. Not reproduced: the library carries out
     * the prompt, and cannot tell where the item went.
     */
    KEEPASSXC_DELETE_KEEPS_THE_ITEM_IN_THE_RECYCLE_BIN(Provider.KEEPASSXC, Status.UNREPORTED,
            "2.7.6 and 2.7.12", null, Fake.NOT_REPRODUCED),

    // ---- KWallet -----------------------------------------------------------------------------

    /**
     * The shared secret of a session is hashed without its leading zero bytes (OpenSSL's
     * {@code DH_compute_key}, through QCA), where gnome-keyring, KeePassXC, libsecret and the
     * library hash all of its 128 bytes. About one session in 256 has a key of its own on each
     * side, and KWallet answers every secret of it with "Can't find session". The library replaces
     * such a session, four times at most ({@code SharedSecretTest}).
     */
    KWALLET_HASHES_THE_SHARED_SECRET_WITHOUT_LEADING_ZEROS(Provider.KWALLET, Status.FIXED,
            "5 and 6 up to 6.24; fixed in 6.25", "https://bugs.kde.org/show_bug.cgi?id=514194", Fake.ON_REQUEST),

    /**
     * The client's public key is read as a signed number (QCA's {@code BigInteger}), so that a key
     * whose top bit is set arrives changed, and the two sides of the session have keys of their
     * own. The library sends the key with the sign byte that {@code BigInteger.toByteArray()} gives
     * it ({@code SharedSecretTest}).
     */
    KWALLET_READS_THE_PUBLIC_KEY_AS_SIGNED(Provider.KWALLET, Status.FIXED,
            "5 and 6 up to 6.24; fixed in 6.25", "https://bugs.kde.org/show_bug.cgi?id=514194", Fake.ON_REQUEST),

    /**
     * A client's public key of fewer than 128 bytes is refused, and about one key in 256 is that
     * short without its leading zero byte. The library pads every key to the prime's 128 bytes
     * ({@code PublicKeyEncodingTest}).
     */
    KWALLET_REFUSES_A_SHORT_PUBLIC_KEY(Provider.KWALLET, Status.FIXED,
            "5 and 6 up to 6.24; fixed in 6.25", "https://bugs.kde.org/show_bug.cgi?id=514194", Fake.ON_REQUEST),

    /**
     * {@code Lock} of a wallet that is closed already answers with an error. The library reads
     * {@code Locked} before it locks ({@code CollectionLockPromptTest}).
     */
    KWALLET_REFUSES_TO_LOCK_A_LOCKED_WALLET(Provider.KWALLET, Status.UNREPORTED,
            "5.115 and 6.24", null, Fake.ON_REQUEST),

    /**
     * Reading a locked item answers with an empty secret, encrypted, instead of {@code IsLocked}.
     * The library reads no locked item ({@code LockedItemSecretTest}, {@code BulkUnlockTest}).
     */
    KWALLET_READS_A_LOCKED_ITEM_AS_EMPTY(Provider.KWALLET, Status.REPORTED,
            "5.115, 6.24 and 6.31", "https://bugs.kde.org/show_bug.cgi?id=524650", Fake.ON_REQUEST),

    /**
     * {@code SetSecret} on a locked item answers success and drops the secret: after the unlock,
     * the item has its old one. The specification answers {@code IsLocked}. The library sends no
     * secret to a locked item ({@code UpdateItemTest}).
     */
    KWALLET_DROPS_THE_SECRET_FOR_A_LOCKED_ITEM(Provider.KWALLET, Status.UNREPORTED,
            "5.115, 6.24 and 6.31", null, Fake.ON_REQUEST),

    /**
     * A new label or new attributes for a locked item answer success. The attributes are stored;
     * the label is too, but the entry in the closed wallet keeps its name, so that after the unlock
     * the item reads an empty secret and KWallet 6 brings the old entry back as another item. The
     * specification answers {@code IsLocked}. The library changes no locked item
     * ({@code UpdateItemTest}).
     */
    KWALLET_TAKES_THE_LABEL_OF_A_LOCKED_ITEM(Provider.KWALLET, Status.UNREPORTED,
            "5.115, 6.24 and 6.31; 5.115 makes no second item", null, Fake.ON_REQUEST),

    /**
     * {@code Item.Delete} of a locked item answers "/", which says that it is deleted without a
     * prompt. The item goes, but its secret stays in the wallet, and KWallet 6 brings it back as a
     * new item at the next unlock. The specification answers {@code IsLocked}. The library deletes
     * nothing from a collection that stays locked ({@code DeleteItemTest}).
     */
    KWALLET_ANSWERS_DELETE_OF_A_LOCKED_ITEM_AS_DONE(Provider.KWALLET, Status.UNREPORTED,
            "5.115, 6.24 and 6.31; 5.115 brings nothing back", null, Fake.ON_REQUEST),

    /**
     * {@code Collection.Delete} deletes a locked wallet without a prompt; the specification says
     * that a locked collection cannot be modified. Its development branch dereferences a null
     * pointer there (read from its code). Not reproduced: the library deletes what it is asked to
     * delete, and refuses only the default collection.
     */
    KWALLET_DELETES_A_LOCKED_WALLET(Provider.KWALLET, Status.UNREPORTED,
            "5.115 and 6.24", null, Fake.NOT_REPRODUCED),

    /**
     * {@code Unlock} gives a prompt also when the login has opened the wallet, and the prompt
     * opens it without a dialog. Not reproduced: the library reads {@code Locked} after any unlock,
     * whatever the prompt answered.
     */
    KWALLET_PROMPTS_TO_UNLOCK_AN_OPEN_WALLET(Provider.KWALLET, Status.FIXED,
            "5 and 6 up to 6.29", "https://bugs.kde.org/show_bug.cgi?id=459287", Fake.NOT_REPRODUCED),

    /**
     * A dismissed unlock prompt reports {@code ["/"]} as the objects it unlocked, where it unlocked
     * none. Not reproduced: the library reads {@code Locked} after any unlock, whatever the prompt
     * answered.
     */
    KWALLET_A_DISMISSED_UNLOCK_REPORTS_THE_ROOT_PATH(Provider.KWALLET, Status.UNREPORTED,
            "5.115 and 6.24", null, Fake.NOT_REPRODUCED),

    /**
     * A secret that does not decrypt under the session's key gets the answer "Can't find session",
     * as for a session that does not exist. Not reproduced: the fake decrypts no secret that it is
     * sent, and the library reports the call as failed either way.
     */
    KWALLET_CANNOT_FIND_A_SESSION_FOR_A_SECRET_IT_CANNOT_DECRYPT(Provider.KWALLET, Status.UNREPORTED,
            "5.115 and 6.24", null, Fake.NOT_REPRODUCED),

    /**
     * {@code CreateItem} with {@code replace} replaces the first item whose attributes include the
     * new item's, and the item keeps its old label. Not reproduced: the library never asks to
     * replace.
     */
    KWALLET_REPLACE_KEEPS_THE_OLD_LABEL(Provider.KWALLET, Status.UNREPORTED,
            "5.115 and 6.24", null, Fake.NOT_REPRODUCED),

    // ---- oo7 ---------------------------------------------------------------------------------

    /**
     * A secret whose content type is not exactly {@code text/plain} or
     * {@code application/octet-stream} is refused, {@code text/plain; charset=utf-8} too. The
     * library sends {@code text/plain} ({@code SecretContentTypeTest}).
     */
    OO7_REFUSES_A_CONTENT_TYPE_WITH_PARAMETERS(Provider.OO7, Status.FIXED,
            "0.6.0; 0.7 strips the parameters", null, Fake.ON_REQUEST),

    /**
     * {@code CreateItem} without the {@code Attributes} property makes the handler panic, and the
     * call never gets a reply (read from its code: the properties are unwrapped). The library
     * always sends the attributes, an empty map for none ({@code CreateItemPropertiesTest}).
     */
    OO7_PANICS_ON_CREATE_ITEM_WITHOUT_ATTRIBUTES(Provider.OO7, Status.UNREPORTED,
            "0.6.0 and 0.7.0 beta", null, Fake.ON_REQUEST),

    /**
     * {@code Dismiss} removes the prompt and sends no {@code Completed}, where the specification ends
     * a dismissed prompt with one (read from its code). The library waits for no answer after it
     * dismisses a prompt ({@code PromptResultTest}).
     */
    OO7_DISMISS_SENDS_NO_COMPLETED(Provider.OO7, Status.UNREPORTED,
            "0.6.0 and 0.7.0 beta", null, Fake.ON_REQUEST),

    /**
     * Any client reads the secrets of an unlocked collection, without a prompt, as on
     * gnome-keyring. The library asks the user before it reads all secrets of a collection or
     * deletes from it, as there.
     */
    OO7_ANY_CLIENT_READS_AN_UNLOCKED_COLLECTION(Provider.OO7, Status.UNREPORTED,
            "0.6.0 and 0.7.0 beta", null, Fake.ALWAYS),

    /**
     * Any connection uses any session, where the specification binds a session to the connection
     * that opened it. The fake has one session for every connection.
     */
    OO7_ANY_CONNECTION_USES_ANY_SESSION(Provider.OO7, Status.UNREPORTED,
            "0.6.0 and 0.7.0 beta", null, Fake.ALWAYS),

    /**
     * Of a client that leaves the bus, only one session is closed. Not reproduced: the library
     * closes its sessions itself.
     */
    OO7_CLOSES_ONE_SESSION_OF_A_CLIENT_THAT_LEAVES(Provider.OO7, Status.UNREPORTED,
            "0.6.0", null, Fake.NOT_REPRODUCED),

    /**
     * {@code CreateItem} with {@code replace} deletes every item whose attributes include the new
     * item's; the specification replaces an item with the same attributes. Not reproduced: the
     * library never asks to replace.
     */
    OO7_REPLACE_DELETES_EVERY_ITEM_WITH_THE_ATTRIBUTES(Provider.OO7, Status.FIXED,
            "0.6.0; 0.7 replaces an exact match only", null, Fake.NOT_REPRODUCED),

    /**
     * {@code Item.Delete} deletes, on disk, every item whose attributes include the deleted item's
     * (read from its code). Not reproduced: the library cannot keep it from doing so.
     */
    OO7_DELETE_REMOVES_EVERY_ITEM_WITH_THE_ATTRIBUTES(Provider.OO7, Status.UNREPORTED,
            "0.6.0 and 0.7.0 beta", null, Fake.NOT_REPRODUCED),

    /**
     * {@code SetSecret} and a new label or attributes change the item in memory only, and are lost
     * when the daemon restarts (read from its code). Not reproduced: the library cannot tell.
     */
    OO7_KEEPS_CHANGES_IN_MEMORY_ONLY(Provider.OO7, Status.UNREPORTED,
            "0.6.0 and 0.7.0 beta", null, Fake.NOT_REPRODUCED),

    /**
     * The items' paths are numbered anew at every start of the daemon, where the specification
     * keeps an item's path for its lifetime. Not reproduced: the library hands the paths to the
     * caller, who keeps them at its own risk.
     */
    OO7_RENUMBERS_THE_ITEMS_AT_EVERY_START(Provider.OO7, Status.UNREPORTED,
            "0.6.0 and 0.7.0 beta", null, Fake.NOT_REPRODUCED),

    /**
     * An unknown algorithm, a content type it refuses and a secret that does not decrypt get
     * {@code org.freedesktop.zbus.Error}, where the specification names {@code NotSupported} for
     * the first. Not reproduced: the library logs such an error as unexpected.
     */
    OO7_ANSWERS_WITH_ZBUS_ERRORS(Provider.OO7, Status.UNREPORTED,
            "0.6.0 and 0.7.0 beta", null, Fake.NOT_REPRODUCED),

    /**
     * Reading the label or the attributes of a locked item fails, as {@code GetSecret} and
     * {@code SetSecret} do. Not reproduced: the library reads {@code Locked} first.
     */
    OO7_REFUSES_TO_READ_A_LOCKED_ITEMS_LABEL(Provider.OO7, Status.UNREPORTED,
            "0.6.0 and 0.7.0 beta", null, Fake.NOT_REPRODUCED),

    /**
     * {@code CreateCollection} with an alias that names a collection creates another one, through
     * a prompt, where the specification returns that collection. Not reproduced: the library
     * creates its collections with no alias.
     */
    OO7_CREATES_ANOTHER_COLLECTION_FOR_A_KNOWN_ALIAS(Provider.OO7, Status.UNREPORTED,
            "0.6.0 and 0.7.0 beta", null, Fake.NOT_REPRODUCED);

    /** The providers that the library is tested against. */
    public enum Provider { GNOME_KEYRING, KEEPASSXC, KWALLET, OO7 }

    /** How far the bug is known upstream. */
    public enum Status {
        /** Reported upstream, and not fixed. */
        REPORTED,
        /** Fixed upstream; the versions before the fix have it. */
        FIXED,
        /** Found and analysed here, and not reported upstream. */
        UNREPORTED
    }

    /** What the fake provider does about the bug. */
    public enum Fake {
        /** {@link FakeSecretService#reproduce} turns it on. */
        ON_REQUEST,
        /** The fake always behaves so. */
        ALWAYS,
        /** The fake does not reproduce it: the bug's description says why. */
        NOT_REPRODUCED
    }

    public final Provider provider;
    public final Status status;
    /** The versions known to have it, and the one that fixed it. */
    public final String versions;
    /** The report upstream, or null when there is none. */
    public final String report;
    public final Fake fake;

    ProviderBug(Provider provider, Status status, String versions, String report, Fake fake) {
        this.provider = provider;
        this.status = status;
        this.versions = versions;
        this.report = report;
        this.fake = fake;
    }
}

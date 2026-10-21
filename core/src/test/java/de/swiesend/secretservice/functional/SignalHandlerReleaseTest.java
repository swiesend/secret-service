package de.swiesend.secretservice.functional;

import de.swiesend.secretservice.TransportEncryption;
import de.swiesend.secretservice.functional.interfaces.ServiceInterface;
import de.swiesend.secretservice.functional.interfaces.SessionInterface;
import de.swiesend.secretservice.functional.interfaces.SystemInterface;
import de.swiesend.secretservice.handlers.SignalHandler;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * An object that registers signal handlers releases them when it closes. They stayed registered on
 * the connection, which mostly outlives the object -- SimpleCollection's lasts as long as the JVM --
 * and each kept a buffer of 1024 signals and logged every Secret Service signal on the bus. A
 * SimpleCollection opened and closed per operation added 13 of them every time.
 */
class SignalHandlerReleaseTest {

    @Test
    void aClosedCollectionReleasesItsHandlers() throws Exception {
        try (ServiceInterface service = SecretService.create().orElseThrow();
             SessionInterface session = service.openSession().orElseThrow()) {
            Collection collection = (Collection) session.collection("test", Optional.of("test")).orElseThrow();
            SignalHandler prompts = collection.prompt.getSignalHandler();
            SignalHandler items = collection.collection.getSignalHandler();
            boolean registered = prompts.isConnected() && items.isConnected();
            collection.delete();

            collection.close();

            assertTrue(registered, "the precondition: both were registered");
            assertFalse(prompts.isConnected(), "the prompt handler is released");
            assertFalse(items.isConnected(), "the item signal handler is released");
        }
    }

    @Test
    void aClosedServiceReleasesItsHandler() throws Exception {
        ServiceInterface service = SecretService.create().orElseThrow();
        SignalHandler collections = service.getService().getSignalHandler();
        assertTrue(collections.isConnected(), "the precondition: it is registered");

        service.close();

        assertFalse(collections.isConnected());
    }

    @Test
    void aClosedTransportReleasesTheServiceItOpened() throws Exception {
        try (SystemInterface system = System.connect().orElseThrow()) {
            TransportEncryption transport = new TransportEncryption(system.getConnection());
            SignalHandler collections = transport.getService().getSignalHandler();
            assertTrue(collections.isConnected(), "the precondition: it is registered");

            transport.close();

            assertFalse(collections.isConnected());
        }
    }

    @Test
    void aClosedTransportLeavesAServiceItWasGivenToItsOwner() throws Exception {
        try (ServiceInterface service = SecretService.create().orElseThrow()) {
            new TransportEncryption(service.getService()).close();

            assertTrue(service.getService().getSignalHandler().isConnected(),
                    "the service is the caller's, which still uses its handler");
        }
    }
}

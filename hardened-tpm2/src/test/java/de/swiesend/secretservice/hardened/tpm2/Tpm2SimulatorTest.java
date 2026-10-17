package de.swiesend.secretservice.hardened.tpm2;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import tss.Tpm;
import tss.TpmException;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests {@link Tpm2Simulator} against a stand-in for the simulator, so they need none. The stand-in
 * speaks the simulator's TCP protocol: TPM commands on one port and platform signals on the next,
 * each signal four bytes and acknowledged, one connection on each port.
 */
@Timeout(value = 30, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class Tpm2SimulatorTest {

    private static final int POWER_ON = 1;
    private static final int POWER_OFF = 2;
    private static final int NV_ON = 11;
    private static final int NV_OFF = 12;
    private static final int TPM_CC_STARTUP = 0x144;
    private static final int TPM_CC_DICTIONARY_ATTACK_LOCK_RESET = 0x139;

    @Test
    void startsTheTpmOnlyOncePowerOnIsAcknowledged() throws Exception {
        try (StandIn simulator = StandIn.start()) {
            simulator.holdAcknowledgmentOf(POWER_ON);
            CompletableFuture<Tpm> connecting =
                    CompletableFuture.supplyAsync(() -> Tpm2Simulator.connect(simulator.host(), simulator.port()));
            assertTrue(simulator.awaitHeldSignal(), "the power cycle sends power on");
            // TSS.Java's TpmFactory sends Startup now: it takes the acknowledgment of an earlier
            // signal for that of power on.
            Thread.sleep(500);
            assertEquals(List.of(), simulator.commands(), "no TPM command before power on is acknowledged");

            simulator.releaseAcknowledgment();
            Tpm tpm = connecting.get(10, TimeUnit.SECONDS);
            assertEquals(List.of(POWER_OFF, NV_OFF, POWER_ON, NV_ON), simulator.signals(),
                    "four signals, none with a length before it");
            assertEquals(List.of(TPM_CC_STARTUP, TPM_CC_DICTIONARY_ATTACK_LOCK_RESET), simulator.commands());

            tpm.close();
            assertTrue(simulator.awaitBothEnded(), "closing the TPM closes both connections");
        }
    }

    @Test
    void closesBothConnectionsWhenTheStartFails() throws Exception {
        try (StandIn simulator = StandIn.start()) {
            // What the simulator answers to a command while it is off.
            simulator.answerEmpty();
            assertThrows(TpmException.class, () -> Tpm2Simulator.connect(simulator.host(), simulator.port()));
            assertTrue(simulator.awaitBothEnded(),
                    "a failed start closes both connections; the simulator serves no other while one is open");
        }
    }

    @Test
    void refusesWhereNoSimulatorListens() throws IOException {
        InetAddress loopback = InetAddress.getLoopbackAddress();
        int port;
        try (ServerSocket unused = new ServerSocket(0, 1, loopback)) {
            port = unused.getLocalPort();
        }
        assertThrows(TpmException.class, () -> Tpm2Simulator.connect(loopback.getHostAddress(), port));
    }

    /** Serves one connection on each port, as the simulator does. */
    private static final class StandIn implements AutoCloseable {

        private static final int SEND_COMMAND = 8;
        private static final int SESSION_END = 20;
        private static final short TPM_ST_SESSIONS = (short) 0x8002;

        private final ServerSocket commandPort;
        private final ServerSocket platformPort;
        private final List<Integer> signals = new CopyOnWriteArrayList<>();
        private final List<Integer> commands = new CopyOnWriteArrayList<>();
        private final List<Socket> connections = new CopyOnWriteArrayList<>();
        private final CountDownLatch heldSignalArrived = new CountDownLatch(1);
        private final CountDownLatch acknowledgmentReleased = new CountDownLatch(1);
        private final CountDownLatch connectionsEnded = new CountDownLatch(2);
        private final Thread commandThread;
        private final Thread platformThread;
        private volatile int heldSignal = -1;
        private volatile boolean answerEmpty = false;

        private StandIn(ServerSocket commandPort, ServerSocket platformPort) {
            this.commandPort = commandPort;
            this.platformPort = platformPort;
            this.commandThread = Thread.ofPlatform().daemon().name("stand-in commands").start(this::serveCommands);
            this.platformThread = Thread.ofPlatform().daemon().name("stand-in platform").start(this::servePlatform);
        }

        /** Listens on two consecutive free ports of the loopback interface. */
        static StandIn start() throws IOException {
            InetAddress loopback = InetAddress.getLoopbackAddress();
            for (int attempt = 0; attempt < 20; attempt++) {
                ServerSocket commandPort = new ServerSocket(0, 3, loopback);
                try {
                    return new StandIn(commandPort, new ServerSocket(commandPort.getLocalPort() + 1, 3, loopback));
                } catch (IOException | IllegalArgumentException e) {
                    commandPort.close(); // the next port is taken, or past the last one: another pair
                }
            }
            throw new IOException("no two consecutive free ports on the loopback interface");
        }

        String host() {
            return commandPort.getInetAddress().getHostAddress();
        }

        int port() {
            return commandPort.getLocalPort();
        }

        List<Integer> signals() {
            return List.copyOf(signals);
        }

        List<Integer> commands() {
            return List.copyOf(commands);
        }

        void holdAcknowledgmentOf(int signal) {
            heldSignal = signal;
        }

        void releaseAcknowledgment() {
            acknowledgmentReleased.countDown();
        }

        void answerEmpty() {
            answerEmpty = true;
        }

        boolean awaitHeldSignal() throws InterruptedException {
            return heldSignalArrived.await(10, TimeUnit.SECONDS);
        }

        /** Waits until the client has ended its session, or closed, on both ports. */
        boolean awaitBothEnded() throws InterruptedException {
            return connectionsEnded.await(10, TimeUnit.SECONDS);
        }

        private void servePlatform() {
            try (Socket connection = accept(platformPort)) {
                DataInputStream in = new DataInputStream(connection.getInputStream());
                DataOutputStream out = new DataOutputStream(connection.getOutputStream());
                for (int signal = in.readInt(); signal != SESSION_END; signal = in.readInt()) {
                    signals.add(signal);
                    if (signal == heldSignal) {
                        heldSignalArrived.countDown();
                        acknowledgmentReleased.await(10, TimeUnit.SECONDS);
                    }
                    out.writeInt(0);
                }
            } catch (IOException | InterruptedException e) {
                // the connection ended without a session end, or the test closed the stand-in
            } finally {
                connectionsEnded.countDown();
            }
        }

        private void serveCommands() {
            try (Socket connection = accept(commandPort)) {
                DataInputStream in = new DataInputStream(connection.getInputStream());
                DataOutputStream out = new DataOutputStream(connection.getOutputStream());
                for (int request = in.readInt(); request != SESSION_END; request = in.readInt()) {
                    if (request != SEND_COMMAND) {
                        throw new IOException("not a TPM command: " + request);
                    }
                    in.readByte(); // the locality
                    byte[] command = new byte[in.readInt()];
                    in.readFully(command);
                    commands.add(ByteBuffer.wrap(command).getInt(6)); // after the tag and the size
                    byte[] response = answerEmpty ? new byte[0] : success(command);
                    out.writeInt(response.length);
                    out.write(response);
                    out.writeInt(0);
                }
            } catch (IOException e) {
                // the connection ended without a session end, or the test closed the stand-in
            } finally {
                connectionsEnded.countDown();
            }
        }

        private Socket accept(ServerSocket port) throws IOException {
            Socket connection = port.accept();
            connections.add(connection);
            return connection;
        }

        /**
         * A success without response parameters: the tag, the size and the response code. Where the
         * command carries a session, the response size of the parameters follows, and one password
         * session's response: an empty nonce, the attribute continueSession and an empty HMAC.
         */
        private static byte[] success(byte[] command) {
            short tag = ByteBuffer.wrap(command).getShort(0);
            ByteBuffer response = ByteBuffer.allocate(tag == TPM_ST_SESSIONS ? 19 : 10);
            response.putShort(tag).putInt(response.capacity()).putInt(0);
            if (tag == TPM_ST_SESSIONS) {
                response.putInt(0).putShort((short) 0).put((byte) 1).putShort((short) 0);
            }
            return response.array();
        }

        @Override
        public void close() throws Exception {
            acknowledgmentReleased.countDown();
            commandPort.close();
            platformPort.close();
            for (Socket connection : connections) {
                connection.close();
            }
            commandThread.join(10_000);
            platformThread.join(10_000);
        }
    }
}

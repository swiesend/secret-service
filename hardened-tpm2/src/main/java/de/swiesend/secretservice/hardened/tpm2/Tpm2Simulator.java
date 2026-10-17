package de.swiesend.secretservice.hardened.tpm2;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tss.Tpm;
import tss.TpmDeviceTcp;
import tss.TpmException;
import tss.tpm.TPM_HANDLE;
import tss.tpm.TPM_RH;
import tss.tpm.TPM_SU;

import java.io.DataInputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.Objects;

/**
 * Connects to a TPM 2.0 simulator: the reference simulator ms-tpm-20-ref, or one that speaks its
 * TCP protocol. Use it in place of TSS.Java's {@code TpmFactory.localTpmSimulator()}, also where a
 * {@code Supplier<Tpm>} selects the TPM: {@code Tpm2Simulator::connect}.
 *
 * <p>The simulator takes TPM commands on one port and platform signals, such as power on, on the
 * next. It reads each signal as four bytes and acknowledges it. TSS.Java 1.0.0 sends a four-byte
 * length before each signal, which the simulator reads as a signal of its own and acknowledges
 * too. {@code TpmFactory}'s power cycle then returns on the acknowledgment of an earlier signal,
 * and {@code Startup} can reach the simulator before it is on, which answers it with an empty
 * response. This class sends each power signal alone and waits for its acknowledgment.</p>
 *
 * <p>The simulator serves one connection on each port at a time, so a connection left open stalls
 * every later one. {@code TpmFactory} leaves its connection open when a step after the connect
 * fails. This class closes it then, and closing the {@code Tpm} it returns closes both sockets,
 * also where the simulator is gone.</p>
 */
public final class Tpm2Simulator {

    private static final Logger log = LoggerFactory.getLogger(Tpm2Simulator.class);

    /** The simulator's command port; its platform port is the next one. */
    public static final int DEFAULT_PORT = 2321;

    // The platform signals, as the simulator's TpmTcpProtocol.h numbers them.
    private static final int SIGNAL_POWER_ON = 1;
    private static final int SIGNAL_POWER_OFF = 2;
    private static final int SIGNAL_NV_ON = 11;
    private static final int SIGNAL_NV_OFF = 12;

    private Tpm2Simulator() {}

    /**
     * Connects to the simulator on {@code localhost:2321} and starts it.
     *
     * @return the started TPM; closing it closes the connection
     * @throws TpmException if the simulator is unreachable or refuses a step
     */
    public static Tpm connect() {
        return connect("localhost", DEFAULT_PORT);
    }

    /**
     * Connects to the simulator at {@code host}, on its command port {@code port} and its platform
     * port {@code port + 1}, and starts it as {@code TpmFactory.localTpmSimulator()} does: a power
     * cycle, {@code Startup(CLEAR)}, and a reset of the dictionary-attack lockout.
     *
     * @param host the simulator's host
     * @param port the simulator's command port
     * @return the started TPM; closing it closes the connection
     * @throws TpmException if the simulator is unreachable or refuses a step; the connection is
     *         closed then
     */
    public static Tpm connect(String host, int port) {
        Objects.requireNonNull(host, "host");
        SimulatorDevice device = new SimulatorDevice(host, port);
        if (!device.connect()) {
            throw new TpmException("no TPM simulator at " + host + ":" + port);
        }
        boolean started = false;
        try {
            device.powerCycle();
            Tpm tpm = new Tpm();
            tpm._setDevice(device);
            tpm.Startup(TPM_SU.CLEAR);
            tpm.DictionaryAttackLockReset(TPM_HANDLE.from(TPM_RH.LOCKOUT));
            started = true;
            return tpm;
        } finally {
            if (!started) {
                device.close();
            }
        }
    }

    /** TSS.Java's TCP device, with the power signals sent as the simulator reads them. */
    private static final class SimulatorDevice extends TpmDeviceTcp {

        SimulatorDevice(String host, int port) {
            super(host, port);
        }

        @Override
        public void powerCtl(boolean on) {
            signal(on ? SIGNAL_POWER_ON : SIGNAL_POWER_OFF);
            signal(on ? SIGNAL_NV_ON : SIGNAL_NV_OFF);
        }

        private void signal(int signal) {
            try {
                SignalSocket.getOutputStream().write(ByteBuffer.allocate(Integer.BYTES).putInt(signal).array());
                // Unbuffered, so it reads this signal's acknowledgment and nothing after it.
                int ack = new DataInputStream(SignalSocket.getInputStream()).readInt();
                if (ack != 0) {
                    throw new TpmException("the TPM simulator refused platform signal " + signal);
                }
            } catch (IOException e) {
                throw new TpmException("platform signal " + signal + " to the TPM simulator failed", e);
            }
        }

        /**
         * Ends the session on both ports and closes them. TSS.Java's close stops at the first port it
         * cannot write to, and leaves that socket and the next one open; this closes both anyway.
         */
        @Override
        public void close() {
            try {
                super.close();
            } catch (RuntimeException e) {
                log.debug("ending the TPM simulator session failed: {}", e.toString());
            } finally {
                closeQuietly(CommandSocket);
                closeQuietly(SignalSocket);
            }
        }

        private static void closeQuietly(Socket socket) {
            if (socket == null) return;
            try {
                socket.close();
            } catch (IOException e) {
                log.debug("closing a TPM simulator socket failed: {}", e.toString());
            }
        }
    }
}

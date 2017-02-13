import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Random;
import java.util.concurrent.CopyOnWriteArrayList;

public abstract class RdtProtocol {

    protected enum TAG { SYNC, SEND, RECV, CLOSE, HOOK } // for debugging

    protected static final int MAXOVERFLOW = 2000;       // max repeated packets
    protected static final int DEFTCPHEAD = 20;          // in bytes
    protected static final int MSS = 576;                // in bytes
    protected boolean debugMode;
    protected short remotePort;
    protected short listenPort;
    protected short windowSize;
    protected int nextSeqNum;
    protected int corrupted;
    protected int duplicates;
    protected int memberIsn;
    protected int remoteIsn;
    protected int remoteFsn;
    protected int bytesTrans;
    protected long startTime;
    protected long endTime;
    protected File dataFile;
    protected Timer timer;
    protected InetAddress remoteAddr;
    protected DatagramSocket listenSock;
    protected DatagramSocket sendSock;
    protected FileOutputStream fileWriter;
    protected CopyOnWriteArrayList<Thread> threads;

    private boolean stdout;
    private long logEntry;
    private File logFile;
    private PrintWriter logger;

    /**
     * Constructs a new protocol member.
     *
     * @param args  : CL parameters.
     * @param debug : True - for debugging mode.
     *              : False - otherwise
     */
    public RdtProtocol(String[] args, boolean debug) {

        threads = new CopyOnWriteArrayList<>();
        memberIsn = new Random().nextInt(1000);
        debugMode = debug;
        remoteIsn = 0;
        nextSeqNum = 0;
        logEntry = 0;
        corrupted = 0;
        duplicates = 0;
        bytesTrans = 0;

        try {

            dataFile = new File(args[0]);
            logFile = new File(args[1]);
            remoteAddr = InetAddress.getByName(args[2]);
            remotePort = Short.parseShort(args[3]);
            listenPort = Short.parseShort(args[4]);
            listenSock = new DatagramSocket(listenPort);
            sendSock = new DatagramSocket();
            stdout = (args[1].equals("stdout"));

            /* if output requested to console */
            if (stdout) {
                logFile = File.createTempFile("temp", ".txt");
                logFile.deleteOnExit();
            } else {
                logFile = new File(args[1]);
            }
            logger = new PrintWriter(new FileWriter(logFile, false));

            logger.println(String.format(
                    "%-20s%-16s%-8s%-8s%-11s%-11s%-26s%-18s",
                    "#", "Timestamp", "Source", "Dest", "Seq#",
                    "ACK#", "URG ACK PSH RST SYN FIN", "EstRTT")
            );

        } catch (IOException | NumberFormatException e) {
            if (debug)
                e.printStackTrace();
            kill("Error: Improper argument format: " + e.getCause());
        }

        /* print parameters to console */
        String divider = "=============================" +
                         "============================";
        if (debug)
            System.out.println("======================DEBUG=MODE" +
                               "=========================");
        else
            System.out.println(divider);

        try {
            System.out.println(
                    "\tFile name:      "   + args[0] +
                    "\n\tLog file name:  " + args[1] +
                    "\n\tRemote IP:      " + args[2] +
                    "\n\tRemote port:    " + args[3] +
                    "\n\tListening port: " + args[4]);

            if (args.length > 6) {
                windowSize = Short.parseShort(args[5]);
                System.out.println("\tWindow Size:    " + args[5]);
            }
        } catch (Exception e) {
            kill("Error: Improper argument format." + e.getMessage());
        }
        System.out.println(divider);

        /* for debugging */
        if (debugMode)
            Runtime.getRuntime().traceMethodCalls(true);

        startShutdownHook();

        /* instantiate timer */
        instTimer();

        /* instantiate handlers */
        instHandlers();

        System.out.println("\n\n" + divider + "\n" + getTimestamp() +
                           ": Establishing connection ...");

        /* start the timer */
        timer.start();

        /* perform the handshake */
        connect();

        System.out.println(getTimestamp() + ": Connection established." +
                "\n" + divider + "\n\n\n" + divider);

        if (!debugMode)
            System.out.println(getTimestamp() + ": Transferring file ... ");

        /* start the data and ACK handlers and record times */
        startTime = System.currentTimeMillis();
        startHandlers();
        endTime = System.currentTimeMillis();

        System.out.println(divider + "\n\n\n" + divider + "\n" +
                getTimestamp() + ": Closing connection...");

        /* close the connection */
        disconnect();

        /* close timer */
        timer.shutdown();

        System.out.println(divider + "\n\n");

        /* ensure shutdown hook is executed */
        System.exit(0);
    }

    /**
     * Instantiates the ACK and Data Handler threads.
     */
    abstract void instHandlers();

    /**
     * Starts the ACK and Data Handler threads.
     */
    abstract void startHandlers();

    /**
     * Performs the TCP 3-way handshake to synchronize
     * and open connection to the remote host.
     */
    abstract void connect();

    /**
     * Performs the TCP 4-way handshake to close connection
     * to the remote host.
     */
    abstract void disconnect();

    /**
     * Prints the file transfer statistics upon termination.
     */
    abstract void printStats();

    /**
     * A hook that captures interrupt signals.
     */
    private void startShutdownHook() {

        Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {

                /* close listening socket */
                if (listenSock != null && !listenSock.isClosed())
                    listenSock.close();

                /* interrupt any running threads */
                if (debugMode) {

                    threads.stream().filter(Thread::isAlive).forEach(t -> {
                        System.out.println(TAG.HOOK + "  : " + t.getName() +
                                           " was interrupted. Stack Trace:\n");
                        for (StackTraceElement s : t.getStackTrace())
                            System.out.println(s);

                        System.out.println();
                        t.interrupt();
                    });

                } else {
                    threads.stream().filter(Thread::isAlive).
                            forEach(Thread::interrupt);
                }

                /* print file transfer statistics */
                printStats();

                /* flush any remaining content */
                logger.flush();

                /* print to console if necessary */
                if (stdout) {
                    try (BufferedReader logReader =
                                 new BufferedReader(new FileReader(logFile))) {
                        System.out.println(TAG.HOOK +
                                           "  : Received Packet Log:");
                        String line;
                        while ((line = logReader.readLine()) != null)
                            System.out.println(line);

                    } catch (IOException e) {
                        println("ERROR: Unable to read line from " + logFile);
                    }
                }

                logger.close();
            }
        });
    }

    /**
     * Instantiates the Timer.
     */
    private void instTimer() {
        timer = new Timer(debugMode);
        timer.setName("Timer Thread");
        threads.add(timer);
    }

    /**
     * Kills the program and displays error message to standard error.
     *
     * @param msg : The message to be displayed before terminating.
     */
    protected void kill(String msg) {
        System.err.println(msg);
        System.exit(-1);
    }

    /**
     * Logs a time stamp and the message to standard out.
     *
     * @param msg : The message to be displayed.
     */
    void println(String msg) {
        if (debugMode)
            System.out.println(getTimestamp() + msg);
    }

    /**
     * Sends a datagram to the sender.
     *
     * @param buff : The TcpPacket encoded as a byte array
     * @return     : True on success, false otherwise
     */
    protected boolean sendPacket(byte[] buff) {
        try {
            sendSock.send(new DatagramPacket(buff, buff.length,
                    remoteAddr, remotePort));
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Attempts to receive incoming datagrams into the buffer.
     *
     * @param buffSize : The size of the receive buffer.
     * @return         : If not corrupt - the decoded TcpPacket object.
     *                 : Null, otherwise.
     */
    protected TcpPacket receivePacket(int buffSize) {

        try {

            byte[] buff = new byte[buffSize];
            DatagramPacket packet = new DatagramPacket(buff, buff.length);

            listenSock.setSoTimeout(timer.timeout);
            listenSock.receive(packet);

            TcpPacket payload = new TcpPacket();
            payload.extract(packet.getData());

            /* check for corruption */
            byte[] sent = payload.getSegment();
            sent[16] = 0;
            sent[17] = 0;

            if (payload.getChecksum() != payload.calculateChecksum(sent)) {
                corrupted++;
                return null;
            }
            return payload;

        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Returns a timestamp with millisecond accuracy.
     *
     * @return : String formatted timestamp.
     */
    protected String getTimestamp() {
        return new SimpleDateFormat("[HH:mm:ss:SSS] ").
                format(Calendar.getInstance().getTime());
    }

    /**
     * Logs the contents of the TcpPacket payload object to the logfile.
     *
     * @param payload : The TcpPacket payload.
     */
    protected synchronized void log(TcpPacket payload) {

        String flags = "";
        flags += payload.getUrg() ? "URG " : " -  ";
        flags += payload.getAck() ? "ACK " : " -  ";
        flags += payload.getPsh() ? "PSH " : " -  ";
        flags += payload.getRst() ? "RST " : " -  ";
        flags += payload.getSyn() ? "SYN " : " -  ";
        flags += payload.getFin() ? "FIN " : " -  ";
        logger.println(
                String.format("%-20s%-16s%-8d%-8d%-11d%-11d%-26s%-18s",
                        logEntry++, getTimestamp(), payload.getSrcPort(),
                        payload.getDestPort(), payload.getSeqNum(),
                        payload.getAckNum(), flags,
                        Double.toString(timer.estRtt))
        );
    }
}

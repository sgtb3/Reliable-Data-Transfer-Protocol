import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.*;
import java.util.Arrays;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Random;
import java.util.concurrent.CopyOnWriteArrayList;

abstract class RDT_Protocol {

    enum TAG { SYNC, SEND, RECV, CLOSE, HOOK }       /* for debugging */

    static final int MAX_OVERFLOW = 2000;            /* max allowable repeated packets */
    protected static final int DEFAULT_TCP_HEAD = 20;/* in bytes */
    protected static final int MSS = 576;            /* in bytes */

    protected boolean stdout;
    boolean debug_mode;
    protected short remote_port;
    protected short listen_port;
    protected short window_size;
    protected int next_seq_num;
    protected int corrupted;
    protected int duplicates;
    int member_isn;
    int remote_isn;
    int remote_fsn;
    int bytes_trans;
    protected long start_time;
    protected long end_time;
    private long log_entry;
    protected File data_file;
    protected File log_file;
    protected Timer timer;
    private PrintWriter logger;
    protected InetAddress remote_addr;
    protected DatagramSocket listen_sock;
    protected DatagramSocket send_sock;
    protected FileOutputStream file_writer;
    protected CopyOnWriteArrayList<Thread> threads;

    /**
     * Constructs a new protocol member.
     *
     * @param args  : CL parameters.
     * @param debug : True - for debugging mode.
     *              : False - otherwise
     */
    RDT_Protocol(String[] args, boolean debug) {

        threads = new CopyOnWriteArrayList<>();
        member_isn = new Random().nextInt(1000);
        debug_mode = debug;
        remote_isn = 0;
        next_seq_num = 0;
        log_entry    = 0;
        corrupted    = 0;
        duplicates   = 0;
        bytes_trans  = 0;

        try {

            data_file   = new File(args[0]);
            log_file    = new File(args[1]);
            remote_addr = InetAddress.getByName(args[2]);
            remote_port = Short.parseShort(args[3]);
            listen_port = Short.parseShort(args[4]);
            listen_sock = new DatagramSocket(listen_port);
            send_sock   = new DatagramSocket();
            stdout      = (args[1].equals("stdout"));

            /* if output requested to console */
            if (stdout) {
                log_file = File.createTempFile("temp", ".txt");
                log_file.deleteOnExit();
            } else {
                log_file = new File(args[1]);
            }
            logger = new PrintWriter(new FileWriter(log_file, false));

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
                window_size = Short.parseShort(args[5]);
                System.out.println("\tWindow Size:    " + args[5]);
            }

        } catch (Exception e) {
            kill("Error: Improper argument format.");
        }
        System.out.println(divider);

        /* for debugging */
        if (debug_mode)
            Runtime.getRuntime().traceMethodCalls(true);

        start_shutdown_hook();

        /* instantiate timer */
        inst_timer();

        /* instantiate handlers */
        inst_handlers();

        System.out.println("\n\n" + divider + "\n" + get_timestamp() +
                           ": Establishing connection ...");

        /* start the timer */
        timer.start();

        /* perform the handshake */
        connect();

        System.out.println(get_timestamp() + ": Connection established." +
                "\n" + divider + "\n\n\n" + divider);

        if (!debug_mode)
            System.out.println(get_timestamp() + ": Transferring file ... ");

        /* start the data and ACK handlers and record times */
        start_time = System.currentTimeMillis();
        start_handlers();
        end_time = System.currentTimeMillis();

        System.out.println(divider + "\n\n\n" + divider + "\n" +
                get_timestamp() + ": Closing connection...");

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
    abstract void inst_handlers();

    /**
     * Starts the ACK and Data Handler threads.
     */
    abstract void start_handlers();

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
    abstract void print_stats();

    /**
     * A hook that captures interrupt signals.
     */
    protected void start_shutdown_hook() {

        Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {

                /* close listening socket */
                if (listen_sock != null && !listen_sock.isClosed())
                    listen_sock.close();

                /* interrupt any running threads */
                if (debug_mode) {

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
                print_stats();

                /* flush any remaining content */
                logger.flush();

                /* print to console if necessary */
                if (stdout) {

                    try (BufferedReader log_reader =
                                 new BufferedReader(new FileReader(log_file))) {
                        System.out.println(TAG.HOOK +
                                           "  : Received Packet Log:");
                        String line;
                        while ((line = log_reader.readLine()) != null)
                            System.out.println(line);

                    } catch (IOException e) {
                        println("ERROR: Unable to read line from " + log_file);
                    }
                }

                logger.close();
            }
        });
    }

    /**
     * Instantiates the Timer.
     */
    protected void inst_timer() {
        timer = new Timer(debug_mode);
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
    protected void println(String msg) {
        if (debug_mode)
            System.out.println(get_timestamp() + msg);
    }

    /**
     * Sends a datagram to the sender.
     *
     * @param buff : The TCP_Packet encoded as a byte array
     * @return     : True on success, false otherwise
     */
    protected boolean send_packet(byte[] buff) {
        try {
            send_sock.send(new DatagramPacket(buff, buff.length,
                           remote_addr, remote_port));
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Attempts to receive incoming datagrams into the buffer.
     *
     * @param buff_size : The size of the receive buffer.
     * @return          : If not corrupt - the decoded TCP_Packet object.
     *                  : Null, otherwise.
     */
    protected TCP_Packet receive_packet(int buff_size) {

        try {

            byte[] buff = new byte[buff_size];
            DatagramPacket packet = new DatagramPacket(buff, buff.length);

            listen_sock.setSoTimeout(timer.timeout);
            listen_sock.receive(packet);

            TCP_Packet payload = new TCP_Packet();
            payload.extract(packet.getData());

            /* check for corruption */
            byte[] sent = payload.get_segment();
            sent[16] = 0;
            sent[17] = 0;
            if (payload.get_checksum() != payload.calculate_checksum(sent)) {
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
    protected String get_timestamp() {
        return new SimpleDateFormat("[HH:mm:ss:SSS] ").
                format(Calendar.getInstance().getTime());
    }

    /**
     * Logs the contents of the TCP_Packet payload object to the logfile.
     *
     * @param payload : The TCP_Packet payload.
     */
    protected synchronized void log(TCP_Packet payload) {

        String flags = "";
        flags += payload.get_URG() ? "URG " : " -  ";
        flags += payload.get_ACK() ? "ACK " : " -  ";
        flags += payload.get_PSH() ? "PSH " : " -  ";
        flags += payload.get_RST() ? "RST " : " -  ";
        flags += payload.get_SYN() ? "SYN " : " -  ";
        flags += payload.get_FIN() ? "FIN " : " -  ";
        logger.println(
                String.format("%-20s%-16s%-8d%-8d%-11d%-11d%-26s%-18s",
                        log_entry++, get_timestamp(), payload.get_src_port(),
                        payload.get_dest_port(), payload.get_seq_num(),
                        payload.get_ack_num(), flags,
                        Double.toString(timer.est_rtt))
        );
    }
}

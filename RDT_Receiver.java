import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

public class RDT_Receiver extends RDT_Protocol {

    private boolean FIN_recv;
    private int acks_sent;
    private int last_ack_sent;
    private int receiver_seq_num;
    private ACK_Handler ah;
    private Data_Handler dh;
    private ConcurrentLinkedDeque<Integer> ack_queue;
    private CopyOnWriteArrayList<Integer> received;

    /**
     * Constructs a new Receiver.
     * @param args  : The CL args.
     * @param debug : True - for debugging mode.
     *              : False - otherwise
     */
    private RDT_Receiver(String[] args, boolean debug) {
        super(args, debug);
    }


    /**
     * Handles the Receiver's incoming actions (receiving data).
     */
    private class Data_Handler extends Thread {

        /**
         * Constructs a new Data_Handler.
         */
        public Data_Handler() {
            received = new CopyOnWriteArrayList<>();
            try {
                file_writer = new FileOutputStream(data_file);
            } catch (FileNotFoundException e) {
                kill("ERROR: Failed to create data file: " + e.getCause());
                if (debug_mode) {
                    e.printStackTrace();
                }
            }
            last_ack_sent = 0;
            remote_fsn = -1;
        }

        @Override
        public void run() {

            println(TAG.RECV + "  : Data_Handler running...");

            TCP_Packet payload;
            int curr_seq_num;
            int exp_seq_num;
            byte[] data;

            while (true)
            {
                // break if final ACK has been sent
                if (last_ack_sent == remote_fsn) {
                    break;
                }
                // receive the packet
                payload = receive_packet(MSS);
                if (payload == null) {
                    continue;
                }

                // for concurrency, save the next expected seq num
                exp_seq_num = next_seq_num;

                // extract data and seq_num from received payload
                curr_seq_num = payload.get_seq_num();
                data = payload.get_data();

                // check for out-of-order/duplicate packets
                if (curr_seq_num != exp_seq_num) {
                    String msg = "  : <-- seq# " + curr_seq_num;
                    if (received.contains(curr_seq_num)) {
                        duplicates++;
                        msg += " (Duplicate)";
                    }
                    println(TAG.RECV + msg + " (Out-of-order) (expecting " + exp_seq_num + ")");
                    ack_queue.offer(exp_seq_num);
                    continue;
                }

                // if final data packet
                if (payload.get_FIN()) {

                    println(TAG.RECV + "  : (FINAL) <-- seq# " + curr_seq_num);

                    // get the size of the actual data
                    int data_size = (payload.get_segment().length - DEFAULT_TCP_HEAD) -
                                     payload.bytes_to_int(payload.get_options());

                    bytes_trans += data_size;
                    FIN_recv = true;

                    // write data to file
                    try {
                        file_writer.write(data, 0, data_size);
                        file_writer.close();
                    } catch (IOException | NullPointerException ignored) {}

                    // save the final sequence number
                    remote_fsn = (curr_seq_num + payload.get_segment().length) -
                                  DEFAULT_TCP_HEAD;
                    next_seq_num = remote_fsn;

                    timer.start_timer(curr_seq_num);

                } else {

                    println(TAG.RECV + "  : <-- seq# " + curr_seq_num);

                    // if segment contains data, write data to file
                    if (data.length != 0) {
                        bytes_trans += data.length;
                        try {
                            file_writer.write(data);
                        } catch (IOException | NullPointerException ignored ) {}
                    }

                    // update next expected seq num
                    next_seq_num = curr_seq_num + data.length;

                    // stop timer for valid packet
                    if (timer.running && (timer.seq_num <= curr_seq_num)) {
                        timer.stop_timer(curr_seq_num);
                    }

                    // start timer for the next seq num if it's not running
                    if (!timer.running) {
                        timer.start_timer(next_seq_num);
                    }
                }

                // log packet to file
                log(payload);

                // add to list of received segments
                if (!received.contains(curr_seq_num)) {
                    received.add(curr_seq_num);
                }

                // send the next expected seq num to queue for reply
                ack_queue.offer(next_seq_num);
            }
            println(TAG.RECV + "  : Data_Handler complete.");
        }
    }

    /**
     * Handles the Receiver's outgoing actions (sending acknowledgements)
     */
    private class ACK_Handler extends Thread {

        /**
         * Constructor.
         */
        public ACK_Handler() {
            ack_queue = new ConcurrentLinkedDeque<>();
            acks_sent = 0;
        }

        /**
         * Handles the dequeue portion. If more than one ACK is in the queue,
         * it chooses the one with the highest number and removes the
         * affected ACKs from the queue.
         * @return : The next appropriate ACK to be sent.
         */
        private int dequeue_ack() {

            // for concurrency, save queue in its present state
            Object[] curr_queue = ack_queue.toArray();
            int queue_size = curr_queue.length;

            if (queue_size == 1) {
                receiver_seq_num++;
                ack_queue.removeFirstOccurrence(last_ack_sent);
                println(TAG.SEND + "  : --> ack# " + curr_queue[0]);
                return (int) curr_queue[0];
            }

            // otherwise queue contains > 1 ACK
            receiver_seq_num += queue_size;
            for (Object ack : curr_queue) {
                ack_queue.removeFirstOccurrence(ack);
            }

            println(TAG.SEND + "  : --> Cumulative (ack#'s " + curr_queue[0] +
                    " - " + curr_queue[queue_size-1] + ")\n");

            return (int) curr_queue[queue_size-1];
        }

        @Override
        public void run() {

            println(TAG.SEND + "  : Ack_Handler running...");

            TCP_Packet payload = new TCP_Packet();
            payload.set_src_port(listen_sock.getLocalPort());
            payload.set_dest_port(remote_port);
            payload.set_ACK(true);
            byte[] buff = new byte[0];
            int overflow_count = 0;

            while (true)
            {
                if (ack_queue.size() == 0) {
                    continue;
                }

                payload.set_seq_num(receiver_seq_num);

                // check for timeout
                if (timer.timeout_event) {
                    println(TAG.SEND + "  : Detected timeout_event." +
                            " Resending last sent ACK# --> " + last_ack_sent);
                    payload.set_ack_num(last_ack_sent);
                } else {
                    payload.set_ack_num(dequeue_ack());
                }

                // encode the payload
                try {
                    buff = payload.encode();
                } catch (Exception e) {
                    kill("ERROR: Failed to encode ACK: " + e.getCause());
                }

                // send the packet
                if (send_packet(buff))
                {
                    // prevent overflow attack
                    if ((last_ack_sent == payload.get_ack_num()) &&
                        (++overflow_count >= MAX_OVERFLOW)) {
                        kill("ERROR: Network error - Packet overflow.");
                    }

                    // update fields
                    last_ack_sent = payload.get_ack_num();
                    acks_sent++;

                    // start the timer if it's not running
                    if (!timer.running) {
                        timer.start_timer(last_ack_sent);
                    }

                    // break if final ACK has been sent
                    if (FIN_recv && (remote_fsn >= 0) &&
                       (last_ack_sent >= remote_fsn)) {
                        break;
                    }
                }
            }
            println(TAG.SEND + "  : ACK_Handler complete.");
        }
    }

    /**
     * Creates a TCP_packet object.
     * @param opt : 1 - create ACK packet.
     *            : 2 - create SYN/ACK packet.
     *            : 3 - create FIN/ACK packet.
     *            : 4 - create FIN packet.
     * @return    : TCP_Packet encoded as an array of bytes.
     */
    private byte[] make_packet(int opt, int seq_num, int ack_num) {

        TCP_Packet payload = new TCP_Packet();
        payload.set_src_port(listen_sock.getLocalPort());
        payload.set_dest_port(remote_port);

        // set flags
        if (opt == 1 || opt == 2 || opt == 3) {
            payload.set_ACK(true);
            payload.set_ack_num(ack_num);
        }
        if (opt == 2 || opt == 3 || opt == 4) {
            payload.set_seq_num(seq_num);
            if (opt == 2) {
                payload.set_SYN(true);
            } else {
                payload.set_FIN(true);
            }
        }
        // encode and return
        try {
            return payload.encode();
        } catch (Exception e) {
            if (debug_mode) {
                e.printStackTrace();
            }
            return null;
        }
    }

    @Override
    protected void inst_handlers() {

        ah = new ACK_Handler();
        ah.setName("ACK_Handler Thread");
        threads.add(ah);

        dh = new Data_Handler();
        dh.setName("Data_Handler Thread");
        threads.add(dh);
    }

    @Override
    protected void start_handlers() {

        dh.start();
        ah.start();
        try {
            dh.join();
            ah.join();
        } catch (InterruptedException e) {
            kill("ERROR: Unable to complete file transfer!");
            if (debug_mode) {
                e.printStackTrace();
            }
        }
    }

    @Override
    protected void connect() {

        TCP_Packet payload;
        byte[] buff;

        // receive SYN
        while (true) {
            payload = receive_packet(DEFAULT_TCP_HEAD);
            if (payload != null && payload.get_SYN()) {
                remote_isn = payload.get_seq_num();
                println(TAG.SYNC + "  : Received SYN --> seq# " + remote_isn);
                log(payload);
                break;
            }
        }

        // make SYN/ACK
        buff = make_packet(2, member_isn, (remote_isn + 1));
        if (buff == null) {
            kill("ERROR: Failed to make SYN/ACK.");
        }

        // send SYN/ACK
        while (true) {
            if (send_packet(buff)) {
                println(TAG.SYNC + "  : SYN/ACK sent --> seq# " + member_isn +
                        " / ack# " + (remote_isn + 1));
                timer.start_timer(member_isn);
                break;
            }
        }

        // receive ACK
        while (true) {
            payload = receive_packet(DEFAULT_TCP_HEAD);
            if ((payload != null) && payload.get_ACK() &&
                (payload.get_ack_num() == (member_isn + 1)))
            {
                println(TAG.SYNC + "  : Received ACK --> ack# " + (member_isn + 1));
                timer.stop_timer(member_isn + 1);
                log(payload);
                break;
            }
        }
    }

    @Override
    protected void disconnect() {

        // stop the timer if it's still running
        if (timer.running) {
            timer.stop_timer(timer.seq_num);
        }

        // make FIN
        byte[] buff = make_packet(4, receiver_seq_num, 0);
        if (buff == null) {
            kill("ERROR: Failed to make FIN.");
        }

        // send FIN
        while (true) {
            if (send_packet(buff)) {
                println(TAG.CLOSE + " : Sent FIN --> seq# " + receiver_seq_num);
                timer.start_timer(receiver_seq_num);
                break;
            }
        }

        TCP_Packet payload;
        boolean successful;

        // receive FIN/ACK
        while (true) {
            try {
                payload = receive_packet(DEFAULT_TCP_HEAD);
                if ((payload != null) && payload.get_ACK() &&
                        (payload.get_ack_num() == (receiver_seq_num + 1)))
                {
                    println(TAG.CLOSE + " : Received FIN/ACK --> seq# " +
                            payload.get_seq_num() + " / ack# " +
                            payload.get_ack_num());
                    timer.stop_timer(receiver_seq_num + 1, true);
                    log(payload);
                    successful = true;
                    break;
                }
            } catch (Exception ignored) {}
        }

        String msg = successful ? "Connection closed."
                     : "Connection closed improperly.";

        System.out.println(get_timestamp() + ": " + msg +
                " File transfer completed successfully.");
    }

    @Override
    protected void print_stats() {

        long trans_time_sec = TimeUnit.MILLISECONDS.
                              toSeconds(end_time - start_time);
        System.out.println(
                "=============================" +
                "============================" +
                "\n\t\t\tFILE TRANSFER STATISTICS" +
                "\nFile transfer time: (" + trans_time_sec + ") s" +
                "\nReceived file size: (" + bytes_trans + ") bytes" +
                "\nEnding timeout: " + timer.timeout + " ms" +
                "\nEnding est_RTT: " + timer.est_rtt + " ms" +
                "\nEnding dev_RTT: " + timer.dev_rtt + " ms" +
                "\n(" + received.size() + ") valid segments received " +
                "\n(" + corrupted + ") corrupted segments received" +
                "\n(" + duplicates + ") duplicate segments received " +
                "\n(" + acks_sent + ") ACKs sent" +
                "\n============================" +
                "============================="
        );
    }

    /**
     * The main method.
     * @param args: The CL args.
     */
    public static void main(String[] args) {

        if (((args.length != 6) ||
                !args[5].equals("debug")) && (args.length != 5))
        {
            System.out.println("Usage: Receiver <filename>" +
                    " <log_filename> <sender_IP> <sender_port> " +
                    "<listen_port>  optional: <debug>");
            System.exit(-1);
        }
        new RDT_Receiver(args, (args.length == 6));
    }
}
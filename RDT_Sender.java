import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class RDT_Sender extends RDT_Protocol {

    private boolean FIN_sent;
    private boolean FINACK_recv;
    private int base;
    private int padding_bytes;
    private ACK_Handler ah;
    private Data_Handler dh;
    private ConcurrentHashMap<Integer, Segment> segments;

    /**
     * Constructs a new Sender.
     * 
     * @param args  : The CL args.
     * @param debug : True - for debugging mode.
     *              : False - otherwise
     */
    private RDT_Sender(String[] args, boolean debug) {
        super(args, debug);
    }

    /**
     * Handles the Sender's outgoing actions (sending data).
     */
    private class Data_Handler extends Thread {

        @Override
        public void run() {

            println(TAG.SEND + "  : Data_Handler running ...");

            int overflow_count = 0;
            int prev_seq_num = -1;
            int curr_seq_num;
            int curr_seg_num;
            int total_segs = segments.size();
            Segment final_seg = segments.get(total_segs-1);
            Segment curr_seg;
            byte[] buff;
            boolean is_final_seg;

            while (true) {

                /* break if final data segment acknowledged */
                if (final_seg.acked)
                    break;

                /* for concurrency issues, save current sequence number */
                curr_seq_num = next_seq_num;
                curr_seg = find_segment(curr_seq_num, 1);
                if (curr_seg == null)
                    kill("ERROR: Failed to find " +
                         "packet with seq num (" + curr_seq_num + ")");

                /* save corresponding segment number */
                curr_seg_num = curr_seg.seg_num;
                is_final_seg = (curr_seg_num + 1) >= total_segs;

                /*
                 * if final seg make final payload with FIN flag set.
                 * otherwise, create non-FIN TCP payload with data
                 */
                buff = make_packet(is_final_seg ? 4 : 3, curr_seq_num, 0,
                       curr_seg.get_data());

                if (is_final_seg) {

                    while (true) {

                        /* send the final segment */
                        if (!send_packet(buff))
                            continue;

                        /* add to list of sent packets if needed */
                        if (!curr_seg.sent)
                            bytes_trans += curr_seg.get_data().length;

                        /* start timer if it's not running */
                        if (!timer.running)
                            timer.start_timer(curr_seq_num);

                        /* update fields */
                        curr_seg.sent = true;
                        curr_seg.time_sent = System.currentTimeMillis();
                        FIN_sent = true;
                        println(TAG.SEND + "  : (FINAL) seq# --> " + 
                        		curr_seq_num);

                        /* sleep for the maximum allowable time */
                        try {
                            sleep(timer.timeout);
                        } catch (InterruptedException ignored) {}

                        /* break if final segment has been acked */
                        if (curr_seg.acked)
                            break;
                    }

                } else {

                    /* check if sequence number is withing max window size */
                    if (curr_seq_num >= (base + window_size)) {

                        try {
                            println(TAG.SEND + 
                            		"  : |====> MAXIMUM WINDOW SIZE <====|");
                            sleep(timer.timeout);
                        } catch (InterruptedException ignored) {}

                        /* check if timeout event has occurred during sleep */
                        if (timer.timeout_event) {
                            next_seq_num = base;
                            println(TAG.SEND + "  : Detected timeout_event. " +
                                    "Resending all packets starting with " + 
                                    "base --> seq# " + base);

                        } else if ((prev_seq_num == curr_seq_num) &&
                                   (++overflow_count >= MAX_OVERFLOW)) {
                            /* prevent packet overflow attack */
                            kill("ERROR: Network error - Packet overflow.");
                        }
                        continue;
                    }

                    /* send non-final data packet */
                    if (!send_packet(buff))
                        continue;

                    /* add to list of sent packets if needed */
                    if (!curr_seg.sent)
                        bytes_trans += curr_seg.get_data().length;

                    /* update segment fields */
                    curr_seg.sent = true;
                    curr_seg.time_sent = System.currentTimeMillis();

                    /* start the timer if it's not running */
                    if (!timer.running)
                        timer.start_timer(curr_seq_num);

                    println(TAG.SEND + "  : --> seq# " + curr_seq_num);

                    /* increment next sequence number */
                    try {
                        next_seq_num = segments.get(curr_seg_num + 1).seq_num;
                    } catch (NullPointerException e) {
                        if (FINACK_recv)
                            break;
                    }
                }
            }

            println(TAG.SEND + "  : Data_Handler complete.");
        }
    }

    /**
     * Handles the Sender's incoming actions (receiving acknowledgements).
     */
    private class ACK_Handler extends Thread {

        /**
         * Simulates the TCP fast retransmit mechanism.
         * 
         * @param curr_ack : The ACK num to be retransmitted.
         */
        private void fast_retransmit(int curr_ack) {

            /* find corresponding segment */
            Segment retrans_seg = find_segment(curr_ack, 1);

            if (retrans_seg == null)
                kill("ERROR. Failed to find segment in map!");

            if (retrans_seg.seg_num < 0)
                return;

            /* update the next sequence number */
            next_seq_num = curr_ack;

            println(TAG.RECV + "  : 3 duplicate ACKs received. Retransmitting" +
                    " all packets starting with seq# " + curr_ack + " -->" +
                    " (packet " + retrans_seg.seg_num + ")");

            /* update retransmission fields */
            if (!retrans_seg.retrans) {
                retrans_seg.retrans = true;
                retrans_seg.retrans_count++;
            }
        }

        @Override
        public void run() {

            println(TAG.RECV + "  : Ack_Handler running...");

            TCP_Packet payload;
            int prev_ack;
            int curr_ack;
            int final_ack_num = segments.get(segments.size()-1).ack_num;
            int prev_ack_retrans = -1;
            int overflow_count = 0;

            while (true) {

                /* break if final segment acknowledged */
                if (FINACK_recv)
                    break;

                /* receive packet */
                payload = receive_packet(DEFAULT_TCP_HEAD);
                if (payload == null)
                    continue;

                /* get packet ack number */
                curr_ack = payload.get_ack_num();
                prev_ack = curr_ack;

                /* check if valid ack number */
                Segment recv_seg = find_segment(curr_ack, 2);
                
                if (recv_seg == null) {

                    println(TAG.RECV + "  : (Unknown) <-- ack# " +
                            curr_ack + "  : " + payload);

                    /* prevent overflow from unknown ACKs */
                    if ((curr_ack == prev_ack) && 
                    	(++overflow_count > MAX_OVERFLOW))
                        kill("ERROR: Network error - Packet overflow.");
                    continue;
                }

                /* check for duplicate ACKs */
                if (curr_ack == prev_ack) {

                    println(TAG.RECV + "  : <-- ack# " + curr_ack +
                            " (Duplicate x" + (++recv_seg.ack_count) + ")");

                    /* if segment has been ACKed @ least 3 times in a row */
                    if (recv_seg.ack_count >= 3) {

                        /* prevent overflow from repeated ACKs */
                        if (recv_seg.ack_count >= MAX_OVERFLOW)
                            kill("ERROR: Network error - Packet overflow.");

                        /* if timer is not running for a retransmitted ACK */
                        if ((prev_ack_retrans != curr_ack) && !timer.running || 
                        	(timer.seq_num != curr_ack)) {

                            println(TAG.RECV + 
                            		"  : Calling fast retransmit... ");

                            fast_retransmit(curr_ack);
                           
                            /* reset the duplicate ack count */
                            recv_seg.ack_count = 0; 
                            prev_ack_retrans = curr_ack;
                        }

                        continue;
                    }
                }

                /* if final ACK */
                if (FIN_sent && (curr_ack >= final_ack_num)) {
                    println(TAG.RECV + "  : <-- (FINAL) ack# " + curr_ack);
                    FINACK_recv = true;
                } else if (!recv_seg.sent) {
                    println(TAG.RECV + "  : ACK (ack# " + curr_ack + 
                    		") doesn't correspond to any transmitted seq_num");
                    continue;
                }

                /* start timer if it's not running */
                if (!timer.running ||
                   ((timer.seq_num < curr_ack) && !FINACK_recv))
                    timer.start_timer(base);

                if ((curr_ack < final_ack_num) && !FINACK_recv)
                    println(TAG.RECV + "  : <-- ack# " + curr_ack);

                /* update the base flag */
                base = curr_ack;
                if (!recv_seg.base)
                    recv_seg.base = true;

                /* update the acked flag and timestamp, log packet */
                if (!recv_seg.acked) {
                    recv_seg.acked = true;
                    log(payload);
                }

                recv_seg.time_acked = System.currentTimeMillis();
            }

            println(TAG.RECV + "  : ACK_Handler complete.");
        }
    }

    /**
     * Segments the data file into MSS sized chunks and
     * places them in the segment hash map.
     */
    private void segment_file() {

        try {

            byte[] file_bytes = Files.readAllBytes(Paths.
                                get(data_file.getAbsolutePath()));
            int remaining = file_bytes.length;
            int approx_size = Math.round(remaining/(MSS-DEFAULT_TCP_HEAD)) + 1;
            segments = new ConcurrentHashMap<>(approx_size);

            int total_read = 0;
            int file_index = 0; /* i.e. seq number */
            int map_index  = 0; /* i.e. seg number */
            int seg_index;
            byte[] data;
            Segment seg;

            while (remaining > 0) {

                seg  = new Segment(map_index, file_index);
                data = new byte[(MSS-DEFAULT_TCP_HEAD)];
                seg_index = 0;

                while ((seg_index < remaining) && (seg_index < data.length))
                    data[seg_index++] = file_bytes[file_index++];

                remaining -= seg_index;
                total_read += data.length;
                seg.set_data(data);
                segments.put(map_index++, seg);
            }

            padding_bytes = (int) (total_read - data_file.length());

        } catch (IOException e) {
            kill("ERROR: Failed to segment file: " + e.getCause());
        }
    }

    /**
     * Creates a TCP_packet object.
     * @param opt : 1 - Create SYN packet.
     *            : 2 - Create ACK packet.
     *            : 3 - Create data packet.
     *            : 4 - Create FIN packet with data.
     *            : 5 - Create FIN packet without data.
     *            : 6 - Create FIN/ACK packet.
     *            : 7 - Create RST packet.
     *            
     * @return    : TCP_Packet encoded as a byte array.
     */
    private byte[] make_packet(int opt, int seq_num, int ack_num, byte[] data) {

        TCP_Packet payload = new TCP_Packet();
        payload.set_src_port(listen_sock.getLocalPort());
        payload.set_dest_port(remote_port);
        payload.set_seq_num(seq_num);
        payload.set_ack_num(ack_num);

        /* set flags */
        if (opt == 1)
            payload.set_SYN(true);
        
        if (opt == 2 || opt == 6)
            payload.set_ACK(true);
        
        if (opt == 4 || opt == 5 || opt == 6) {
            payload.set_FIN(true);
            if (opt != 6 && padding_bytes != 0)
                payload.set_options(payload.int_to_bytes(padding_bytes));
        }

        if (opt == 7)
            payload.set_RST(true);

        /* if packet contains data and options if necessary */
        if ((opt == 3 || opt == 4) && data != null)
            payload.set_data(data);

        /* encode and return packet */
        try {
            return payload.encode();
        } catch (Exception e) {
            if (debug_mode)
                e.printStackTrace();
            return null;
        }
    }

    /**
     * Returns the sequence numbers of all segments that match the criteria.
     * @param opt : 1 - Sent segments.
     *            : 2 - Acked segments.
     *            : 3 - Retransmitted segments.
     *            : 4 - Base segments
     *            
     * @return : A new ArrayList consisting of the sequence numbers.
     */
    private ArrayList<Integer> get_seq_numbers(int opt) {

        ArrayList<Integer> list = new ArrayList<>();
        for (Integer entry : segments.keySet()) {

            if (((opt == 1) && segments.get(entry).sent) ||
                ((opt == 2) && segments.get(entry).acked) ||
                ((opt == 3) && segments.get(entry).retrans) ||
                ((opt == 4) && segments.get(entry).base))
                list.add(segments.get(entry).seq_num);
        }

        return list;
    }

    /**
     * Searches the segment map for a segment.
     * @param num     : The corresponding sequence or ACK number.
     * @param opt     : 1 - search by seq_num
     *                : 2 - search by ack_num
     *                
     * @return        : The Segment contained in the map, if it exists.
     *                : Null, otherwise.
     */
    private Segment find_segment(int num, int opt) {

        if (opt == 1) {
            for (Integer entry : segments.keySet()) {
                if (segments.get(entry).seq_num == num)
                    return segments.get(entry);
            }
        } else if (opt == 2) {
            for (Integer entry : segments.keySet()) {
                if (segments.get(entry).ack_num == num)
                    return segments.get(entry);
            }
        }

        return null;
    }

    @Override
    protected void inst_handlers() {

        /* segment the file before instantiating handlers */
        segment_file();

        ah = new ACK_Handler();
        ah.setName("ACK_Handler Thread");
        threads.add(ah);

        dh = new Data_Handler();
        dh.setName("Data_Handler Thread");
        threads.add(dh);
    }

    @Override
    protected void start_handlers() {

        ah.start();
        dh.start();

        try {
            dh.join();
        } catch (InterruptedException e) {
            kill("ERROR: Unable to complete file transfer!");
            if (debug_mode)
                e.printStackTrace();
        }
    }

    @Override
    protected void connect() {

        TCP_Packet payload;
        
        /* make SYN */
        byte[] buff = make_packet(1, member_isn, 0, null);
        if (buff == null)
            kill("ERROR: Failed to make SYN.");
        
        /* send SYN */
        while (true) {
            if (send_packet(buff)) {
                println(TAG.SYNC + "  : SYN sent --> seq# " + member_isn);
                timer.start_timer(member_isn);
                break;
            }
        }

        /* receive SYN/ACK */
        while (true) {
            payload = receive_packet(DEFAULT_TCP_HEAD);
            if ((payload != null) && payload.get_SYN() && payload.get_ACK() &&
                (payload.get_ack_num() == (member_isn+1))) {
                remote_isn = payload.get_seq_num();
                println(TAG.SYNC + "  : Received SYN/ACK --> seq# "
                        + remote_isn + " / ack# " + (member_isn+1));
                timer.stop_timer((member_isn+1), true);
                log(payload);
                break;
            }
        }

        /* make ACK */
        buff = make_packet(2, (member_isn + 1), (remote_isn + 1), null);
        if (buff == null)
            kill("ERROR: Failed to make ACK.");

        /* send ACK */
        while (true) {
            if (send_packet(buff)) {
                println(TAG.SYNC + "  : Sent ACK --> ack# " + (member_isn + 1));
                timer.start_timer(member_isn+1);
                break;
            }
        }

        /* reset the timer for data transfer */
        timer.stop_timer(member_isn+1, true);
        timer.seq_num = -1;
    }

    @Override
    protected void disconnect() {

        /* stop the timer if it's still running */
        if (timer.running) {

            Segment seg = find_segment(timer.seq_num, 1);

            if (seg != null && !seg.retrans)
                timer.stop_timer(timer.seq_num, true);
            else
                timer.stop_timer(timer.seq_num);
        }

        TCP_Packet payload;
        int remote_fsn;

        /* receive FIN */
        while (true) {
            payload = receive_packet(DEFAULT_TCP_HEAD);
            if ((payload != null) && payload.get_FIN()) {
                remote_fsn = payload.get_seq_num();
                println(TAG.CLOSE + " : Received FIN --> seq# " + remote_fsn);
                log(payload);
                break;
            }
        }

        /* make FIN/ACK */
        byte[] buff = make_packet(6, ++next_seq_num, ++remote_fsn, null);
        if (buff == null)
            kill("ERROR: Failed to make Receiver's FIN/ACK.");

        /* send FIN/ACK */
        while (true) {
            if (send_packet(buff)) {
                timer.start_timer(next_seq_num);
                println(TAG.CLOSE + " : Sent FIN/ACK --> seq# " + next_seq_num +
                        " / ack# " + remote_fsn);
                break;
            }
        }

        /* wait for final timeout */
        boolean successful = true;
        while (true) {
            if (!timer.timeout_event && (timer.time_remaining > 0)) {
                payload = receive_packet(DEFAULT_TCP_HEAD);
                if (payload != null)
                    successful = false;
            } else {
                println(TAG.CLOSE + " : No further data from Receiver.");
                break;
            }
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

        ArrayList<Integer> sent  = get_seq_numbers(1);
        ArrayList<Integer> acked = get_seq_numbers(2);

        System.out.println(
                "=============================" +
                "============================" +
                "\n\t\t\tFILE TRANSFER STATISTICS" +
                "\nFile transfer time: (" + trans_time_sec + ") s" +
                "\nFile size: (" + data_file.length() + ") bytes" +
                "\n(" + bytes_trans + ") bytes sent" +
                "\nFinal segment padded with (" + padding_bytes + ") bytes" +
                "\nEnding timeout: " + timer.timeout + " ms" +
                "\nEnding est_RTT: " + timer.est_rtt + " ms" +
                "\nEnding dev_RTT: " + timer.dev_rtt + " ms" +
                "\n(" + acked.size() + ") valid ACKs received " +
                "\n(" + corrupted + ") corrupted ACKs received" +
                "\n(" + duplicates + ") duplicates ACKs received" +
                "\n(" + sent.size() + ") segments sent" +
                "\n============================" +
                "============================="
        );
    }

    /**
     * The main entry point.
     * 
     * @param args: The CL args.
     */
    public static void main(String[] args) {

        if (((args.length != 7) ||
             !args[6].equals("debug")) && (args.length != 6)) {

            System.out.println("Usage: Sender <filename> <log_filename> " +
                    "<receiver_IP> <receiver_port> <listen_port>  " +
                    "<window_size> optional: <debug>");
            System.exit(-1);
        }

        new RDT_Sender(args, (args.length == 7));
    }
}

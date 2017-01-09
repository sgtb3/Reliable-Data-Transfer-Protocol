import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

public class RdtReceiver extends RdtProtocol {

    private boolean finRecv;
    private int acksSent;
    private int lastAckSent;
    private int receiverSeqNum;
    private AckHandler ah;
    private DataHandler dh;
    private ConcurrentLinkedDeque<Integer> ackQueue;
    private CopyOnWriteArrayList<Integer> received;

    /**
     * Constructs a new Receiver.
     * 
     * @param args  : The CL args.
     * @param debug : True - for debugging mode.
     *              : False - otherwise
     */
    private RdtReceiver(String[] args, boolean debug) {
        super(args, debug);
    }

    /** Handles the Receiver's incoming actions (receiving data). */
    private class DataHandler extends Thread {

        /** Constructs a new DataHandler. */
        public DataHandler() {

            received = new CopyOnWriteArrayList<>();
            try {
                fileWriter = new FileOutputStream(dataFile);
            } catch (FileNotFoundException e) {
                kill("ERROR: Failed to create data file: " + e.getCause());
                if (debugMode)
                    e.printStackTrace();
            }
            lastAckSent = 0;
            remoteFsn = -1;
        }

        @Override
        public void run() {

            println(TAG.RECV + "  : DataHandler running...");

            TcpPacket payload;
            int currSeqNum;
            int expSeqNum;
            byte[] data;

            while (true) {

                /* break if final ACK has been sent */
                if (lastAckSent == remoteFsn)
                    break;
                
                /* receive the packet */
                payload = receivePacket(MSS);
                if (payload == null)
                    continue;

                /* for concurrency, save the next expected seq num */
                expSeqNum = nextSeqNum;

                /* extract data and seqNum from received payload */
                currSeqNum = payload.getSeqNum();
                data = payload.getData();

                /* check for out-of-order/duplicate packets */
                if (currSeqNum != expSeqNum) {
                    String msg = "  : <-- seq# " + currSeqNum;
                    if (received.contains(currSeqNum)) {
                        duplicates++;
                        msg += " (Duplicate)";
                    }
                    println(TAG.RECV + msg + " (Out-of-order) (expecting " + 
                    		expSeqNum + ")");
                    ackQueue.offer(expSeqNum);
                    continue;
                }

                /* if final data packet */
                if (payload.getFin()) {

                    println(TAG.RECV + "  : (FINAL) <-- seq# " + currSeqNum);

                    /* get the size of the actual data */
                    int data_size = (payload.getSegment().length -
                            DEFTCPHEAD) - payload.
                            bytesToInt(payload.getOptions());

                    bytesTrans += data_size;
                    finRecv = true;

                    /* write data to file */
                    try {
                        fileWriter.write(data, 0, data_size);
                        fileWriter.close();
                    } catch (IOException | NullPointerException ignored) {}

                    /* save the final sequence number */
                    remoteFsn = (currSeqNum + payload.getSegment().length) -
                            DEFTCPHEAD;
                    nextSeqNum = remoteFsn;

                    timer.startTimer(currSeqNum);

                } else {

                    println(TAG.RECV + "  : <-- seq# " + currSeqNum);

                    /* if segment contains data, write data to file */
                    if (data.length != 0) {
                        bytesTrans += data.length;
                        try {
                            fileWriter.write(data);
                        } catch (IOException | NullPointerException ignored ) {}
                    }

                    /* update next expected seq num */
                    nextSeqNum = currSeqNum + data.length;

                    /* stop timer for valid packet */
                    if (timer.running && (timer.seqNum <= currSeqNum))
                        timer.stopTimer(currSeqNum);

                    /* start timer for the next seq num if it's not running */
                    if (!timer.running)
                        timer.startTimer(nextSeqNum);
                }

                /* log packet to file */
                log(payload);

                /* add to list of received segments */
                if (!received.contains(currSeqNum))
                    received.add(currSeqNum);

                /* send the next expected seq num to queue for reply */
                ackQueue.offer(nextSeqNum);
            }
            println(TAG.RECV + "  : DataHandler complete.");
        }
    }

    /**
     * Handles the Receiver's outgoing actions (sending acknowledgements).
     */
    private class AckHandler extends Thread {

        /**
         * Constructs a new AckHandler object.
         */
        public AckHandler() {
            ackQueue = new ConcurrentLinkedDeque<>();
            acksSent = 0;
        }

        /**
         * Handles the dequeue portion. If more than one ACK is in the queue,
         * it chooses the one with the highest number and removes the
         * affected ACKs from the queue.
         * 
         * @return : The next appropriate ACK to be sent.
         */
        private int dequeueAck() {

            /* for concurrency, save queue in its present state */
            Object[] currQueue = ackQueue.toArray();
            int queueSize = currQueue.length;

            if (queueSize == 1) {
                receiverSeqNum++;
                ackQueue.removeFirstOccurrence(lastAckSent);
                println(TAG.SEND + "  : --> ack# " + currQueue[0]);
                return (int) currQueue[0];
            }

            /* otherwise queue contains > 1 ACK */
            receiverSeqNum += queueSize;
            for (Object ack : currQueue)
                ackQueue.removeFirstOccurrence(ack);

            println(TAG.SEND + "  : --> Cumulative (ack#'s " + currQueue[0] +
                    " - " + currQueue[queueSize-1] + ")\n");

            return (int) currQueue[queueSize-1];
        }

        @Override
        public void run() {

            println(TAG.SEND + "  : Ack_Handler running...");

            TcpPacket payload = new TcpPacket();
            payload.setSrcPort(listenSock.getLocalPort());
            payload.setDestPort(remotePort);
            payload.setAck(true);
            byte[] buff = new byte[0];
            int overflowCount = 0;

            while (true) {

                if (ackQueue.size() == 0)
                    continue;

                payload.setSeqNum(receiverSeqNum);

                /* check for timeout */
                if (timer.timeoutEvent) {
                    println(TAG.SEND + "  : Detected timeoutEvent." +
                            " Resending last sent ACK# --> " + lastAckSent);
                    payload.setAckNum(lastAckSent);
                } else {
                    payload.setAckNum(dequeueAck());
                }

                /* encode the payload */
                try {
                    buff = payload.encode();
                } catch (Exception e) {
                    kill("ERROR: Failed to encode ACK: " + e.getCause());
                }

                /* send the packet */
                if (sendPacket(buff)) {

                    /* prevent overflow attack */
                    if ((lastAckSent == payload.getAckNum()) &&
                        (++overflowCount >= MAXOVERFLOW))
                        kill("ERROR: Network error - Packet overflow.");

                    /* update fields */
                    lastAckSent = payload.getAckNum();
                    acksSent++;

                    /* start the timer if it's not running */
                    if (!timer.running)
                        timer.startTimer(lastAckSent);

                    /* break if final ACK has been sent */
                    if (finRecv && (remoteFsn >= 0) &&
                       (lastAckSent >= remoteFsn))
                        break;
                }
            }

            println(TAG.SEND + "  : AckHandler complete.");
        }
    }

    /**
     * Creates a TCP_packet object.
     * @param opt : 1 - create ACK packet.
     *            : 2 - create SYN/ACK packet.
     *            : 3 - create FIN/ACK packet.
     *            : 4 - create FIN packet.
     *            
     * @return    : TcpPacket encoded as an array of bytes.
     */
    private byte[] makePacket(int opt, int seq_num, int ack_num) {

        TcpPacket payload = new TcpPacket();
        payload.setSrcPort(listenSock.getLocalPort());
        payload.setDestPort(remotePort);

        /* set flags */
        if (opt == 1 || opt == 2 || opt == 3) {
            payload.setAck(true);
            payload.setAckNum(ack_num);
        }

        if (opt == 2 || opt == 3 || opt == 4) {
            payload.setSeqNum(seq_num);
            if (opt == 2)
                payload.setSyn(true);
            else
                payload.setFin(true);
        }

        /* encode and return */
        try {
            return payload.encode();
        } catch (Exception e) {
            if (debugMode)
                e.printStackTrace();
            return null;
        }
    }

    @Override
    protected void instHandlers() {

        ah = new AckHandler();
        ah.setName("AckHandler Thread");
        threads.add(ah);

        dh = new DataHandler();
        dh.setName("DataHandler Thread");
        threads.add(dh);
    }

    @Override
    protected void startHandlers() {

        dh.start();
        ah.start();
        try {
            dh.join();
            ah.join();
        } catch (InterruptedException e) {
            kill("ERROR: Unable to complete file transfer!");
            if (debugMode)
                e.printStackTrace();
        }
    }

    @Override
    protected void connect() {

        TcpPacket payload;
        byte[] buff;

        /* receive SYN */
        while (true) {
            payload = receivePacket(DEFTCPHEAD);
            if (payload != null && payload.getSyn()) {
                remoteIsn = payload.getSeqNum();
                println(TAG.SYNC + "  : Received SYN --> seq# " + remoteIsn);
                log(payload);
                break;
            }
        }

        /* make SYN/ACK */
        buff = makePacket(2, memberIsn, (remoteIsn + 1));
        if (buff == null)
            kill("ERROR: Failed to make SYN/ACK.");

        /* send SYN/ACK */
        while (true) {
            if (sendPacket(buff)) {
                println(TAG.SYNC + "  : SYN/ACK sent --> seq# " + memberIsn +
                        " / ack# " + (remoteIsn + 1));
                timer.startTimer(memberIsn);
                break;
            }
        }

        /* receive ACK */
        while (true) {
            payload = receivePacket(DEFTCPHEAD);
            if ((payload != null) && payload.getAck() &&
                (payload.getAckNum() == (memberIsn + 1))) {
                println(TAG.SYNC + "  : Received ACK --> ack# " + 
                	   (memberIsn + 1));
                timer.stopTimer(memberIsn + 1);
                log(payload);
                break;
            }
        }
    }

    @Override
    protected void disconnect() {

        /* stop the timer if it's still running */
        if (timer.running)
            timer.stopTimer(timer.seqNum);

        /* make FIN */
        byte[] buff = makePacket(4, receiverSeqNum, 0);
        if (buff == null)
            kill("ERROR: Failed to make FIN.");

        /* send FIN */
        while (true) {
            if (sendPacket(buff)) {
                println(TAG.CLOSE + " : Sent FIN --> seq# " + receiverSeqNum);
                timer.startTimer(receiverSeqNum);
                break;
            }
        }

        TcpPacket payload;
        boolean successful = false;

        /* receive FIN/ACK */
        while (true) {
            try {
                payload = receivePacket(DEFTCPHEAD);
                if ((payload != null) && payload.getAck() &&
                        (payload.getAckNum() == (receiverSeqNum + 1))) {
                    println(TAG.CLOSE + " : Received FIN/ACK --> seq# " +
                            payload.getSeqNum() + " / ack# " +
                            payload.getAckNum());
                    timer.stopTimer(receiverSeqNum + 1, true);
                    log(payload);
                    successful = true;
                    break;
                }
            } catch (Exception ignored) {}
        }

        String msg = successful ? "Connection closed."
                     : "Connection closed improperly.";

        System.out.println(getTimestamp() + ": " + msg +
                " File transfer completed successfully.");
    }

    @Override
    protected void printStats() {

        long transTimeSec = TimeUnit.MILLISECONDS.toSeconds(endTime-startTime);

        System.out.println(
                "=============================" +
                "============================" +
                "\n\t\t\tFILE TRANSFER STATISTICS" +
                "\nFile transfer time: (" + transTimeSec + ") seconds" +
                "\nReceived file size: (" + bytesTrans + ") bytes" +
                "\nEnding timeout: " + timer.timeout + " ms" +
                "\nEnding est_RTT: " + timer.estRtt + " ms" +
                "\nEnding dev_RTT: " + timer.devRtt + " ms" +
                "\n(" + received.size() + ") valid segments received " +
                "\n(" + corrupted + ") corrupted segments received" +
                "\n(" + duplicates + ") duplicate segments received " +
                "\n(" + acksSent + ") ACKs sent" +
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

        if (((args.length != 6) ||
                !args[5].equals("debug")) && (args.length != 5)) {

            System.out.println("Usage: RdtReceiver <filename> " +
                    "<log_filename> <sender_IP> <sender_port> " +
                    "<listening_port> optional: <debug>");
            System.exit(-1);
        }
        new RdtReceiver(args, (args.length == 6));
    }
}
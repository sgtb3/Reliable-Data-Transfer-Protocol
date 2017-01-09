import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class RdtSender extends RdtProtocol {

    private boolean finSent;
    private boolean finAckRecv;
    private int base;
    private int paddingBytes;
    private AckHandler ah;
    private DataHandler dh;
    private ConcurrentHashMap<Integer, Segment> segments;

    /**
     * Constructs a new Sender.
     * 
     * @param args  : The CL args.
     * @param debug : True - for debugging mode.
     *              : False - otherwise
     */
    private RdtSender(String[] args, boolean debug) {
        super(args, debug);
    }

    /** Handles the Sender's outgoing actions (sending data). */
    private class DataHandler extends Thread {

        @Override
        public void run() {

            println(TAG.SEND + "  : DataHandler running ...");

            int overflowCount = 0;
            int prevSeqNum = -1;
            int currSeqNum;
            int currSegNum;
            int totalSegs = segments.size();
            Segment finalSeg = segments.get(totalSegs-1);
            Segment currSeg;
            byte[] buff;
            boolean isFinalSeg;

            while (true) {

                /* break if final data segment acknowledged */
                if (finalSeg.acked)
                    break;

                /* for concurrency issues, save current sequence number */
                currSeqNum = nextSeqNum;
                currSeg = findSegment(currSeqNum, 1);
                if (currSeg == null)
                    kill("ERROR: Failed to find " +
                         "packet with seq num (" + currSeqNum + ")");

                /* save corresponding segment number */
                currSegNum = currSeg.segNum;
                isFinalSeg = (currSegNum + 1) >= totalSegs;

                /*
                 * if final seg, make final payload with FIN flag set.
                 * otherwise, create non-FIN TCP payload with data
                 */
                buff = makePacket(isFinalSeg ? 4 : 3, currSeqNum, 0,
                       currSeg.getData());

                if (isFinalSeg) {

                    while (true) {

                        /* send the final segment */
                        if (!sendPacket(buff))
                            continue;

                        /* add to list of sent packets if needed */
                        if (!currSeg.sent)
                            bytesTrans += currSeg.getData().length;

                        /* start timer if it's not running */
                        if (!timer.running)
                            timer.startTimer(currSeqNum);

                        /* update fields */
                        currSeg.sent = true;
                        currSeg.timeSent = System.currentTimeMillis();
                        finSent = true;
                        println(TAG.SEND + "  : (FINAL) seq# --> " + 
                        		currSeqNum);

                        /* sleep for the maximum allowable time */
                        try {
                            sleep(timer.timeout);
                        } catch (InterruptedException ignored) {}

                        /* break if final segment has been acked */
                        if (currSeg.acked)
                            break;
                    }

                } else {

                    /* check if sequence number is withing max window size */
                    if (currSeqNum >= (base + windowSize)) {

                        try {
                            println(TAG.SEND + 
                            		"  : |====> MAXIMUM WINDOW SIZE <====|");
                            sleep(timer.timeout);
                        } catch (InterruptedException ignored) {}

                        /* check if timeout event has occurred during sleep */
                        if (timer.timeoutEvent) {
                            nextSeqNum = base;
                            println(TAG.SEND + "  : Detected timeoutEvent. " +
                                    "Resending all packets starting with " + 
                                    "base --> seq# " + base);

                        } else if ((prevSeqNum == currSeqNum) &&
                                   (++overflowCount >= MAXOVERFLOW)) {
                            /* prevent packet overflow attack */
                            kill("ERROR: Network error - Packet overflow.");
                        }
                        continue;
                    }

                    /* send non-final data packet */
                    if (!sendPacket(buff))
                        continue;

                    /* add to list of sent packets if needed */
                    if (!currSeg.sent)
                        bytesTrans += currSeg.getData().length;

                    /* update segment fields */
                    currSeg.sent = true;
                    currSeg.timeSent = System.currentTimeMillis();

                    /* start the timer if it's not running */
                    if (!timer.running)
                        timer.startTimer(currSeqNum);

                    println(TAG.SEND + "  : --> seq# " + currSeqNum);

                    /* increment next sequence number */
                    try {
                        nextSeqNum = segments.get(currSegNum + 1).seqNum;
                    } catch (NullPointerException e) {
                        if (finAckRecv)
                            break;
                    }
                }
            }

            println(TAG.SEND + "  : DataHandler complete.");
        }
    }

    /** Handles the Sender's incoming actions (receiving acknowledgements). */
    private class AckHandler extends Thread {

        /**
         * Simulates the TCP fast retransmit mechanism.
         * 
         * @param currAck : The ACK num to be retransmitted.
         */
        private void fastRetransmit(int currAck) {

            /* find corresponding segment */
            Segment retransSeg = findSegment(currAck, 1);

            if (retransSeg == null)
                kill("ERROR. Failed to find segment in map!");

            if (retransSeg.segNum < 0)
                return;

            /* update the next sequence number */
            nextSeqNum = currAck;

            println(TAG.RECV + "  : 3 duplicate ACKs received. Retransmitting" +
                    " all packets starting with seq# " + currAck + " -->" +
                    " (packet " + retransSeg.segNum + ")");

            /* update retransmission fields */
            if (!retransSeg.retrans) {
                retransSeg.retrans = true;
                retransSeg.retransCount++;
            }
        }

        @Override
        public void run() {

            println(TAG.RECV + "  : Ack_Handler running...");

            TcpPacket payload;
            int prevAck;
            int currAck;
            int finalAckNum = segments.get(segments.size()-1).ackNum;
            int prevAckRetrans = -1;
            int overflowCount = 0;

            while (true) {

                /* break if final segment acknowledged */
                if (finAckRecv)
                    break;

                /* receive packet */
                payload = receivePacket(DEFTCPHEAD);
                if (payload == null)
                    continue;

                /* get packet ack number */
                currAck = payload.getAckNum();
                prevAck = currAck;

                /* check if valid ack number */
                Segment recvSeg = findSegment(currAck, 2);
                
                if (recvSeg == null) {

                    println(TAG.RECV + "  : (Unknown) <-- ack# " +
                            currAck + "  : " + payload);

                    /* prevent overflow from unknown ACKs */
                    if ((currAck == prevAck) && 
                    	(++overflowCount > MAXOVERFLOW))
                        kill("ERROR: Network error - Packet overflow.");
                    continue;
                }

                /* check for duplicate ACKs */
                if (currAck == prevAck) {

                    println(TAG.RECV + "  : <-- ack# " + currAck +
                            " (Duplicate x" + (++recvSeg.ackCount) + ")");

                    /* if segment has been ACKed @ least 3 times in a row */
                    if (recvSeg.ackCount >= 3) {

                        /* prevent overflow from repeated ACKs */
                        if (recvSeg.ackCount >= MAXOVERFLOW)
                            kill("ERROR: Network error - Packet overflow.");

                        /* if timer is not running for a retransmitted ACK */
                        if ((prevAckRetrans != currAck) && !timer.running || 
                        	(timer.seqNum != currAck)) {

                            println(TAG.RECV + 
                            		"  : Calling fast retransmit... ");

                            fastRetransmit(currAck);
                           
                            /* reset the duplicate ack count */
                            recvSeg.ackCount = 0;
                            prevAckRetrans = currAck;
                        }

                        continue;
                    }
                }

                /* if final ACK */
                if (finSent && (currAck >= finalAckNum)) {
                    println(TAG.RECV + "  : <-- (FINAL) ack# " + currAck);
                    finAckRecv = true;
                } else if (!recvSeg.sent) {
                    println(TAG.RECV + "  : ACK (ack# " + currAck + 
                    		") doesn't correspond to any transmitted seqNum");
                    continue;
                }

                /* start timer if it's not running */
                if (!timer.running ||
                   ((timer.seqNum < currAck) && !finAckRecv))
                    timer.startTimer(base);

                if ((currAck < finalAckNum) && !finAckRecv)
                    println(TAG.RECV + "  : <-- ack# " + currAck);

                /* update the base flag */
                base = currAck;
                if (!recvSeg.base)
                    recvSeg.base = true;

                /* update the acked flag and timestamp, log packet */
                if (!recvSeg.acked) {
                    recvSeg.acked = true;
                    log(payload);
                }

                recvSeg.timeAcked = System.currentTimeMillis();
            }

            println(TAG.RECV + "  : AckHandler complete.");
        }
    }

    /**
     * Segments the data file into MSS sized chunks and
     * places them in the segment hash map.
     */
    private void segmentFile() {

        try {

            byte[] fileBytes = Files.readAllBytes(Paths.
                                get(dataFile.getAbsolutePath()));
            int remaining = fileBytes.length;
            int approxSize = Math.round(remaining/(MSS- DEFTCPHEAD)) + 1;
            segments = new ConcurrentHashMap<>(approxSize);

            int totalRead = 0;
            int fileIndex = 0; /* i.e. seq number */
            int mapIndex  = 0; /* i.e. seg number */
            int segIndex;
            byte[] data;
            Segment seg;

            while (remaining > 0) {

                seg  = new Segment(mapIndex, fileIndex);
                data = new byte[(MSS- DEFTCPHEAD)];
                segIndex = 0;

                while ((segIndex < remaining) && (segIndex < data.length))
                    data[segIndex++] = fileBytes[fileIndex++];

                remaining -= segIndex;
                totalRead += data.length;
                seg.setData(data);
                segments.put(mapIndex++, seg);
            }

            paddingBytes = (int) (totalRead - dataFile.length());

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
     * @return    : TcpPacket encoded as a byte array.
     */
    private byte[] makePacket(int opt, int seqNum, int ackNum, byte[] data) {

        TcpPacket payload = new TcpPacket();
        payload.setSrcPort(listenSock.getLocalPort());
        payload.setDestPort(remotePort);
        payload.setSeqNum(seqNum);
        payload.setAckNum(ackNum);

        /* set flags */
        if (opt == 1)
            payload.setSyn(true);
        
        if (opt == 2 || opt == 6)
            payload.setAck(true);
        
        if (opt == 4 || opt == 5 || opt == 6) {
            payload.setFin(true);
            if (opt != 6 && paddingBytes != 0)
                payload.setOptions(payload.intToBytes(paddingBytes));
        }

        if (opt == 7)
            payload.setRst(true);

        /* if packet contains data and options if necessary */
        if ((opt == 3 || opt == 4) && data != null)
            payload.setData(data);

        /* encode and return packet */
        try {
            return payload.encode();
        } catch (Exception e) {
            if (debugMode)
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
    private ArrayList<Integer> getSeqNumbers(int opt) {

        ArrayList<Integer> list = new ArrayList<>();
        for (Integer entry : segments.keySet()) {

            if (((opt == 1) && segments.get(entry).sent) ||
                ((opt == 2) && segments.get(entry).acked) ||
                ((opt == 3) && segments.get(entry).retrans) ||
                ((opt == 4) && segments.get(entry).base))
                list.add(segments.get(entry).seqNum);
        }

        return list;
    }

    /**
     * Searches the segment map for a segment.
     * @param num     : The corresponding sequence or ACK number.
     * @param opt     : 1 - search by seqNum
     *                : 2 - search by ackNum
     *                
     * @return        : The Segment contained in the map, if it exists.
     *                : Null, otherwise.
     */
    private Segment findSegment(int num, int opt) {

        if (opt == 1) {
            for (Integer entry : segments.keySet()) {
                if (segments.get(entry).seqNum == num)
                    return segments.get(entry);
            }
        } else if (opt == 2) {
            for (Integer entry : segments.keySet()) {
                if (segments.get(entry).ackNum == num)
                    return segments.get(entry);
            }
        }

        return null;
    }

    @Override
    protected void instHandlers() {

        /* segment the file before instantiating handlers */
        segmentFile();

        ah = new AckHandler();
        ah.setName("AckHandler Thread");
        threads.add(ah);

        dh = new DataHandler();
        dh.setName("DataHandler Thread");
        threads.add(dh);
    }

    @Override
    protected void startHandlers() {

        ah.start();
        dh.start();

        try {
            dh.join();
        } catch (InterruptedException e) {
            kill("ERROR: Unable to complete file transfer!");
            if (debugMode)
                e.printStackTrace();
        }
    }

    @Override
    protected void connect() {

        TcpPacket payload;
        
        /* make SYN */
        byte[] buff = makePacket(1, memberIsn, 0, null);
        if (buff == null)
            kill("ERROR: Failed to make SYN.");
        
        /* send SYN */
        while (true) {
            if (sendPacket(buff)) {
                println(TAG.SYNC + "  : SYN sent --> seq# " + memberIsn);
                timer.startTimer(memberIsn);
                break;
            }
        }

        /* receive SYN/ACK */
        while (true) {
            payload = receivePacket(DEFTCPHEAD);
            if ((payload != null) && payload.getSyn() && payload.getAck() &&
                (payload.getAckNum() == (memberIsn +1))) {
                remoteIsn = payload.getSeqNum();
                println(TAG.SYNC + "  : Received SYN/ACK --> seq# "
                        + remoteIsn + " / ack# " + (memberIsn +1));
                timer.stopTimer((memberIsn +1), true);
                log(payload);
                break;
            }
        }

        /* make ACK */
        buff = makePacket(2, (memberIsn + 1), (remoteIsn + 1), null);
        if (buff == null)
            kill("ERROR: Failed to make ACK.");

        /* send ACK */
        while (true) {
            if (sendPacket(buff)) {
                println(TAG.SYNC + "  : Sent ACK --> ack# " + (memberIsn + 1));
                timer.startTimer(memberIsn +1);
                break;
            }
        }

        /* reset the timer for data transfer */
        timer.stopTimer(memberIsn +1, true);
        timer.seqNum = -1;
    }

    @Override
    protected void disconnect() {

        /* stop the timer if it's still running */
        if (timer.running) {
            Segment seg = findSegment(timer.seqNum, 1);
            if (seg != null && !seg.retrans)
                timer.stopTimer(timer.seqNum, true);
            else
                timer.stopTimer(timer.seqNum);
        }

        TcpPacket payload;
        int remoteFsn;

        /* receive FIN */
        while (true) {
            payload = receivePacket(DEFTCPHEAD);
            if ((payload != null) && payload.getFin()) {
                remoteFsn = payload.getSeqNum();
                println(TAG.CLOSE + " : Received FIN --> seq# " + remoteFsn);
                log(payload);
                break;
            }
        }

        /* make FIN/ACK */
        byte[] buff = makePacket(6, ++nextSeqNum, ++remoteFsn, null);
        if (buff == null)
            kill("ERROR: Failed to make Receiver's FIN/ACK.");

        /* send FIN/ACK */
        while (true) {
            if (sendPacket(buff)) {
                timer.startTimer(nextSeqNum);
                println(TAG.CLOSE + " : Sent FIN/ACK --> seq# " + nextSeqNum +
                        " / ack# " + remoteFsn);
                break;
            }
        }

        /* wait for final timeout */
        boolean successful = true;
        while (true) {
            if (!timer.timeoutEvent && (timer.timeRemaining > 0)) {
                payload = receivePacket(DEFTCPHEAD);
                if (payload != null)
                    successful = false;
            } else {
                println(TAG.CLOSE + " : No further data from Receiver.");
                break;
            }
        }

        String msg = successful ? "Connection closed."
                     : "Connection closed improperly.";

        System.out.println(getTimestamp() + ": " + msg +
                " File transfer completed successfully.");
    }

    @Override
    protected void printStats() {

        long transTimeSec = TimeUnit.MILLISECONDS.toSeconds(endTime-startTime);
        ArrayList<Integer> sent  = getSeqNumbers(1);
        ArrayList<Integer> acked = getSeqNumbers(2);

        System.out.println(
                "=============================" +
                "============================" +
                "\n\t\t\tFILE TRANSFER STATISTICS" +
                "\nFile transfer time: (" + transTimeSec + ") seconds" +
                "\nFile size: (" + dataFile.length() + ") bytes" +
                "\n(" + bytesTrans + ") bytes sent" +
                "\nFinal segment padded with (" + paddingBytes + ") bytes" +
                "\nEnding timeout: " + timer.timeout + " ms" +
                "\nEnding est_RTT: " + timer.estRtt + " ms" +
                "\nEnding dev_RTT: " + timer.devRtt + " ms" +
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

            System.out.println("Usage: RdtSender <filename> <log_filename> " +
                    "<receiver_IP> <receiver_port> <listening_port>  " +
                    "<windowSize> optional: <debug>");
            System.exit(-1);
        }
        new RdtSender(args, (args.length == 7));
    }
}

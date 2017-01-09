import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class TcpPacket {

    /* Default TCP header size without any options or data (in 32-bit words) */
    private static final int DEFHEADLEN = 5;
    private int srcPort;
    private int destPort;
    private int seqNum;
    private int ackNum;
    private int headLen;
    private int recvWin;
    private short checksum;
    private int urgData;
    private boolean URG;
    private boolean ACK;
    private boolean PSH;
    private boolean RST;
    private boolean SYN;
    private boolean FIN;
    private byte[] data;
    private byte[] options;
    private byte[] segment;

    /** Constructs a new TcpPacket object. */
    public TcpPacket() {

        srcPort = 0;
        destPort = 0;
        seqNum = 0;
        ackNum = 0;
        headLen = DEFHEADLEN;
        recvWin = 0;
        urgData = 0;
        URG = false;
        ACK = false;
        PSH = false;
        RST = false;
        SYN = false;
        FIN = false;
        data = new byte[0];
        options = new byte[0];
        segment = new byte[0];
    }

    /**
     * Constructs a new TcpPacket object given the packet fields.
     *
     * @param srcPort  : The source port.
     * @param destPort : The destination port.
     * @param seqNum   : The packet sequence number.
     * @param ackNum   : The acknowledgement number.
     * @param headLen  : The header length in 32-bit words.
     * @param urg      : The urgent data flag.
     * @param ack      : The acknowledgement flag.
     * @param psh      : The push flag.
     * @param rst      : The reset flag.
     * @param syn      : The synchronize flag.
     * @param fin      : The finished flag.
     * @param recvWin  : The receive window.
     * @param urgData  : The urgent data offset.
     * @param data     : The data bytes.
     * @param options  : The options.
     */
    public TcpPacket(int srcPort, int destPort, int seqNum, int ackNum,
                     int headLen, boolean urg, boolean ack, boolean psh,
                     boolean rst, boolean syn, boolean fin, int recvWin,
                     int urgData, byte[] data, byte[] options) {

        this.srcPort = srcPort;
        this.destPort = destPort;
        this.seqNum = seqNum;
        this.ackNum = ackNum;
        this.headLen = headLen;
        this.recvWin = recvWin;
        this.urgData = urgData;
        this.URG = urg;
        this.ACK = ack;
        this.PSH = psh;
        this.RST = rst;
        this.SYN = syn;
        this.FIN = fin;
        this.data = data;
        this.options = options;

        try {
            this.segment = encode();
        } catch (Exception e) {
            System.out.println("Error: Failed to encode segment. " +
                               "Cause: " + e.getCause());
        }
    }

    /**
     * Updates the header field.
     *
     * @param value : options + options padding.
     *
     * @throws Exception : If segment len exceeds 60 bytes.
     */
    private void updateHeader(int value) throws Exception {

        headLen = DEFHEADLEN + (value / 4);
        if (headLen > 15)
            throw new Exception("Segment length of " + headLen +
                    " bytes exceeds maximum of 15 32-bit words (60 bytes).");
    }

    /**
     * Creates a packet using pre-filled class fields.
     *
     * @return The byte[] segment.
     *
     * @throws Exception : If unable to encode TcpPacket.
     */
    public byte[] encode() throws Exception {

        try {

            /* default header length (in bytes) */
            int defHeadLen = (DEFHEADLEN * 4);

            /* if options are present or data requires padding */
            if ((options.length != 0) || ((data.length % 4) != 0)) {

                /* calculate the padding needed */
                byte optsPad = (byte) (4 - Math.ceil(
                                      (double) (2 + options.length) % 4));
                byte dataPad = (byte) (4 - Math.ceil(
                                      (double) (data.length) % 4));

                /* if data padding is a multiple of 4, zero it out */
                if ((dataPad % 4) == 0)
                    dataPad = 0;

                /* make a new segment, includes any additional padding bytes */
                int segSize = defHeadLen + 2 + options.length + optsPad +
                              data.length + dataPad;

                segment = new byte[segSize];

                /* update the header length field */
                int totalOptsLen = 2 + options.length + optsPad;

                updateHeader(totalOptsLen);

                /* set the values of options and data padding */
                segment[defHeadLen] = optsPad;
                segment[defHeadLen + 1] = dataPad;

                int optsEnd = (defHeadLen + 2) + options.length + optsPad;

                /* copy options and data into segment */
                System.arraycopy(options, 0, segment, (defHeadLen + 2),
                                 options.length);
                System.arraycopy(data, 0, segment, optsEnd, data.length);

            } else {

                /* update header length field and initialize a new segment */
                segment = new byte[defHeadLen + options.length + data.length];
                updateHeader(options.length);

                /* copy options and data into segment */
                System.arraycopy(options, 0, segment, defHeadLen,
                                 options.length);
                System.arraycopy(data, 0, segment,
                                (defHeadLen + options.length), data.length);
            }

            /* convert fields to byte arrays */
            byte[] sp = shortToBytes((short) srcPort);
            byte[] dp = shortToBytes((short) destPort);
            byte[] sn = intToBytes(seqNum);
            byte[] an = intToBytes(ackNum);
            byte[] hl = new byte[]{(byte) ((headLen << 4) & 0x1FFFFFFF)};
            byte[] rw = shortToBytes((short) recvWin);
            byte[] cs = shortToBytes((short) 0);
            byte[] ud = URG ? shortToBytes((short) urgData)
                        : new byte[]{0, 0};
            byte[] fl = flagsToByte();

            /* copy each field into the segment */
            System.arraycopy(sp, 0, segment, 0, sp.length);
            System.arraycopy(dp, 0, segment, 2, dp.length);
            System.arraycopy(sn, 0, segment, 4, sn.length);
            System.arraycopy(an, 0, segment, 8, an.length);
            System.arraycopy(hl, 0, segment, 12, hl.length);
            System.arraycopy(fl, 0, segment, 13, fl.length);
            System.arraycopy(rw, 0, segment, 14, rw.length);
            System.arraycopy(cs, 0, segment, 16, cs.length);
            System.arraycopy(ud, 0, segment, 18, ud.length);

            /* calculate the checksum and place it into the segment */
            checksum = calculateChecksum(segment);
            cs = shortToBytes(checksum);
            System.arraycopy(cs, 0, segment, 16, cs.length);

        } catch (Exception e) {
            throw new Exception ("Error: Failed to encode packet. " +
                                 "Cause: " + e.getCause());
        }

        return segment;
    }

    /**
     * Extract TcpPacket fields from array p.
     *
     * @param p : A byte array containing an encoded TcpPacket.
     *
     * @throws IllegalArgumentException : If segment length exceeds 60 bytes.
     * @throws Exception : If buffer p is not large enough to hold min header.
     */
    public void extract(byte[] p) throws Exception {

        segment = p;

        /* empty packet */
        if (p.length == 0)
            return;

        /* default header length (in bytes) */
        int defHeadLen = (DEFHEADLEN * 4);

        /*
         * if given buffer is not large enough to contain the minimum
         * 20 bytes of the TCP header.
         */
        if (p.length < defHeadLen)
            throw new Exception("Packet buffer length " +
                    "insufficient for a minimum TCP header.");

        /* shift header length (in 32-bit words) */
        headLen = (p[12] >>> 4) & 0x0000000F;

        if (p.length < headLen * 4)
            throw new IllegalArgumentException("Segment length of "
                    + headLen + " bytes exceeds maximum " +
                    "of 15 32-bit words (60 bytes).");

        /* copy default fields */
        srcPort = bytesToShort(new byte[]{p[0], p[1]});
        destPort = bytesToShort(new byte[]{p[2], p[3]});
        seqNum = bytesToInt(new byte[]{p[4], p[5], p[6], p[7]});
        ackNum = bytesToInt(new byte[]{p[8], p[9], p[10], p[11]});
        recvWin = bytesToShort(new byte[]{p[14], p[15]});
        checksum = bytesToShort(new byte[]{p[16], p[17]});
        urgData = bytesToShort(new byte[]{p[18], p[19]});

        /* extract the flags */
        URG = (p[13] & 0x20) == 0x20;
        ACK = (p[13] & 0x10) == 0x10;
        PSH = (p[13] & 0x08) == 0x08;
        RST = (p[13] & 0x04) == 0x04;
        SYN = (p[13] & 0x02) == 0x02;
        FIN = (p[13] & 0x01) == 0x01;

        options = new byte[0];
        data = new byte[0];

        /* handle options */
        if (headLen > 5) {

            byte optsPad = p[defHeadLen];
            byte dataPad = p[defHeadLen + 1];

            if (optsPad != 0) {

                int optsBeg = defHeadLen + 2;
                int optsEnd = (headLen * 4) - optsPad;
                int optsLen = optsEnd - optsBeg;

                /* if there are any actual options */
                if (optsLen != 0) {
                    options = new byte[optsLen];
                    int j = 0;
                    for (int i = optsBeg; i < optsEnd; i++, j++)
                        options[j] = p[i];
                }

                int dataBeg = headLen * 4;
                int dataEnd = p.length - dataPad;
                int dataLen = dataEnd - dataBeg;

                /* if there is any data */
                if (dataLen != 0) {
                    data = new byte[dataLen];
                    int j = 0;
                    for (int i = dataBeg; i < dataEnd; i++, j++)
                        data[j] = p[i];
                }
            }

        } else if (p.length - (headLen * 4) != 0) {

            data = new byte[p.length - (headLen * 4)];
            System.arraycopy(p, headLen * 4, data, 0, data.length);
        }

    }

    /**
     * Converts an array of four bytes into an integer.
     *
     * @param bytes : The bytes to be converted to an integer.
     *
     * @return The equivalent integer value.
     */
    public int bytesToInt(byte[] bytes) {

        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.order(ByteOrder.BIG_ENDIAN);
        bb.put(bytes[0]);
        bb.put(bytes[1]);
        bb.put(bytes[2]);
        bb.put(bytes[3]);
        return bb.getInt(0);
    }

    /**
     * Converts an array of two bytes into a short.
     *
     * @param bytes : The bytes to be converted to a short value.
     *
     * @return The equivalent short value.
     */
    public short bytesToShort(byte[] bytes) {

        ByteBuffer bb = ByteBuffer.allocate(2);
        bb.order(ByteOrder.BIG_ENDIAN);
        bb.put(bytes[0]);
        bb.put(bytes[1]);
        return bb.getShort(0);
    }

    /**
     * Converts an array of four bytes into an integer.
     *
     * @param num : The integer to be converted.
     *
     * @return An array of four bytes containing the integer value.
     */
    public byte[] intToBytes(int num) {
        return ByteBuffer.allocate(4).
                order(ByteOrder.BIG_ENDIAN).putInt(num).array();
    }

    /**
     * Converts a short to an array of two bytes.
     *
     * @param value : The short value.
     *
     * @return An array of two bytes containing the short value.
     */
    public byte[] shortToBytes(short value) {
        return ByteBuffer.allocate(2).
                order(ByteOrder.BIG_ENDIAN).putShort(value).array();
    }

    /**
     * Calculates the 16-bit 1's complement checksum.
     *
     * @param bytes : The bytes to be checksumed.
     *
     * @return The checksum value.
     */
    public short calculateChecksum(byte[] bytes) {

        if ((bytes.length & 1) == 0) {

            int sum = 0;
            int i = 0;

            while (i < bytes.length)
                sum += ((bytes[i++] & 0xFF) << 8) | ((bytes[i++] & 0xFF));

            sum = ((sum) & 0xFFFF) + ((sum >> 16) & 0xFFFF);
            return (short) ~sum;
        }

        throw new IllegalArgumentException("Insufficient buffer size.");
    }

    /**
     * Converts the TCP flags into a byte.
     *
     * @return The one-byte array containing the TCP flag values.
     */
    private byte[] flagsToByte() {

        int val = 0;
        val += URG ? 32 : 0;
        val += ACK ? 16 : 0;
        val += PSH ? 8 : 0;
        val += RST ? 4 : 0;
        val += SYN ? 2 : 0;
        val += FIN ? 1 : 0;
        return new byte[]{(byte) val};
    }

    @Override
    public String toString() {

        return "Packet {\n" +
                "\t\t\t[Src port   = " + srcPort + "]" +
                "\t[Dest port = " + destPort + "]\n" +
                "\t\t\t[Seq num    = " + seqNum + "]\n" +
                "\t\t\t[Ack num    = " + ackNum + "]\n" +
                "\t\t\t[Header len = " + headLen + "]" +
                "\t\t[URG = " + (URG ? 1 : 0) + ", " +
                "ACK = " + (ACK ? 1 : 0) + ", " +
                "PSH = " + (PSH ? 1 : 0) + ", " +
                "RST = " + (RST ? 1 : 0) + ", " +
                "SYN = " + (SYN ? 1 : 0) + ", " +
                "FIN = " + (FIN ? 1 : 0) + "]"  +
                "\t[Recv win = " + recvWin + "]\n" +
                "\t\t\t[Checksum   = " + checksum + "]" +
                "\t[Urg data offset = " +
                (urgData < 0 ? "null" : urgData) + "]\n" +
                "\t\t\t[Options    = " + Arrays.toString(options) + "]\n" +
                "\t\t\t[Data    ("+ data.length +" bytes) = " +
                        Arrays.toString(data) + "]\n" +
                "\t\t\t[Segment ("+ segment.length +" bytes) = " +
                        Arrays.toString(segment) + "]\n" +
                "\t\t\t}";
    }

    public int getSrcPort() {
        return srcPort;
    }

    public void setSrcPort(int srcPort) {
        this.srcPort = srcPort;
    }

    public int getDestPort() {
        return destPort;
    }

    public void setDestPort(int destPort) {
        this.destPort = destPort;
    }

    public int getSeqNum() {
        return seqNum;
    }

    public void setSeqNum(int seqNum) {
        this.seqNum = seqNum;
    }

    public int getAckNum() {
        return ackNum;
    }

    public void setAckNum(int ackNum) {
        this.ackNum = ackNum;
    }

    public int getHeadLen() {
        return (headLen << 2);
    }

    public void setHeadLen(int headLen) {
        this.headLen = headLen;
    }

    public boolean getUrg() {
        return URG;
    }

    public void setUrg(boolean urg) {
        this.URG = urg;
    }

    public boolean getAck() {
        return ACK;
    }

    public void setAck(boolean ack) {
        this.ACK = ack;
    }

    public boolean getPsh() {
        return PSH;
    }

    public void setPsh(boolean psh) {
        this.PSH = psh;
    }

    public boolean getRst() {
        return RST;
    }

    public void setRst(boolean rst) {
        this.RST = rst;
    }

    public boolean getSyn() {
        return SYN;
    }

    public void setSyn(boolean syn) {
        this.SYN = syn;
    }

    public boolean getFin() {
        return FIN;
    }

    public void setFin(boolean fin) {
        this.FIN = fin;
    }

    public byte[] getOptions() {
        return options;
    }

    public void setOptions(byte[] options) {
        this.options = options;
    }

    public int getRecvWin() {
        return recvWin;
    }

    public void setRecvWin(int recvWin) {
        this.recvWin = recvWin;
    }

    public short getChecksum() {
        return checksum;
    }

    public void setChecksum(short checksum) {
        this.checksum = checksum;
    }

    public int getUrgData() {
        return urgData;
    }

    public void setUrgData(int urgData) {
        this.urgData = urgData;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public byte[] getSegment() {
        return segment;
    }

    public void setSegment(byte[] segment) {
        this.segment = segment;
    }

    /** Tester */
    public static void main(String[] args) {

        TcpPacket p = new TcpPacket();
        p.setSrcPort(1098);
        p.setDestPort(1099);
        p.setSeqNum(2);
        p.setAckNum(4);
        p.setUrg(true);
        p.setAck(true);
        p.setRst(true);
        p.setFin(true);
        p.setRecvWin(1152);
        p.setUrgData((short) 5);
        p.setData("abcdefghijklmnopqrstuvwxyzzzza".getBytes());
        p.setOptions(new byte[] {1,2,3});

        try {
            byte[] pSegment = p.encode();
            System.out.println(p);

            TcpPacket p2 = new TcpPacket();
            p2.extract(pSegment);
            System.out.println(p2);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
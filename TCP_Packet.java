import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class TCP_Packet {

    /* Default TCP header size without any options or data (in 32-bit words) */
    private static final int DEFAULT_HEAD_LEN = 5;
    private int src_port;
    private int dest_port;
    private int seq_num;
    private int ack_num;
    private int head_len;
    private int recv_win;
    private short checksum;
    private int urg_data;
    private boolean URG;
    private boolean ACK;
    private boolean PSH;
    private boolean RST;
    private boolean SYN;
    private boolean FIN;
    private byte[] data;
    private byte[] options;
    private byte[] segment;

    /**
     * Constructs a new TCP_Packet object.
     */
    public TCP_Packet() {

        src_port = 0;
        dest_port = 0;
        seq_num = 0;
        ack_num = 0;
        head_len = DEFAULT_HEAD_LEN;
        recv_win = 0;
        urg_data = 0;
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
     * Constructs a new TCP_Packet object given the packet fields.
     *
     * @param src_port   : The source port.
     * @param dest_port  : The destination port.
     * @param seq_num    : The packet sequence number.
     * @param ack_num    : The acknowledgement number.
     * @param head_len   : The header length in 32-bit words.
     * @param URG        : The urgent data flag.
     * @param ACK        : The acknowledgement flag.
     * @param PSH        : The push flag.
     * @param RST        : The reset flag.
     * @param SYN        : The synchronize flag.
     * @param FIN        : The finished flag.
     * @param recv_win   : The receive window.
     * @param urg_data   : The urgent data offset.
     * @param data       : The data bytes.
     * @param options    : The options.
     */
    public TCP_Packet(int src_port, int dest_port, int seq_num, int ack_num,
                      int head_len, boolean URG, boolean ACK, boolean PSH,
                      boolean RST, boolean SYN, boolean FIN, int recv_win,
                      int urg_data, byte[] data, byte[] options) {

        this.src_port = src_port;
        this.dest_port = dest_port;
        this.seq_num = seq_num;
        this.ack_num = ack_num;
        this.head_len = head_len;
        this.recv_win = recv_win;
        this.urg_data = urg_data;
        this.URG = URG;
        this.ACK = ACK;
        this.PSH = PSH;
        this.RST = RST;
        this.SYN = SYN;
        this.FIN = FIN;
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
    private void update_header(int value) throws Exception {
        head_len = DEFAULT_HEAD_LEN + (value / 4);
        if (head_len > 15)
            throw new Exception("Segment length of " + head_len +
                    " bytes exceeds maximum of 15 32-bit words (60 bytes).");
    }

    /**
     * Creates a packet using pre-filled class fields.
     *
     * @return The byte[] segment.
     *
     * @throws Exception : If unable to encode TCP_Packet.
     */
    public byte[] encode() throws Exception {

        try {

            /* default header length (in bytes) */
            int def_head_len = (DEFAULT_HEAD_LEN * 4);

            /* if options are present or data requires padding */
            if ((options.length != 0) || ((data.length % 4) != 0)) {

                /* calculate the padding needed */
                byte opts_pad = (byte) (4 - Math.ceil(
                                       (double) (2 + options.length) % 4));
                byte data_pad = (byte) (4 - Math.ceil(
                                       (double) (data.length) % 4));

                /* if data padding is a multiple of 4, zero it out */
                if ((data_pad % 4) == 0)
                    data_pad = 0;

                /* make a new segment, includes any additional padding bytes */
                int seg_size = def_head_len + 2 + options.length + opts_pad +
                               data.length + data_pad;

                segment = new byte[seg_size];

                /* update the header length field */
                int total_opts_len = 2 + options.length + opts_pad;
                update_header(total_opts_len);

                /* set the values of options and data padding */
                segment[def_head_len] = opts_pad;
                segment[def_head_len + 1] = data_pad;


                int opts_end = (def_head_len + 2) + options.length + opts_pad;

                /* copy options and data into segment */
                System.arraycopy(options, 0, segment, (def_head_len + 2),
                                 options.length);
                System.arraycopy(data, 0, segment, opts_end, data.length);

            } else {

                /* update header length field and initialize a new segment */
                segment = new byte[def_head_len + options.length + data.length];
                update_header(options.length);

                /* copy options and data into segment */
                System.arraycopy(options, 0, segment, def_head_len,
                                 options.length);
                System.arraycopy(data, 0, segment,
                                (def_head_len + options.length), data.length);
            }

            /* convert fields to byte arrays */
            byte[] sp = short_to_bytes((short) src_port);
            byte[] dp = short_to_bytes((short) dest_port);
            byte[] sn = int_to_bytes(seq_num);
            byte[] an = int_to_bytes(ack_num);
            byte[] hl = new byte[]{(byte) ((head_len << 4) & 0x1FFFFFFF)};
            byte[] rw = short_to_bytes((short) recv_win);
            byte[] cs = short_to_bytes((short) 0);
            byte[] ud = URG ? short_to_bytes((short) urg_data)
                        : new byte[]{0, 0};
            byte[] fl = flags_to_byte();

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
            checksum = calculate_checksum(segment);
            cs = short_to_bytes(checksum);
            System.arraycopy(cs, 0, segment, 16, cs.length);

        } catch (Exception e) {
            throw new Exception ("Error: Failed to encode packet. " +
                                 "Cause: " + e.getCause());
        }

        return segment;
    }

    /**
     * Extract TCP_Packet fields from array p.
     *
     * @param p : A byte array containing an encoded TCP_Packet.
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
        int def_head_len = (DEFAULT_HEAD_LEN * 4);

        /*
         * if given buffer is not large enough to contain the minimum
         * 20 bytes of the TCP header.
         */
        if (p.length < def_head_len)
            throw new Exception("Packet buffer length " +
                    "insufficient for a minimum TCP header.");

        /* shift header length (in 32-bit words) */
        head_len = (p[12] >>> 4) & 0x0000000F;

        if (p.length < head_len * 4)
            throw new IllegalArgumentException("Segment length of "
                    + head_len + " bytes exceeds maximum " +
                    "of 15 32-bit words (60 bytes).");

        /* copy default fields */
        src_port  = bytes_to_short(new byte[]{p[0], p[1]});
        dest_port = bytes_to_short(new byte[]{p[2], p[3]});
        seq_num = bytes_to_int(new byte[]{p[4], p[5], p[6], p[7]});
        ack_num = bytes_to_int(new byte[]{p[8], p[9], p[10], p[11]});
        recv_win = bytes_to_short(new byte[]{p[14], p[15]});
        checksum = bytes_to_short(new byte[]{p[16], p[17]});
        urg_data = bytes_to_short(new byte[]{p[18], p[19]});

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
        if (head_len > 5) {

            byte opts_pad = p[def_head_len];
            byte data_pad = p[def_head_len + 1];

            if (opts_pad != 0) {

                int opts_beg = def_head_len + 2;
                int opts_end = (head_len * 4) - opts_pad;
                int opts_len = opts_end - opts_beg;

                /* if there are any actual options */
                if (opts_len != 0) {
                    options = new byte[opts_len];
                    int j = 0;
                    for (int i = opts_beg; i < opts_end; i++, j++)
                        options[j] = p[i];
                }

                int data_beg = head_len * 4;
                int data_end = p.length - data_pad;
                int data_len = data_end - data_beg;

                /* if there is any data */
                if (data_len != 0) {
                    data = new byte[data_len];
                    int j = 0;
                    for (int i = data_beg; i < data_end; i++, j++)
                        data[j] = p[i];
                }
            }

        } else if (p.length - (head_len * 4) != 0) {

            data = new byte[p.length - (head_len * 4)];
            System.arraycopy(p, head_len * 4, data, 0, data.length);
        }

    }

    /**
     * Converts an array of four bytes into an integer.
     *
     * @param bytes : The bytes to be converted to an integer.
     *
     * @return The equivalent integer value.
     */
    public int bytes_to_int(byte[] bytes) {

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
    public short bytes_to_short(byte[] bytes) {

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
    public byte[] int_to_bytes(int num) {
        return ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).
                putInt(num).array();
    }

    /**
     * Converts a short to an array of two bytes.
     *
     * @param value : The short value.
     *
     * @return An array of two bytes containing the short value.
     */
    public byte[] short_to_bytes(short value) {
        return ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN).
                putShort(value).array();
    }

    /**
     * Calculates the 16-bit 1's complement checksum.
     *
     * @param bytes : The bytes to be checksumed.
     *
     * @return The checksum value.
     */
    public short calculate_checksum(byte[] bytes) {

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
    private byte[] flags_to_byte() {

        int val = 0;
        val += URG ? 32 : 0;
        val += ACK ? 16 : 0;
        val += PSH ? 8 : 0;
        val += RST ? 4 : 0;
        val += SYN ? 2 : 0;
        val += FIN ? 1 : 0;
        return new byte[]{(byte) val};
    }

    /**
     * Formats the TCP_Packet.
     *
     * @return The String representation of the TCP_Packet object.
     */
    @Override
    public String toString() {

        return "Packet {\n" +
                "\t\t\t[Src port   = " + src_port + "]" +
                "\t[Dest port = " + dest_port + "]\n" +
                "\t\t\t[Seq num    = " + seq_num + "]\n" +
                "\t\t\t[Ack num    = " + ack_num + "]\n" +
                "\t\t\t[Header len = " + head_len + "]" +
                "\t\t[URG = " + (URG ? 1 : 0) + ", " +
                "ACK = " + (ACK ? 1 : 0) + ", " +
                "PSH = " + (PSH ? 1 : 0) + ", " +
                "RST = " + (RST ? 1 : 0) + ", " +
                "SYN = " + (SYN ? 1 : 0) + ", " +
                "FIN = " + (FIN ? 1 : 0) + "]"  +
                "\t[Recv win = " + recv_win + "]\n" +
                "\t\t\t[Checksum   = " + checksum + "]" +
                "\t[Urg data offset = " +
                (urg_data < 0 ? "null" : urg_data) + "]\n" +
                "\t\t\t[Options    = " + Arrays.toString(options) + "]\n" +
                "\t\t\t[Data    ("+ data.length +" bytes) = " +
                        Arrays.toString(data) + "]\n" +
                "\t\t\t[Segment ("+ segment.length +" bytes) = " +
                        Arrays.toString(segment) + "]\n" +
                "\t\t\t}";
    }

    /* Getters and Setters */

    public int get_src_port() {
        return src_port;
    }

    public void set_src_port(int src_port) {
        this.src_port = src_port;
    }

    public int get_dest_port() {
        return dest_port;
    }

    public void set_dest_port(int dest_port) {
        this.dest_port = dest_port;
    }

    public int get_seq_num() {
        return seq_num;
    }

    public void set_seq_num(int seq_num) {
        this.seq_num = seq_num;
    }

    public int get_ack_num() {
        return ack_num;
    }

    public void set_ack_num(int ack_num) {
        this.ack_num = ack_num;
    }

    public int get_head_len() {
        return (head_len << 2);
    }

    public void set_head_len(int head_len) {
        this.head_len = head_len;
    }

    public boolean get_URG() {
        return URG;
    }

    public void set_URG(boolean URG) {
        this.URG = URG;
    }

    public boolean get_ACK() {
        return ACK;
    }

    public void set_ACK(boolean ACK) {
        this.ACK = ACK;
    }

    public boolean get_PSH() {
        return PSH;
    }

    public void set_PSH(boolean PSH) {
        this.PSH = PSH;
    }

    public boolean get_RST() {
        return RST;
    }

    public void set_RST(boolean RST) {
        this.RST = RST;
    }

    public boolean get_SYN() {
        return SYN;
    }

    public void set_SYN(boolean SYN) {
        this.SYN = SYN;
    }

    public boolean get_FIN() {
        return FIN;
    }

    public void set_FIN(boolean FIN) {
        this.FIN = FIN;
    }

    public byte[] get_options() {
        return options;
    }

    public void set_options(byte[] options) {
        this.options = options;
    }

    public int get_recv_win() {
        return recv_win;
    }

    public void set_recv_win(int recv_win) {
        this.recv_win = recv_win;
    }

    public short get_checksum() {
        return checksum;
    }

    public void set_checksum(short checksum) {
        this.checksum = checksum;
    }

    public int get_urg_data() {
        return urg_data;
    }

    public void set_urg_data(int urg_data) {
        this.urg_data = urg_data;
    }

    public byte[] get_data() {
        return data;
    }

    public void set_data(byte[] data) {
        this.data = data;
    }

    public byte[] get_segment() {
        return segment;
    }

    public void set_segment(byte[] segment) {
        this.segment = segment;
    }

    /* Tester */
    public static void main(String[] args) {

        TCP_Packet p = new TCP_Packet();
        p.set_src_port(1098);
        p.set_dest_port(1099);
        p.set_seq_num(2);
        p.set_ack_num(4);
        p.set_URG(true);
        p.set_ACK(true);
        p.set_RST(true);
        p.set_FIN(true);
        p.set_recv_win(1152);
        p.set_urg_data((short) 5);
        p.set_data("abcdefghijklmnopqrstuvwxyzzzza".getBytes());
        p.set_options(new byte[] {1,2,3});

        try {
            byte[] p_segment = p.encode();
            System.out.println(p);

            TCP_Packet p2 = new TCP_Packet();
            p2.extract(p_segment);
            System.out.println(p2);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
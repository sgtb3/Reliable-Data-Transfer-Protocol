import java.util.ArrayList;

public class Segment {

    private byte[] data;
    int seg_num;
    int seq_num;
    int ack_num;
    int ack_count;
    int retrans_count;
    boolean base;
    boolean sent;
    boolean acked;
    boolean retrans;
    long time_sent;
    long time_acked;

    /**
     * Constructs a new Segment.
     *
     * @param seg_num: The segment number.
     * @param seq_num: The associated packet sequence number.
     */
    public Segment(int seg_num, int seq_num) {
        this.seg_num = seg_num;
        this.seq_num = seq_num;
        time_sent = 0;
        time_acked = 0;
        retrans_count = 0;
        base = false;
        sent = false;
        acked = false;
        retrans = false;
    }

    /**
     * Sets the segment data.
     * @param : The non-empty and non-null data.
     */
    public void set_data(byte[] data) {
        this.data = data;
        if (data != null && data.length != 0) {
            ack_num = seq_num + data.length;
        }
    }

    public byte[] get_data() {
        return data;
    }

    @Override
    public String toString() {
        return "\n{" +
                "\n\tSeg#:        " + seg_num       +
                "\n\tSeq#:        " + seq_num       +
                "\n\tData bytes:  " + data.length   +
                "\n\tBase:        " + base          +
                "\n\tSent:        " + sent          +
                "\n\tTime sent:   " + time_sent     +
                "\n\tAcked:       " + acked         +
                "\n\tAck#:        " + ack_num       +
                "\n\tTime acked:  " + time_acked    +
                "\n\tAck Count:   " + ack_count     +
                "\n\tRetrans:     " + retrans       +
                "\n\tNum Retrans: " + retrans_count +
                "\n}\n";
    }

    /* Tester */
    public static void main(String[] args) {

        ArrayList<Segment> list = new ArrayList<>();
        int MSS = 576;

        for (int i = 0; i < 10; i++)
            list.add(new Segment(i, (i * MSS)));

        list.forEach(System.out::println);
    }
}

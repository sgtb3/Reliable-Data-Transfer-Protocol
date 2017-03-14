import java.util.ArrayList;

public class Segment {

    private byte[] data;
    protected int segNum;
    protected int seqNum;
    protected int ackNum;
    protected int ackCount;
    protected int retransCount;
    protected boolean base;
    protected boolean sent;
    protected boolean acked;
    protected boolean retrans;
    protected long timeSent;
    protected long timeAcked;

    /**
     * Constructs a new Segment.
     * @param segNum : The segment number.
     * @param seqNum : The associated packet sequence number.
     */
    public Segment(int segNum, int seqNum) {

        this.segNum = segNum;
        this.seqNum = seqNum;
        timeSent = 0;
        timeAcked = 0;
        retransCount = 0;
        base = false;
        sent = false;
        acked = false;
        retrans = false;
    }

    public void setData(byte[] data) {
        this.data = data;
        if (data != null && data.length != 0)
            ackNum = seqNum + data.length;
    }

    public byte[] getData() {
        return data;
    }

    @Override
    public String toString() {

        return "\n{" +
                "\n\tSeg#:        " + segNum +
                "\n\tSeq#:        " + seqNum +
                "\n\tData bytes:  " + data.length +
                "\n\tBase:        " + base +
                "\n\tSent:        " + sent +
                "\n\tTime sent:   " + timeSent +
                "\n\tAcked:       " + acked +
                "\n\tAck#:        " + ackNum +
                "\n\tTime acked:  " + timeAcked +
                "\n\tAck Count:   " + ackCount +
                "\n\tRetrans:     " + retrans +
                "\n\tNum Retrans: " + retransCount +
                "\n}\n";
    }

    /** Tester */
    public static void main(String[] args) {

        ArrayList<Segment> list = new ArrayList<>();
        int MSS = 576;

        for (int i = 0; i < 10; i++)
            list.add(new Segment(i, (i * MSS)));

        list.forEach(System.out::println);
    }
}

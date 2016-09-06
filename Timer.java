import java.text.SimpleDateFormat;
import java.util.Calendar;

public class Timer extends Thread {

    private static final double BETA = 0.25;
    private static final double ALPHA = 0.125;
    private boolean alive;
    private boolean debug_mode;
    private long start_time;
    private long samp_rtt;
    boolean timeout_event;
    boolean running;
    int timeout;  // milliseconds
    int seq_num;
    long time_remaining;
    long est_rtt; // a weighted avg of the sample_rtt's
    long dev_rtt; // an estimate of variability of the sample_rtt's from the est_rtt

    /**
     * Constructs a new Timer object.
     * @param debug_mode : For debugging.
     */
    public Timer(boolean debug_mode) {

        this.debug_mode = debug_mode;
        timeout_event   = false;
        running         = false;
        alive           = true;
        timeout         =  1;
        seq_num         = -1;
        start_time      =  0;
        samp_rtt        =  1;
        est_rtt         =  1;
        dev_rtt         =  1;
    }

    /**
     * Shuts down the timer.
     */
    public void shutdown() {
        alive = false;
        running = false;
    }

    @Override
    public void run() {

        println("Timer running...");
        while (alive)
        {
            if (!running) {
               continue;
            }

            // calculate inactivity times
            long time_inactive = (System.currentTimeMillis() - start_time);
            time_remaining = (timeout - time_inactive);

            // if time elapsed is > timeout
            if (time_remaining <= 0) {
                timeout_event = true;
                stop_timer(seq_num, false);
            } else {
                try {
                    sleep(time_remaining);
                } catch (InterruptedException ignored) {}
            }
        }
        println("Timer complete.");
    }

    /**
     * Starts the timer.
     * @param seq_num : The sequence number.
     */
    synchronized void start_timer(int seq_num) {

        if (running) {
            if (this.seq_num == seq_num) {
                start_time = System.currentTimeMillis();
                println("RESTARTED for seq# " + seq_num);
            } else {
                stop_timer(this.seq_num);
                start_timer(seq_num);
            }
        } else {
            start_time = System.currentTimeMillis();
            this.seq_num = seq_num;
            running = true;
            println("STARTED for seq# " + seq_num);
        }
    }

    /**
     * Stops the timer.
     * @param ack_num : The acknowledgement number.
     */
    synchronized void stop_timer(int ack_num, boolean update_rtt) {

        if (running && (ack_num >= seq_num))
        {
            running = false;
            String msg = "STOPPED for seq# " + seq_num +
                         ", ack# " + ack_num + "\n";
            if (update_rtt) {
                samp_rtt = System.currentTimeMillis() - start_time;
                update_rtt_stats();
                msg +=  "(samp_rtt: " + samp_rtt + " ms) " +
                        "(est_rtt: " + est_rtt + " ms) " +
                        "(dev_rtt: " + dev_rtt + " ms) " +
                        "(timeout: " + timeout + " ms)\n";
            }
            println(msg);
        }
    }

    /**
     * Stops the timer.
     * @param ack_num : The acknowledgement number.
     */
    synchronized void stop_timer(int ack_num) {
        stop_timer(ack_num, false);
    }

    /**
     * Logs a timestamp and the message to the console.
     * @param msg : The message to be displayed.
     */
    private void println(String msg) {
        if (debug_mode) {
            System.out.println(new SimpleDateFormat("[HH:mm:ss:SSS] ").format
                    (Calendar.getInstance().getTime()) + "TIMER : " + msg);
        }
    }

    /**
     * Updates the Round Trip Time variables.
     */
    private synchronized void update_rtt_stats() {

        est_rtt = Math.round(((1 - ALPHA) * est_rtt) +
                  (ALPHA * samp_rtt));
        dev_rtt = Math.round(((1 - BETA) * dev_rtt) +
                  (BETA * Math.abs(samp_rtt - est_rtt)));
        timeout = new Double(est_rtt + (4 * dev_rtt)).intValue();
    }
}
import java.text.SimpleDateFormat;
import java.util.Calendar;

public class Timer extends Thread {

    private static final double BETA = 0.25;
    private static final double ALPHA = 0.125;
    private boolean alive;
    private boolean debugMode;
    private long startTime;
    private long sampRtt;
    protected boolean timeoutEvent;
    protected boolean running;
    protected int timeout;  /* milliseconds */
    protected int seqNum;
    protected long timeRemaining;
    protected long estRtt; /* a weighted avg of the sample_rtt's */
    protected long devRtt; /* an estimate of variability of the sample_rtt's from the estRtt */

    /**
     * Constructs a new Timer object.
     *
     * @param debugMode : If true, will print debugging statements.
     */
    public Timer(boolean debugMode) {

        this.debugMode = debugMode;
        timeoutEvent = false;
        running         = false;
        alive           = true;
        timeout         =  1;
        seqNum = -1;
        startTime =  0;
        sampRtt =  1;
        estRtt =  1;
        devRtt =  1;
    }

    /** Shuts down the timer. */
    public void shutdown() {
        alive = false;
        running = false;
    }

    @Override
    public void run() {

        println("Timer running...");

        while (alive) {

            if (!running)
               continue;

            /* calculate inactivity times */
            long timeInactive = System.currentTimeMillis() - startTime;
            timeRemaining = timeout - timeInactive;

            /* if time elapsed is > timeout */
            if (timeRemaining <= 0) {
                timeoutEvent = true;
                stopTimer(seqNum, false);
            } else {
                try {
                    sleep(timeRemaining);
                } catch (InterruptedException ignored) {}
            }
        }

        println("Timer complete.");
    }

    /**
     * Starts the timer.
     *
     * @param seqNum : The packet sequence number.
     */
    protected synchronized void startTimer(int seqNum) {

        if (running) {
            if (this.seqNum == seqNum) {
                startTime = System.currentTimeMillis();
                println("RESTARTED for seq# " + seqNum);
            } else {
                stopTimer(this.seqNum);
                startTimer(seqNum);
            }
        } else {
            startTime = System.currentTimeMillis();
            this.seqNum = seqNum;
            running = true;
            println("STARTED for seq# " + seqNum);
        }
    }

    /**
     * Stops the timer.
     *
     * @param ackNum    : The acknowledgement number.
     * @param updateRtt : If set, this method will additionally update the
     *                    return-trip-time statistics.
     */
    protected synchronized void stopTimer(int ackNum, boolean updateRtt) {

        if (running && (ackNum >= seqNum)) {

            running = false;
            String msg = "STOPPED for seq# " + seqNum +
                         ", ack# " + ackNum + "\n";

            if (updateRtt) {
                sampRtt = System.currentTimeMillis() - startTime;
                updateRttStats();
                msg +=  "(sampRtt: " + sampRtt + " ms) " +
                        "(estRtt: " + estRtt + " ms) " +
                        "(devRtt: " + devRtt + " ms) " +
                        "(timeout: " + timeout + " ms)\n";
            }
            println(msg);
        }
    }

    /**
     * Stops the timer.
     *
     * @param ackNum : The acknowledgement number.
     */
    synchronized void stopTimer(int ackNum) {
        stopTimer(ackNum, false);
    }

    /**
     * Logs a timestamp and the message to the console.
     *
     * @param msg : The message to be displayed.
     */
    private void println(String msg) {
        if (debugMode)
            System.out.println(new SimpleDateFormat("[HH:mm:ss:SSS] ").format
                    (Calendar.getInstance().getTime()) + "TIMER : " + msg);
    }

    /**
     * Updates the Round Trip Time variables.
     */
    private synchronized void updateRttStats() {

        estRtt = Math.round(((1 - ALPHA) * estRtt) +
                  (ALPHA * sampRtt));
        devRtt = Math.round(((1 - BETA) * devRtt) +
                  (BETA * Math.abs(sampRtt - estRtt)));
        timeout = new Double(estRtt + (4 * devRtt)).intValue();
    }
}
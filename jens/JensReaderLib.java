package de.telekom.llcto.jens.reader;

/*-
 * Copyright © 2021, 2022
 *      mirabilos <t.glaser@tarent.de>
 * Licensor: Deutsche Telekom
 *
 * Provided that these terms and disclaimer and all copyright notices
 * are retained or reproduced in an accompanying document, permission
 * is granted to deal in this work without restriction, including un‐
 * limited rights to use, publicly perform, distribute, sell, modify,
 * merge, give away, or sublicence.
 *
 * This work is provided “AS IS” and WITHOUT WARRANTY of any kind, to
 * the utmost extent permitted by applicable law, neither express nor
 * implied; without malicious intent or gross negligence. In no event
 * may a licensor, author or contributor be held liable for indirect,
 * direct, other damage, loss, or other issues arising in any way out
 * of dealing in the work, even if advised of the possibility of such
 * damage or existence of a defect, except proven that it results out
 * of said person’s immediate fault when using the work as intended.
 */

import java.io.Closeable;
import java.io.IOException;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.text.NumberFormat;
import java.text.SimpleDateFormat;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;
import java.util.stream.Stream;

/**
 * <p>Java™ part of the JNI JENS relayfs library.</p>
 *
 * @author mirabilos (t.glaser@tarent.de)
 */
public final class JensReaderLib {
    private static char decimal;
    private static final SimpleDateFormat sdfHalf;

    static {
        sdfHalf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.ROOT);
        sdfHalf.setTimeZone(TimeZone.getTimeZone(ZoneOffset.UTC));
    };

    /**
     * <p>Signed integer type.</p>
     *
     * <p>This type is a signed integer type (i.e. the Java™ default).
     * It may carry values from negative minimum to positive maximum.</p>
     *
     * <p>In contrast to a {@link Positive} type, it is not safe to use
     * in unsigned context.</p>
     *
     * @author mirabilos (t.glaser@tarent.de)
     */
    @SuppressWarnings("unused")
    @Documented
    @Retention(RetentionPolicy.SOURCE)
    @Target({ ElementType.TYPE_USE })
    public @interface Signed {
    }

    /**
     * <p>Positive integer type.</p>
     *
     * <p>This type can be used in either signed or unsigned contexts.
     * It may carry values from 0 to positive maximum.</p>
     *
     * <p>The optional attribute {@code max} documents the maximum expected value
     * if it differs from Byte.MAX_VALUE, Short.MAX_VALUE, Integer.MAX_VALUE or
     * Long.MAX_VALUE, respectively.</p>
     *
     * <p>Values annotated thusly can be used in both {@link Unsigned} and
     * {@link Signed} contexts and are safe for any standard arithmetic of
     * their kind.</p>
     *
     * @author mirabilos (t.glaser@tarent.de)
     */
    @SuppressWarnings("unused")
    @Documented
    @Retention(RetentionPolicy.SOURCE)
    @Target({ ElementType.TYPE_USE })
    public @interface Positive {
        long max() default Long.MAX_VALUE /* or Integer.MAX_VALUE */;
    }

    /**
     * <p>Unsigned integer type.</p>
     *
     * <p>This type is an <b>unsigned</b> integer type and needs special handling.
     * It may carry values from 0 to (2 * positive maximum + 1).</p>
     *
     * <p>In contrast to a {@link Positive} type, it is <b>not safe to use
     * in signed context</b>!</p>
     *
     * @author mirabilos (t.glaser@tarent.de)
     */
    @Documented
    @Retention(RetentionPolicy.SOURCE)
    @Target({ ElementType.TYPE_USE })
    public @interface Unsigned {
    }

    /**
     * <p>Used by JNI code.</p>
     *
     * <p>This field is used (read and/or written) by native code. (Intended via
     * https://stackoverflow.com/a/5284371/2171120 to tell IntelliJ to ignore the
     * unused and/or uninitialised state of the annotated field.)</p>
     *
     * <p>This class is used by native code and therefore must not be renamed or
     * moved to a different package. Its members (fields and/or methods) may not
     * be renamed.</p>
     */
    @Retention(RetentionPolicy.SOURCE)
    @Target({ ElementType.FIELD, ElementType.TYPE })
    public @interface UsedByJNI {
    }

    /**
     * Formats timestamps as milliseconds, using the current locale’s decimal separator.
     *
     * @param ns unsigned timestamp in nanoseconds
     * @return String "%d.%06d" (except using the locale’s decimal separator) in milliseconds
     */
    public static String formatTimestamp(final @Unsigned long ns) {
        final @Positive(max = 18446744073709L) long ms = Long.divideUnsigned(ns, 1000000L);
        final @Positive(max = 999999) long frac = Long.remainderUnsigned(ns, 1000000L);
        return String.format("%d%c%06d", ms, decimal, frac);
    }

    /**
     * Formats timestamps as ISO 8601 with nanoseconds.
     *
     * @param ns  unsigned timestamp in nanoseconds
     * @param ofs unsigned timestamp offset in nanoseconds
     * @return String "yyyy-mm-ddThh:mm:ss.sssssssssZ", empty ("") if ofs is 0
     */
    public static String formatTimestamp(final @Unsigned long ns, final @Unsigned long ofs) {
        if (ofs == 0)
            return "";

        final @Unsigned long ts = ns + ofs;
        final @Positive(max = 18446744073709L) long ms = Long.divideUnsigned(ts, 1000000L);
        final @Positive(max = 999999999) long frac = Long.remainderUnsigned(ts, 1000000000L);
        return String.format("%s.%09dZ", sdfHalf.format(new Date(ms)), frac);
    }

    /**
     * Formats ECN bits as string.
     *
     * @param bits integer representation of ECN bits (0‥3)
     * @return String "00", "01", "10" or "11"
     */
    public static String formatECNBits(final @Positive(max = 3) int bits) {
        final String s = Integer.toBinaryString(bits);
        return s.length() < 2 ? "0" + s : s;
    }

    /**
     * <p>Internal hook point for the native interface. Class must not be moved
     * or renamed for the native code to be able to attach.</p>
     *
     * @author mirabilos (t.glaser@tarent.de)
     */
    @UsedByJNI
    private static class JNI {
        @UsedByJNI
        private int fd;
        @UsedByJNI
        private @Unsigned long lastOffset;
        @UsedByJNI
        private final AbstractJensActor.Record[] rQueueSize;
        @UsedByJNI
        private final AbstractJensActor.Record[] rPacket;
        @UsedByJNI
        private final AbstractJensActor.Record[] rUnknown;
        @UsedByJNI
        private int nQueueSize;
        @UsedByJNI
        private int nPacket;
        @UsedByJNI
        private int nUnknown;
        @UsedByJNI
        private final ByteBuffer buf;

        static {
            System.loadLibrary("jensdmpJNI");
        }

        private static AbstractJensActor.Record[] mkarr() {
            return Stream.generate(AbstractJensActor.Record::new).limit(1024).toArray(AbstractJensActor.Record[]::new);
        }

        private JNI() {
            fd = -1;
            /* the sizes are checked in the JNI code */
            buf = ByteBuffer.allocateDirect(65536);
            rQueueSize = mkarr();
            rPacket = mkarr();
            rUnknown = mkarr();
        }

        private native String nativeOpen(final String fn);

        private native String nativeRead();

        private native void nativeClose();

        private void open(final String filename) throws IOException {
            close(); // in case it was open

            final String err = nativeOpen(filename);

            if (err != null) {
                throw new IOException(err);
            }
        }

        private boolean read(final AbstractJensActor actor) throws IOException, InterruptedException {
            final String err = nativeRead();

            if (Thread.interrupted()) {
                throw new InterruptedException();
            }
            if (err != null) {
                throw new IOException(err);
            }

            if (nQueueSize > 0) {
                actor.handleQueueSize(rQueueSize, nQueueSize);
            }
            if (nPacket > 0) {
                actor.handlePacket(rPacket, nPacket);
            }
            if (nUnknown > 0) {
                actor.handleUnknown(rUnknown, nUnknown);
            }
            return (nQueueSize + nPacket + nUnknown) > 0;
        }

        private void close() {
            if (fd != -1) {
                nativeClose();
                fd = -1;
            }
        }

        @SuppressWarnings("deprecation")
        @Override
        protected void finalize() {
            close();
        }
    }

    /**
     * <p>Callback class for incoming records from the kernel.</p>
     *
     * <p>Subclass this, overriding only the methods needed (the inherited
     * default methods will just not do anything) with the code that should
     * be executed on each record type in small batches.</p>
     *
     * <p>This class needs to know the network interface the sch_janz queue is
     * running on, so it can properly construct IP addresses when asked to.</p>
     *
     * <p>Each method is passed a {@link Record} array and the amount of
     * valid records of its corresponding type in the array for this invocation;
     * make sure to only use the fields documented for the respective method.
     * The length is guaranteed to be positive (between 1 and some small enough
     * number, such as 4096). Since callbacks are processed in batches use the
     * {@link Record#timestamp} to keep track of the relative order and
     * duration; don’t assume “live” operation.</p>
     *
     * @author mirabilos (t.glaser@tarent.de)
     */
    public static class AbstractJensActor {
        protected final NetworkInterface networkInterface;

        /**
         * <p>Initialises a new AbstractJensActor or subclass thereof.</p>
         *
         * @param iface {@link NetworkInterface} on which the queue is running
         */
        public AbstractJensActor(final NetworkInterface iface) {
            networkInterface = iface;
        }

        /**
         * <p>Auxilliary data associated with the record.</p>
         *
         * <p>A single object of a single type is used for simplicity and, more
         * importantly, speed. Only some fields are supported for each record
         * type:</p>
         *
         * <p>QueueSize:</p><ul>
         * <li>{@link #timestamp}</li>
         * <li>{@link #tsOffset}</li>
         * <li>{@link #len}</li>
         * <li>{@link #mem}</li>
         * <li>{@link #bwLimit}</li>
         * <li>{@link #extraLatency}</li>
         * <li>{@link #handoverStarting}</li>
         * </ul>
         *
         * <p>Packet:</p><ul>
         * <li>{@link #timestamp}</li>
         * <li>{@link #tsOffset}</li>
         * <li>{@link #sojournTime}</li>
         * <li>{@link #chance}</li>
         * <li>{@link #ecnIn}</li>
         * <li>{@link #ecnOut}</li>
         * <li>{@link #ecnValid}</li>
         * <li>{@link #markJENS}</li>
         * <li>{@link #dropped}</li>
         * <li>{@link #pktSize}</li>
         * <li>{@link #ipVer}</li>
         * <li>{@link #nextHeader}</li>
         * <li>{@link AbstractJensActor#getSourceIP(Record)}</li>
         * <li>{@link AbstractJensActor#getDestinationIP(Record)}</li>
         * <li>{@link #srcPort}</li>
         * <li>{@link #dstPort}</li>
         * </ul>
         *
         * <p>Unknown:</p><ul>
         * <li>{@link #timestamp}</li>
         * <li>{@link #tsOffset}</li>
         * <li>{@link #type}</li>
         * </ul>
         *
         * @author mirabilos (t.glaser@tarent.de)
         */
        @UsedByJNI
        protected static final class Record {

            /* valid for all record types */

            /**
             * <p>Timestamp in nanoseconds for the record.</p>
             *
             * <p>Used in all record types.</p>
             */
            @UsedByJNI
            public @Unsigned long timestamp;

            /**
             * <p>Current timestamp offset in nanoseconds.</p>
             *
             * <p>This is so {@link #timestamp} + tsOffset is epoch-based.</p>
             *
             * <p>Used in all record types. Valid only after the first
             * QueueSize record was read (otherwise 0 which means invalid).</p>
             */
            @UsedByJNI
            public @Unsigned long tsOffset;

            /* only valid for QueueSize */

            /**
             * <p>Length of the queue (number of packets in the queue).</p>
             *
             * <p>Capped at 0xFFFF, which will also be shown if there are more
             * than 65535 packets in the queue. Normally, the queue is sizef for
             * 10240 packets only, so this should not be an issue.</p>
             *
             * <p>{@link #handleQueueSize(Record[], int)} only.</p>
             */
            @UsedByJNI
            public @Positive(max = 0x0000FFFFL) int len;
            /**
             * <p>Memory usage of the queue in bytes.</p>
             *
             * <p>{@link #handleQueueSize(Record[], int)} only.</p>
             */
            @UsedByJNI
            public @Positive(max = 0xFFFFFFFFL) long mem;
            /**
             * <p>Current bandwidth limit in bits per second.</p>
             *
             * <p>Maximum 8 Gbit/s using SI præficēs; this is always a
             * multiple of 8 bits because bytes are used internally.</p>
             *
             * <p>{@link #handleQueueSize(Record[], int)} only.</p>
             */
            @UsedByJNI
            public @Positive(max = 8000000000L) long bwLimit;
            /**
             * <p>Currently enacted extra latency, in nanoseconds.</p>
             *
             * <p>{@link #handleQueueSize(Record[], int)} only.</p>
             */
            @UsedByJNI
            public @Positive(max = 0x3FFFFFFFC00L) long extraLatency;
            /**
             * <p>Whether a handover is just starting.</p>
             *
             * <p>{@link #handleQueueSize(Record[], int)} only.</p>
             */
            @UsedByJNI
            public boolean handoverStarting;

            /* only valid for Packet */

            /**
             * <p>Sojourn time of this packet in the FIFO, in nanoseconds.</p>
             *
             * <p>Note this may be 0x3FFFFFFFC00L, for example if the packet
             * was dropped while the queue was resized, or if it could not
             * be determined otherwise.</p>
             *
             * <p>{@link #handlePacket(Record[], int)} only.</p>
             */
            @UsedByJNI
            public @Positive(max = 0x3FFFFFFFC00L) long sojournTime;
            /**
             * <p>Chance in [0, 1] that this packet is to be ECN CE marked,
             * based on {@code markfull} and {@code markfree}.</p>
             *
             * <p>Mind that rounding occurred by the time this value is filled.</p>
             *
             * <p>Note: {@link #markJENS} indicates whether the packet was actually
             * marked (or would be if it was ECN-capable), based on the random number
             * retrieved from the kernel.</p>
             *
             * <p>{@link #handlePacket(Record[], int)} only.</p>
             */
            @UsedByJNI
            public double chance;
            /**
             * <p>ECN bits of the packet when arriving, if any (see {@link #ecnValid}).</p>
             *
             * <p>{@link #handlePacket(Record[], int)} only.</p>
             */
            @UsedByJNI
            public @Positive(max = 3) int ecnIn;
            /**
             * <p>ECN bits of the packet when leaving, if any (see {@link #ecnValid}).</p>
             *
             * <p>{@link #handlePacket(Record[], int)} only.</p>
             */
            @UsedByJNI
            public @Positive(max = 3) int ecnOut;
            /**
             * <p>Whether the ECN bits are valid.</p>
             *
             * <p>The ECN bits can only be valid for IP (IPv6) and Legacy IP (IPv4)
             * packets, not other packet types (such as ARP), and when the packet
             * fragment is not too short. Having this flag false is not a problem.</p>
             *
             * <p>{@link #handlePacket(Record[], int)} only.</p>
             */
            @UsedByJNI
            public boolean ecnValid;
            /**
             * <p>Whether the packet was ECN CE marked due to the JENS algorithm,
             * based on {@code markfull} and {@code markfree} as well as the
             * {@link #chance} and the actual random value from the kernel.</p>
             *
             * <p>Note that this flag can be set even if the packet was not ECN-capable.
             * The packet is neither marked nor dropped in that case.</p>
             *
             * <p>{@link #handlePacket(Record[], int)} only.</p>
             */
            @UsedByJNI
            public boolean markJENS;
            /**
             * <p>Whether the packet was dropped (instead of passed on) on leaving.</p>
             *
             * <p>{@link #handlePacket(Record[], int)} only.</p>
             */
            @UsedByJNI
            public boolean dropped;
            /**
             * <p>Real size of the packet, including Layer 2 framing.</p>
             *
             * <p>{@link #handlePacket(Record[], int)} only.</p>
             */
            @UsedByJNI
            public @Positive(max = 0xFFFFFFFFL) long pktSize;
            /**
             * <p>IP version (4 or 6), or 0 to indicate not IP.</p>
             *
             * <p>{@link #handlePacket(Record[], int)} only.</p>
             */
            @UsedByJNI
            public @Positive(max = 6) int ipVer;
            /**
             * <p>IP header field “next header” (Legacy IP “protocol”).</p>
             *
             * <p>Values are these taken from an IP fixed or extension
             * header; additionally, it can be either 44 if the protocol
             * could not be determined due to packet fragmentation, or 59
             * when other reasons prevent determining it (note 59 is also
             * valid for some IPv6 packets). See also: <a
             * href="https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers">List
             * of IP protocol numbers</a></p>
             *
             * <p>Only valid if {@link #ipVer} is 4 or 6.</p>
             *
             * <p>{@link #handlePacket(Record[], int)} only.</p>
             */
            @UsedByJNI
            public @Positive(max = 255) int nextHeader;
            /**
             * <p>Bare source IP address of the packet.</p>
             *
             * <p>Only valid if {@link #ipVer} is 4 or 6.</p>
             *
             * <p>{@link #handlePacket(Record[], int)} only.</p>
             */
            @UsedByJNI
            private byte[] srcIP = new byte[16];
            /**
             * <p>Bare destination IP address of the packet.</p>
             *
             * <p>Only valid if {@link #ipVer} is 4 or 6.</p>
             *
             * <p>{@link #handlePacket(Record[], int)} only.</p>
             */
            @UsedByJNI
            private byte[] dstIP = new byte[16];
            /**
             * <p>Source port of the packet.</p>
             *
             * <p>Only valid if {@link #ipVer} is 4 or 6
             * and {@link #nextHeader} is 6 or 17.</p>
             *
             * <p>{@link #handlePacket(Record[], int)} only.</p>
             */
            @UsedByJNI
            public @Positive(max = 65535) int srcPort;
            /**
             * <p>Destination port of the packet.</p>
             *
             * <p>Only valid if {@link #ipVer} is 4 or 6
             * and {@link #nextHeader} is 6 or 17.</p>
             *
             * <p>{@link #handlePacket(Record[], int)} only.</p>
             */
            @UsedByJNI
            public @Positive(max = 65535) int dstPort;

            /* only valid for Unknown */

            /**
             * <p>The type octet of the record line.</p>
             *
             * <p>{@link #handleUnknown(Record[], int)} only.</p>
             */
            @UsedByJNI
            public byte type;
        }

        private static boolean mightNeedZoneID(final byte[] addr) {
            if ((addr[0] & (byte) 0xE0) == 0x20) {
                // global Unicast 2000::/3
                return false;
            }
            if ((addr[0] == 0x00) && (addr[1] == 0x00) &&
              (addr[2] == 0x00) && (addr[3] == 0x00) &&
              (addr[4] == 0x00) && (addr[5] == 0x00) &&
              (addr[6] == 0x00) && (addr[7] == 0x00) &&
              (addr[8] == 0x00) && (addr[9] == 0x00)) {
                if ((addr[10] == 0x00) && (addr[11] == 0x00) &&
                  (addr[12] == 0x00) && (addr[13] == 0x00) &&
                  (addr[14] == 0x00) && ((addr[15] & (byte) 0xFE) == 0x00)) {
                    // ::/128, ::1/128
                    return false;
                }
                //noinspection RedundantIfStatement
                if ((addr[10] == (byte) 0xFF) && (addr[11] == (byte) 0xFF)) {
                    // v4-mapped: convert to Inet4Address, MUST NOT be scoped
                    return false;
                }
            }
            return true;
        }

        /**
         * <p>Constructs a Java™ IP address object for a record.</p>
         *
         * <p>If {@code ver} is neither 4 nor 6, {@code null} is returned;
         * an {@link Inet4Address} or {@link Inet6Address}, possibly with
         * zone/scope ID, otherwise. The zone/scope ID is omitted for ::1,
         * :: or (most) global Unicast/Anycast addresses because if present
         * it’s printing always, even if unnecessary.</p>
         *
         * @param ver  {@link Record#ipVer}
         * @param addr {@link Record#srcIP} or {@link Record#dstIP}
         * @return null if ver not in (4, 6); {@link InetAddress} otherwise
         */
        private InetAddress getIP(final int ver, final byte[] addr) {
            switch (ver) {
            case 6:
                if (mightNeedZoneID(addr)) {
                    try {
                        return Inet6Address.getByAddress(null, addr, networkInterface);
                    } catch (UnknownHostException e) {
                        /* FALLTHROUGH */
                    }
                }
                /* FALLTHROUGH */
            case 4:
                try {
                    return InetAddress.getByAddress(addr);
                } catch (UnknownHostException e) {
                    /* NOTREACHED */
                    throw new RuntimeException(e);
                }
                /* NOTREACHED */
            default:
                return null;
            }
        }

        /**
         * <p>Returns the source IP address of a record.</p>
         *
         * @param r record to return the source IP address of
         * @return {@link InetAddress} corresponding to the IP, null if not IP
         */
        public final InetAddress getSourceIP(final AbstractJensActor.Record r) {
            return getIP(r.ipVer, r.srcIP);
        }

        /**
         * <p>Returns the destination IP address of a record.</p>
         *
         * @param r record to return the destination IP address of
         * @return {@link InetAddress} corresponding to the IP, null if not IP
         */
        public final InetAddress getDestinationIP(final AbstractJensActor.Record r) {
            return getIP(r.ipVer, r.dstIP);
        }

        /**
         * <p>Handles queue-size records (periodically).</p>
         *
         * <p>The default implementation does nothing. Override only when needed.</p>
         *
         * @param r array of {@link Record}s with the data to process
         * @param n amount of {@link Record} elements in the {@code r} array
         */
        public void handleQueueSize(final AbstractJensActor.Record[] r, final int n) {
        }

        /**
         * <p>Handles packet records (one for each packet leaving the queue).</p>
         *
         * <p>The default implementation does nothing. Override only when needed.</p>
         *
         * @param r array of {@link Record}s with the data to process
         * @param n amount of {@link Record} elements in the {@code r} array
         */
        public void handlePacket(final AbstractJensActor.Record[] r, final int n) {
        }

        /**
         * <p>Handles unknown records (all other XML tags not listed above).</p>
         *
         * <p>The default implementation does nothing. Override only when needed.</p>
         *
         * @param r array of {@link Record}s with the data to process
         * @param n amount of {@link Record} elements in the {@code r} array
         */
        public void handleUnknown(final AbstractJensActor.Record[] r, final int n) {
        }
    }

    /**
     * <p>Initialises a JensReader instance and returns it.</p>
     *
     * <p>(This is a separate method because throwing exceptions in
     * constructors is not a very good idea, and this method can throw.)</p>
     *
     * @param args  arguments to pass; for now, the path to the relayfs file
     * @param actor an instance of an {@link AbstractJensActor} subclass
     * @return an object whose {@link JensReader#run()} method can be called
     * @throws IOException on most errors
     */
    public static JensReader init(final String[] args, final AbstractJensActor actor) throws IOException {
        /* configure decimal separator */
        // this is awful but we can’t directly use NumberFormat…
        final NumberFormat numberFormat = NumberFormat.getInstance();
        if (numberFormat instanceof DecimalFormat) {
            final DecimalFormat decimalFormat = (DecimalFormat) numberFormat;
            final DecimalFormatSymbols symbols = decimalFormat.getDecimalFormatSymbols();
            decimal = symbols.getDecimalSeparator();
        } else {
            decimal = '.';
        }

        /* open the relayfs file */
        final JNI reader = new JNI();
        reader.open(args[0]);
        /* go on */
        return new JensReader(reader, actor);
    }

    /**
     * <p>Methods doing the actual reading and parsing in a loop and cleaning up.</p>
     *
     * @author mirabilos (t.glaser@tarent.de)
     */
    protected static class JensReader implements Closeable {
        private final JNI reader;
        private final AbstractJensActor actor;

        private JensReader(final JNI xreader, final AbstractJensActor xactor) {
            reader = xreader;
            actor = xactor;
        }

        /**
         * <p>Reads records from the kernel and calls the actor.</p>
         *
         * <p>If this method returns, the relayfs channel has signalled EOF.</p>
         *
         * @throws InterruptedException if the current Thread was interrupted
         * @throws IOException          if reading from the kernel fails
         */
        public void run() throws IOException, InterruptedException {
            //noinspection StatementWithEmptyBody
            while (reader.read(actor)) {
                // nothing
            }
            reader.close();
        }

        /**
         * <p>Releases any native resources opened by this JensReader.</p>
         *
         * <p>This method is intended to be called if the {@link Thread} running
         * this JensReader instance is to be terminated externally, as opposed
         * to by reading end of file. It is implicitly run after {@link #run()}
         * finishes but may be explicitly called multiple times.</p>
         */
        @Override
        public void close() {
            reader.close();
        }
    }
}

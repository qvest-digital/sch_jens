package de.telekom.llcto.jens.reader;

/*-
 * Copyright © 2021
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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.nio.file.Path;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * <p>Example parser component for the output of the “jensdmp” C program.</p>
 *
 * <p>The XML parser averages 1 ms for each record on my laptop once warmed up,
 * which is well below the intervals of 5 ms for periodic reports. Data rates
 * nearing 10 Mbit/s will saturate it, however (at ~1000 byte-sized packets).
 * Do ensure to reduce the bandwidth below that when using statistics.</p>
 *
 * @author mirabilos (t.glaser@tarent.de)
 */
public final class JensReaderLib {
    private static char decimal;
    private static Process p = null;
    private static boolean needToInstallShutdownHook = true;

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
    @Documented
    @Retention(RetentionPolicy.SOURCE)
    @Target({ ElementType.TYPE_USE })
    public @interface Positive {
        long max() default Long.MAX_VALUE /* or Integer.MAX_VALUE */;
    }

    /**
     * <p>Unsigned integer type</p>
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
     * Formats ECN bits as string.
     *
     * @param bits integer representation of ECN bits (0‥3)
     * @return String "00", "01", "10" or "11"
     */
    public static String formatECNBits(final @Positive(max = 3) int bits) {
        final String s = Integer.toBinaryString(bits);
        return s.length() < 2 ? "0" + s : s;
    }

    private static class JNI {
        private int fd;
        private final AbstractJensActor.Record[] rQueueSize;
        private final AbstractJensActor.Record[] rPacket;
        private final AbstractJensActor.Record[] rUnknown;
        private int nQueueSize;
        private int nPacket;
        private int nUnknown;

        static {
            System.loadLibrary("jensdmpJNI");
        }

        private JNI() {
            /* 256 is asserted in the C/JNI part */
            rQueueSize = new AbstractJensActor.Record[256];
            rPacket = new AbstractJensActor.Record[256];
            rUnknown = new AbstractJensActor.Record[256];
        }

        private native String nativeOpen(final String fn);

        //…
        private native void nativeClose();

        protected void open(final String filename) throws IOException {
            final String err = nativeOpen(filename);

            if (err != null) {
                throw new IOException(err);
            }
        }

        protected void close() {
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
     * be executed on each record type.</p>
     *
     * <p>Each method may access a {@link Record} instance {@code r}; do use
     * only the fields documented to be valid for the respective method.</p>
     *
     * @author mirabilos (t.glaser@tarent.de)
     */
    public static class AbstractJensActor {
        /**
         * <p>Auxilliary data associated with the record.</p>
         *
         * <p>A single object of a single type is used for simplicity and, more
         * importantly, speed. Only some fields are supported for each record
         * type:</p>
         *
         * <p>QueueSize:</p><ul>
         * <li>{@link #timestamp}</li>
         * <li>{@link #len}</li>
         * <li>{@link #mem}</li>
         * </ul>
         *
         * <p>Packet:</p><ul>
         * <li>{@link #timestamp}</li>
         * <li>{@link #sojournTime}</li>
         * <li>{@link #chance}</li>
         * <li>{@link #ecnIn}</li>
         * <li>{@link #ecnOut}</li>
         * <li>{@link #ecnValid}</li>
         * <li>{@link #markCoDel}</li>
         * <li>{@link #markJENS}</li>
         * <li>{@link #dropped}</li>
         * </ul>
         *
         * <p>Unknown:</p><ul>
         * <li>{@link #timestamp}</li>
         * <li>{@link #type}</li>
         * </ul>
         *
         * @author mirabilos (t.glaser@tarent.de)
         */
        protected static final class Record {

            /* valid for all record types */

            /**
             * <p>Timestamp in nanoseconds for the record.</p>
             *
             * <p>Used in all record types.</p>
             */
            public @Unsigned long timestamp;

            /* only valid for QueueSize */

            /**
             * <p>Length of the queue (number of packets in the queue).</p>
             *
             * <p>Capped at 0xFFFF, which will also be shown if there are more
             * than 65535 packets in the queue. Normally, the queue is sizef for
             * 10240 packets only, so this should not be an issue.</p>
             *
             * <p>{@link #handleQueueSize()} only.</p>
             */
            public @Positive(max = 0x0000FFFFL) int len;
            /**
             * <p>Memory usage of the queue in bytes.</p>
             *
             * <p>{@link #handleQueueSize()} only.</p>
             */
            public @Positive(max = 0xFFFFFFFFL) long mem;

            /* only valid for Packet */

            /**
             * <p>Sojourn time of this packet in the FIFO, in nanoseconds.</p>
             *
             * <p>Note this may be 0x3FFFFFFFC00L, for example if the packet
             * was dropped while the queue was resized, or if it could not
             * be determined otherwise.</p>
             *
             * <p>{@link #handlePacket()} only.</p>
             */
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
             * <p>{@link #handlePacket()} only.</p>
             */
            public double chance;
            /**
             * <p>ECN bits of the packet when arriving, if any (see {@link #ecnValid}).</p>
             *
             * <p>{@link #handlePacket()} only.</p>
             */
            public @Positive(max = 3) int ecnIn;
            /**
             * <p>ECN bits of the packet when leaving, if any (see {@link #ecnValid}).</p>
             *
             * <p>{@link #handlePacket()} only.</p>
             */
            public @Positive(max = 3) int ecnOut;
            /**
             * <p>Whether the ECN bits are valid.</p>
             *
             * <p>The ECN bits can only be valid for IP (IPv6) and Legacy IP (IPv4)
             * packets, not other packet types (such as ARP), and when the packet
             * fragment is not too short. Having this flag false is not a problem.</p>
             *
             * <p>{@link #handlePacket()} only.</p>
             */
            public boolean ecnValid;
            /**
             * <p>Whether the packet was ECN CE marked because {@code target} was not
             * reached within {@code interval} (CoDel algorithm).</p>
             *
             * <p>Note that this flag can be set even if the packet was not ECN-capable.
             * The packet is dropped by the CoDel algorithm in those cases.</p>
             *
             * <p>{@link #handlePacket()} only.</p>
             */
            public boolean markCoDel;
            /**
             * <p>Whether the packet was ECN CE marked due to the JENS algorithm,
             * based on {@code markfull} and {@code markfree} as well as the
             * {@link #chance} and the actual random value from the kernel.</p>
             *
             * <p>Note that this flag can be set even if the packet was not ECN-capable.
             * The packet is neither marked nor dropped in that case.</p>
             *
             * <p>{@link #handlePacket()} only.</p>
             */
            public boolean markJENS;
            /**
             * <p>Whether the packet was dropped (instead of passed on) on leaving.</p>
             *
             * <p>{@link #handlePacket()} only.</p>
             */
            public boolean dropped;

            /* only valid for Unknown */

            /**
             * <p>The type octet of the record line.</p>
             *
             * <p>{@link #handleUnknown()} only.</p>
             */
            public byte type;
        }

        protected final Record r;

        public AbstractJensActor() {
            r = new Record();
        }

        /**
         * <p>Handles queue-size records (periodically).</p>
         *
         * <p>Access the field {@link Record} {@code r} to get the record data.</p>
         *
         * <p>The default implementation does nothing. Override only when needed.</p>
         */
        public void handleQueueSize() {
        }

        /**
         * <p>Handles packet records (one for each packet leaving the queue).</p>
         *
         * <p>Access the field {@link Record} {@code r} to get the record data.</p>
         *
         * <p>The default implementation does nothing. Override only when needed.</p>
         */
        public void handlePacket() {
        }

        /**
         * <p>Handles unknown records (all other XML tags not listed above).</p>
         *
         * <p>Access the field {@link Record} {@code r} to get the record data.</p>
         *
         * <p>The default implementation does nothing. Override only when needed.</p>
         */
        public void handleUnknown() {
        }
    }

    private static final String DEFAULT_JENSDMP_PATH = "/usr/libexec/jensdmp";

    /**
     * <p>Initialises a JensReader instance and returns it.</p>
     *
     * <p>(This is a separate method because throwing exceptions in
     * constructors is not a very good idea, and this method can throw a lot.)</p>
     *
     * <p>Make sure to call {@link #done()} to terminate the subprocess if it is
     * no longer needed. (The {@link JensReader#run()} method does this, and a
     * JVM shutdown hook to do so is also set up in case the process is killed.)</p>
     *
     * @param jensdmpExecutable path to {@code jensdmp}, or {@code null} for default
     * @param args              arguments to pass to {@code jensdmp}
     * @param actor             an instance of an {@link AbstractJensActor} subclass
     * @return an object whose {@link JensReader#run()} method can be called
     * @throws ParserConfigurationException if the XML parser complains
     * @throws IOException                  on most other errors
     */
    public static JensReader init(final Path jensdmpExecutable, final String[] args,
      final AbstractJensActor actor) throws ParserConfigurationException, IOException {
        /* configure decimal separator */

        new JNI().open(args[0]);

        // this is awful but we can’t directly use NumberFormat…
        final NumberFormat numberFormat = NumberFormat.getInstance();
        if (numberFormat instanceof DecimalFormat) {
            final DecimalFormat decimalFormat = (DecimalFormat) numberFormat;
            final DecimalFormatSymbols symbols = decimalFormat.getDecimalFormatSymbols();
            decimal = symbols.getDecimalSeparator();
        } else {
            decimal = '.';
        }

        /* configure XML parser */

        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        final DocumentBuilder db = dbf.newDocumentBuilder();

        /* configure and start subprocess */

        if (needToInstallShutdownHook) {
            /* this is installed only once */
            Runtime.getRuntime().addShutdownHook(new Thread(JensReaderLib::done));
            needToInstallShutdownHook = false;
        }
        final ArrayList<String> argv = new ArrayList<>();
        argv.add(jensdmpExecutable == null ? DEFAULT_JENSDMP_PATH :
          jensdmpExecutable.toAbsolutePath().toString());
        argv.addAll(Arrays.asList(args));
        p = new ProcessBuilder(argv)
          .redirectInput(ProcessBuilder.Redirect.INHERIT)
          .redirectError(ProcessBuilder.Redirect.INHERIT)
          .start();
        /* everything below here MUST be within the following try block */

        try {
            /* access subprocess’ stdout */
            final Reader r = new InputStreamReader(p.getInputStream());

            /* initialise internal parser instance */
            return new JensReader(new BufferedReader(r), actor, db);
        } catch (final Exception e) {
            // ensure the subprocess is cleaned up if there were errors
            done();
            throw e;
        }
    }

    /**
     * Internal class doing the actual reading and parsing.
     *
     * @author mirabilos (t.glaser@tarent.de)
     */
    protected static class JensReader {
        private final BufferedReader reader;
        private final DocumentBuilder db;
        private final AbstractJensActor actor;
        private Element e;

        private JensReader(final BufferedReader xreader, final AbstractJensActor xactor, final DocumentBuilder xdb) {
            reader = xreader;
            actor = xactor;
            db = xdb;
        }

        /**
         * <p>Reads records from the {@code jensdmp} subprocess and calls the actor.</p>
         *
         * <p>If this method returns, the subprocess has signalled EOF.</p>
         *
         * @throws IOException  if reading from the subprocess fails
         * @throws SAXException if parsing the subprocess’ output fails
         */
        public void run() throws IOException, SAXException {
            //noinspection StatementWithEmptyBody
            while (handleLine(reader.readLine())) {
                // nothing
            }
            done();
        }

        @SuppressWarnings("SameParameterValue")
        private double getFloat(final String attributeName) {
            return Double.parseDouble(e.getAttribute(attributeName));
        }

        @SuppressWarnings("SameParameterValue")
        private @Unsigned long get64X(final String attributeName) {
            return Long.parseUnsignedLong(e.getAttribute(attributeName), 16);
        }

        private @Positive(max = 0xFFFFFFFFL) long get32X(final String attributeName) {
            final @Unsigned int d32 = Integer.parseUnsignedInt(e.getAttribute(attributeName), 16);
            // 0x00000000_00000000L‥0x00000000_FFFFFFFFL
            return Integer.toUnsignedLong(d32);
        }

        @SuppressWarnings("SameParameterValue")
        private @Positive(max = 0x0000FFFFL) int get16X(final String attributeName) {
            return Integer.parseInt(e.getAttribute(attributeName), 16);
        }

        private @Unsigned int get8b(final String attributeName) {
            return Integer.parseUnsignedInt(e.getAttribute(attributeName), 2);
        }

        private boolean has(final String attributeName) {
            return !("".equals(e.getAttribute(attributeName)));
        }

        private boolean handleLine(final String line) throws IOException, SAXException {
            if (line == null) {
                return false;
            }
            db.reset();
            final Document d = db.parse(new InputSource(new StringReader(line)));
            e = /* root element */ d.getDocumentElement();
            actor.r.timestamp = get64X("ts");
            switch (e.getTagName()) {
            case "Qsz":
                actor.r.len = get16X("len");
                actor.r.mem = get32X("mem");
                actor.handleQueueSize();
                break;
            case "pkt":
                actor.r.sojournTime = get32X("time") * 1024L;
                actor.r.chance = getFloat("chance");
                actor.r.ecnIn = get8b("ecn-in");
                actor.r.ecnOut = get8b("ecn-out");
                actor.r.ecnValid = has("ecn-valid");
                actor.r.markCoDel = has("slow");
                actor.r.markJENS = has("mark");
                actor.r.dropped = has("drop");
                actor.handlePacket();
                break;
            default:
                actor.r.type = /*XXX*/ (byte) 0xFF;
                actor.handleUnknown();
                break;
            }
            return true;
        }
    }

    /**
     * <p>Terminates the subprocess if it is still running.</p>
     *
     * <p>This is called with {@link JensReader#run()} finishes successfully
     * and in a JVM shutdown hook but may be explicitly called if so desired.</p>
     *
     * <p>This method is synchronised and idempotent.</p>
     */
    public static synchronized void done() {
        if (p != null) {
            p.destroy();
            p = null;
        }
    }
}

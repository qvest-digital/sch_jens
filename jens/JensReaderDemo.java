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

import java.net.NetworkInterface;
import java.util.Arrays;

/**
 * <p>Example main() for the sch_jens relayfs channel reader.</p>
 *
 * <p>This is not an example of good error handling… namely, it does not have
 * any at all. This merely serves to instruct how to parse the statistics.</p>
 *
 * @author mirabilos (t.glaser@tarent.de)
 */
public final class JensReaderDemo {
    /**
     * <p>Callback actions for incoming records.</p>
     *
     * <p>This example just prints all lines. (Note: it is not necessary to
     * override <i>all</i> methods; any methods not overrided will simply
     * not do anything.)</p>
     *
     * @author mirabilos (t.glaser@tarent.de)
     */
    private static class DemoActor extends JensReaderLib.AbstractJensActor {
        private DemoActor(final NetworkInterface iface) {
            super(iface);
        }

        @Override
        public void handleQueueSize(final JensReaderLib.AbstractJensActor.Record[] r, final int n) {
            for (int i = 0; i < n; ++i) {
                System.out.printf("%03d/%03d ", i + 1, n);
                System.out.printf("[%17s] ", JensReaderLib.formatTimestamp(r[i].timestamp));
                System.out.printf("queue-size: %d packet%s, %.2f KiB\n", r[i].len,
                  r[i].len == 1 ? "" : "s", (double) r[i].mem / 1024.0);
            }
        }

        @Override
        public void handlePacket(final JensReaderLib.AbstractJensActor.Record[] r, final int n) {
            for (int i = 0; i < n; ++i) {
                System.out.printf("%03d/%03d ", i + 1, n);
                System.out.printf("[%17s] ", JensReaderLib.formatTimestamp(r[i].timestamp));
                System.out.printf("sojourn-time: %9s ms; ", JensReaderLib.formatTimestamp(r[i].sojournTime));
                if (r[i].ecnValid) {
                    System.out.printf("ECN bits %s → %s",
                      JensReaderLib.formatECNBits(r[i].ecnIn),
                      JensReaderLib.formatECNBits(r[i].ecnOut));
                } else {
                    System.out.print("no traffic class");
                }
                // note both of the following can indicate marking even for nōn-ECN packets
                // in that case, they aren’t marked (obviously); CoDel drops them, JENS doesn’t
                // (but JENS is defined to operate only with ECN-capable traffic) */
                System.out.printf("; JENS %7.3f%% (%s)", r[i].chance * 100.0,
                  r[i].markJENS ? "marked: CE" : "not marked");
                if (r[i].markCoDel) {
                    System.out.print("; CoDel marked");
                }
                if (r[i].dropped) {
                    System.out.print("; dropped");
                }
                if (r[i].ipVer != 0) {
                    System.out.printf("; IPv%d (%s → %s)", r[i].ipVer,
                      getSourceIP(r[i]).getHostAddress(),
                      getDestinationIP(r[i]).getHostAddress());
                }
                System.out.printf("; %d bytes; flow ID %d", r[i].pktSize, r[i].flowId);
                System.out.println();
            }
        }

        @Override
        public void handleUnknown(final JensReaderLib.AbstractJensActor.Record[] r, final int n) {
            for (int i = 0; i < n; ++i) {
                // we could extract the first two lines into a new method if needed
                System.out.printf("%03d/%03d ", i + 1, n);
                System.out.printf("[%17s] ", JensReaderLib.formatTimestamp(r[i].timestamp));
                System.out.printf("unknown: %X\n", r[i].type);
            }
        }
    }

    /**
     * <p>Retrieves {@code sch_jens} relayfs channel statistics and prints them.</p>
     *
     * <p>The {@code args[]} passed to the main function is stripped its first
     * element, which is expected to be the network interface name the sch_jens
     * queue runs on; all subsequent elements are handed on to the reader library,
     * which currently only expects one argument (the debugfs path), unchanged.</p>
     *
     * <p>Received records are parsed (using {@link JensReaderLib}); each is
     * (using {@link DemoActor}) merely formatted to stdout.</p>
     *
     * <p>This program requires superuser privileges in order to access the
     * debugfs file backing the relayfs channel. It does not drop privileges;
     * JENS runs as root anyway and this is an integration example).</p>
     *
     * @param args arguments to pass to the reader
     */
    public static void main(String[] args) {
        if (args.length < 2) {
            System.err.println("usage: java JensReaderDemo ifname path…");
            System.exit(1);
        }
        try {
            final NetworkInterface nif = NetworkInterface.getByName(args[0]);
            if (nif == null) {
                System.err.printf("network interface %s not found\n", args[0]);
                System.exit(1);
            }
            final String[] subargs = Arrays.copyOfRange(args, 1, args.length);
            // reader is autocloseable
            try (JensReaderLib.JensReader reader = JensReaderLib.init(subargs,
              new DemoActor(nif))) {
                System.out.printf("%03d/%03d ", 0, 0);
                System.out.printf("[%17s] ", JensReaderLib.formatTimestamp(0));
                System.out.println("JensReaderDemo ready to run!");
                reader.run();
            }
        } catch (Exception e) {
            System.err.println("Error: " + e);
            System.exit(1);
        }
        System.exit(0);
    }
}

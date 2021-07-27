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

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * <p>Example main() for the parser for the output of “jensdmp”.</p>
 *
 * <p>This is not an example of good error handling… namely, it does not have
 * any at all. This merely serves to instruct how to parse the output.</p>
 *
 * @author mirabilos (t.glaser@tarent.de)
 */
public final class JensReaderDemo {
    /**
     * <p>Callback actions for incoming lines.</p>
     *
     * <p>This example just prints all lines. (Note: it is not necessary to
     * override <i>all</i> methods; any methods not overrided will simply
     * not do anything.)</p>
     *
     * @author mirabilos (t.glaser@tarent.de)
     */
    private static class DemoActor extends JensReaderLib.AbstractJensActor {
        @Override
        public void handleQueueSize(final Record r) {
            System.out.printf("[%13s] ", JensReaderLib.formatTimestamp(r.timestamp));
            System.out.printf("queue-size: %d packets\n", r.len);
        }

        @Override
        public void handlePacket(final Record r) {
            System.out.printf("[%13s] ", JensReaderLib.formatTimestamp(r.timestamp));
            System.out.printf("sojourn-time: %9s ms; ", JensReaderLib.formatTimestamp(r.sojournTime));
            if (r.ecnValid) {
                System.out.printf("ECN bits %s → %s",
                  JensReaderLib.formatECNBits(r.ecnIn),
                  JensReaderLib.formatECNBits(r.ecnOut));
            } else {
                System.out.print("no traffic class");
            }
            System.out.printf("; JENS %6.2f%% (%s)", r.chance * 100.0,
              r.markJENS ? "marked: CE" : "not marked");
            if (r.markCoDel) {
                System.out.print("; CoDel marked");
            }
            if (r.dropped) {
                System.out.print("; dropped");
            }
            System.out.println();
        }

        @Override
        public void handleUnknown(final Record r) {
            System.out.printf("[%13s] ", JensReaderLib.formatTimestamp(r.timestamp));
            System.out.printf("unknown: %s\n", r.tagName);
        }
    }

    /**
     * <p>Runs {@code jensdmp} as a subprocess, parsing its output.</p>
     *
     * <p>The {@code jensdmp} executable is searched for in the current working
     * directory; it is used if it exists and is executable; otherwise, the
     * standard path is used. The {@code args[]} passed to the main function
     * are handed on to {@code jensdmp} unchanged; do make sure to pass anything
     * {@code jensdmp} needs, specifically the debugfs path.</p>
     *
     * <p>Received records are parsed (using {@link JensReaderLib}); each is
     * (using {@link DemoActor}) merely formatted to stdout.</p>
     *
     * <p>Because {@code jensdmp} must run as superuser initially to open the
     * debugfs file (even though it drops privileges later) this program must
     * also run as root (even though it does not drop privileges; JENS runs
     * as root anyway and this is intended as JENS integration example).</p>
     *
     * @param args arguments to pass to {@code jensdmp}
     */
    public static void main(String[] args) {
        try {
            // see if ./jensdmp is executable
            final Path cwdJensdmp = Paths.get("jensdmp");
            // use it if so, use default path (null) otherwise
            final Path pathToJensdmp = Files.isExecutable(cwdJensdmp) ? cwdJensdmp : null;
            JensReaderLib.init(args, new DemoActor(), pathToJensdmp).run();
        } catch (Exception e) {
            System.err.println("Error: " + e);
            System.exit(1);
        }
        System.exit(0);
    }
}

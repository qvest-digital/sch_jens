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

/**
 * <p>Example parser for the output of the “jensdmp” C program.</p>
 *
 * <p>This is not an example of good error handling… namely, it does not have
 * any at all. This merely serves to instruct how to parse the output.</p>
 *
 * <p>The XML parser averages 1 ms for each record on my laptop once warmed up,
 * which is well below the intervals of 5 ms for periodic reports. Data rates
 * nearing 10 Mbit/s will saturate it, however (at ~1000 byte-sized packets).
 * Do ensure to reduce the bandwidth below that when using statistics.</p>
 *
 * @author mirabilos (t.glaser@tarent.de)
 */
public final class JensReader {
    public static void main(String[] args) {
        try {
            final JensReader jr = init(new InputStreamReader(System.in));
            jr.go();
        } catch (Exception e) {
            System.err.println("Error: " + e);
            System.exit(1);
        }
        System.exit(0);
    }

    private static JensReader init(final Reader r)
      throws ParserConfigurationException {
        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        final DocumentBuilder db = dbf.newDocumentBuilder();
        return new JensReader(new BufferedReader(r), db);
    }

    final BufferedReader reader;
    final DocumentBuilder db;

    private JensReader(final BufferedReader r, final DocumentBuilder xdb) {
        reader = r;
        db = xdb;
    }

    private void go() throws IOException, SAXException {
        //noinspection StatementWithEmptyBody
        while (one(reader.readLine())) {
            // nothing
        }
    }

    private boolean one(final String line) throws IOException, SAXException {
        if (line == null) {
            return false;
        }
        db.reset();
        final Document d = db.parse(new InputSource(new StringReader(line)));
        final Element root = d.getDocumentElement();
        System.out.printf("element %s with id %s\n",
          root.getTagName(), root.getAttribute("id"));
        return true;
    }
}

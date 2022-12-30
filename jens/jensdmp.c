/*-
 * Copyright © 2021, 2022
 *	mirabilos <t.glaser@tarent.de>
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

#include <sys/types.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

/* prerequisite kernel headers */
#include <linux/types.h>
#include <linux/pkt_sched.h>
#include "../janz/janz_uapi.h"

#ifndef INFTIM
#define INFTIM (-1)
#endif

#define BIT(n) (1U << (n))

#define RBUF_TARGETSIZE (65536U)
#define RBUF_SUBBUFSIZE (RBUF_TARGETSIZE / (TC_JANZ_RELAY_NRECORDS * sizeof(struct tc_janz_relay)))
#define RBUF_ELEMENTLEN (RBUF_SUBBUFSIZE * TC_JANZ_RELAY_NRECORDS)

struct tc_janz_relay rbuf[RBUF_SUBBUFSIZE < 1 ? -1 : (long)RBUF_ELEMENTLEN];
#define cbuf ((char *)rbuf)
/* compile-time assertion */
struct cta_rbufsize { char ok[sizeof(rbuf) == RBUF_TARGETSIZE ? 1 : -1]; };

static void consume(size_t);
static void tsv_show(size_t);
static void tsv_header(void);

static volatile sig_atomic_t do_exit = 0;

/* should be /var/empty but Debian doesn’t have that */
#define CHROOT_TARGETDIR	"/root"
/* nobody user, or a dedicated one */
#define PRIVDROP_UID		65534
#define PRIVDROP_GID		65534

static const gid_t privdrop_gid = PRIVDROP_GID;

static void
drop_privs(void)
{
	/* drop privileges so we stop running as root */
	if (chroot(CHROOT_TARGETDIR))
		err(1, "chroot");
	if (chdir("/"))
		err(1, "chdir");
	if (setgroups(1, &privdrop_gid))
		err(1, "setgroups");
	if (setresgid(PRIVDROP_GID, PRIVDROP_GID, PRIVDROP_GID))
		err(1, "setresgid");
	if (setresuid(PRIVDROP_UID, PRIVDROP_UID, PRIVDROP_UID))
		err(1, "setresuid");
}

static void
sighandler(int signo)
{
	do_exit = signo;
}

static const struct sigaction sa = {
	.sa_handler = &sighandler,
};

int
main(int argc, char *argv[])
{
	int fd;
	size_t n, off = 0;
	struct pollfd pfd;
	int pres;
	int format = 0;

	if (argc == 3 && !strcmp(argv[1], "-t"))
		format = 1;
	else if (argc != 2)
		errx(255, "Usage: %s [-t] /path/to/debugfs/sch_janz/nnnn:0",
		    argc > 0 ? argv[0] : "jensdmp");

#define setup_signal(sig) \
	if (sigaction((sig), &sa, NULL)) \
		err(1, "sigaction: %s", #sig)
	setup_signal(SIGHUP);
	setup_signal(SIGINT);
	setup_signal(SIGPIPE);
	setup_signal(SIGTERM);
#undef setup_signal

	if ((fd = open(argv[1 + format], O_RDONLY)) == -1)
		err(1, "open");

	/* switch away from running as root */
	drop_privs();

	if (format)
		tsv_header();

 loop:
	if (do_exit)
		goto do_exit;
	pfd.fd = fd;
	pfd.events = POLLIN;
	pres = poll(&pfd, 1, INFTIM);
	if (do_exit)
		goto do_exit;
	if (pres == -1) {
		if (errno == EINTR)
			goto loop;
		err(2, "poll");
	}
#ifndef NDEBUG
	if (pres != 1)
		errx(2, "poll returned %d", pres);
#endif
	/* pres == 1, (pfd.revents & (POLLIN | POLLRDNORM)) is true */
	if ((n = read(fd, cbuf + off, sizeof(rbuf) - off)) == (size_t)-1) {
		if (errno == EINTR)
			goto loop;
		err(2, "read");
	}
	if (n == 0)
		goto eof;
	off += n;
	//printf(" read(%04zX)", n);
	if (off < sizeof(struct tc_janz_relay))
		goto loop;
	//printf(" consume(%04zX)\n", off);

	n = 0;
	while ((n + sizeof(struct tc_janz_relay)) <= off) {
		(format ? tsv_show : consume)(n / sizeof(struct tc_janz_relay));
		n += sizeof(struct tc_janz_relay);
		if (do_exit)
			goto do_exit;
	}
	if (n < off)
		memcpy(cbuf, cbuf + n, off - n);
	off -= n;
	goto loop;

 eof:
	putchar('\r');
	fflush(NULL);
	errx(3, "end of input reached");
 do_exit:
	putchar('\r');
	fflush(NULL);
	warnx("exiting on signal %d", do_exit);
	close(fd);

	return (0);
}

#define IPADDRFMTLEN	((size_t)(INET_ADDRSTRLEN > INET6_ADDRSTRLEN ? \
			 INET_ADDRSTRLEN : INET6_ADDRSTRLEN))
static inline void
ipfmt(char dst[IPADDRFMTLEN], const unsigned char *src, int ipver)
{
	switch (ipver) {
	case 4:
		ipver = AF_INET;
		src += 12;
		break;
	case 6:
		ipver = AF_INET6;
		break;
	default:
		errx(1, "unknown IP version: %d", ipver);
	}
	if (!inet_ntop(ipver, src, dst, IPADDRFMTLEN))
		err(1, "inet_ntop");
}

static void
consume(size_t idx)
{
	char ipsrc[IPADDRFMTLEN], ipdst[IPADDRFMTLEN];

	//printf("%03zX [%llu.%09u] ", idx + 1U,
	//    (unsigned long long)(rbuf[idx].ts / 1000000000),
	//    (unsigned int)(rbuf[idx].ts % 1000000000));
	switch (rbuf[idx].type) {
	case TC_JANZ_RELAY_INVALID:
	default:
#ifdef show_invalid_records
		printf("<invalid type=\"%02X\"", rbuf[idx].type);
 dump:
		printf(" ts=\"%llX\" f=\"%02X\" e=\"%04X\" d=\"%08X\"/>\n",
		    (unsigned long long)rbuf[idx].ts,
		    rbuf[idx].f8, rbuf[idx].e16, rbuf[idx].d32);
#endif
		break;

	case TC_JANZ_RELAY_PADDING:
#ifdef show_invalid_records
		printf("<padding");
		goto dump;
#endif

	case TC_JANZ_RELAY_SOJOURN:
		printf("<pkt ts=\"%llX\" time=\"%X\" chance=\"%.7f\""
		    " ecn-in=\"%d%d\" ecn-out=\"%d%d\"",
		    (unsigned long long)rbuf[idx].ts, rbuf[idx].d32,
		    (double)rbuf[idx].e16 / TC_JANZ_RELAY_SOJOURN_PCTDIV,
		    !!(rbuf[idx].f8 & BIT(1)), !!(rbuf[idx].f8 & BIT(0)),
		    !!(rbuf[idx].f8 & BIT(4)), !!(rbuf[idx].f8 & BIT(3)));
		//if (rbuf[idx].f8 & TC_JANZ_RELAY_SOJOURN_SLOW)
		//	fputs(" slow=\"y\"", stdout);
		if (rbuf[idx].f8 & TC_JANZ_RELAY_SOJOURN_MARK)
			fputs(" mark=\"y\"", stdout);
		if (rbuf[idx].f8 & TC_JANZ_RELAY_SOJOURN_DROP)
			fputs(" drop=\"y\"", stdout);
		if (rbuf[idx].f8 & BIT(2))
			fputs(" ecn-valid=\"y\"", stdout);
		if (rbuf[idx].z.zSOJOURN.ipver) {
			ipfmt(ipsrc, rbuf[idx].x8, rbuf[idx].z.zSOJOURN.ipver);
			ipfmt(ipdst, rbuf[idx].y8, rbuf[idx].z.zSOJOURN.ipver);
			printf(" ip=\"%u\" l4=\"%u\" srcip=\"%s\" dstip=\"%s\"",
			    (unsigned)rbuf[idx].z.zSOJOURN.ipver,
			    (unsigned)rbuf[idx].z.zSOJOURN.nexthdr,
			    ipsrc, ipdst);
			if (rbuf[idx].z.zSOJOURN.nexthdr == 6 ||
			    rbuf[idx].z.zSOJOURN.nexthdr == 17)
				printf(" srcport=\"%u\" dstport=\"%u\"",
			    (unsigned)rbuf[idx].z.zSOJOURN.sport,
			    (unsigned)rbuf[idx].z.zSOJOURN.dport);
		}
		printf(" real-owd=\"%X\" size=\"%u\"/>\n",
		    rbuf[idx].z.zSOJOURN.real_owd,
		    rbuf[idx].z.zSOJOURN.psize);
		break;

	case TC_JANZ_RELAY_QUEUESZ:
		printf("<Qsz ts=\"%llX\" len=\"%X\" mem=\"%X\""
		    " tsofs=\"%llX\" bw=\"%llu\"",
		    (unsigned long long)rbuf[idx].ts,
		    (unsigned int)rbuf[idx].e16, (unsigned int)rbuf[idx].d32,
		    (unsigned long long)rbuf[idx].x64[1],
		    (unsigned long long)rbuf[idx].x64[0]);
		if (rbuf[idx].f8 & TC_JANZ_RELAY_QUEUESZ_HOVER)
			fputs(" handover=\"starting\"", stdout);
		printf("/>\n");
		break;

	case TC_JANZ_RELAY_WDOGDBG:
		printf("<wdog ts=\"%llX\" early=\"%X\" u50=\"%llX\""
		   " u1m=\"%llX\" u4m=\"%llX\" a4m=\"%llX\"",
		    (unsigned long long)rbuf[idx].ts,
		    (unsigned int)rbuf[idx].e16,
		    (unsigned long long)rbuf[idx].x64[0],
		    (unsigned long long)rbuf[idx].x64[1],
		    (unsigned long long)rbuf[idx].y64[0],
		    (unsigned long long)rbuf[idx].y64[1]);
		if (rbuf[idx].f8 != 0)
			printf(" c=\"%s\" d=\"%s%u\"",
			    (rbuf[idx].f8 & 0x30) == 0x10 ? "notbef" :
			    (rbuf[idx].f8 & 0x30) == 0x20 ? "ntsend" : "unkERR",
			    (rbuf[idx].f8 & 2) ? "-" : "",
			    (unsigned int)rbuf[idx].d32);
		printf("/>\n");
		break;
	}
}

static void
tsv_header(void)
{
	/*
	 * Format:
	 * - uppercase = number
	 *   - with period
	 *   - & hexadecimal
	 * - question mark-suffixed = boolean (number 0 or 1)
	 * - lowercase = string
	 */
	puts("\"p|q|w\""
	    ",\"TS.\""
	    ",\"OWD.|MEMBYTES|wdogscheduled?\""
	    ",\"QDELAY.|NPKTS|NTOOEARLY\""
	    ",\"CHANCE|handover?|N50US\""
	    ",\"ecnin|BWLIM|N1MS\""
	    ",\"ecnout|TSOFS.|N4MS\""
	    ",\"bit5?|-|NLATER\""
	    ",\"mark?|-|(THISDELAY)\""
	    ",\"drop?|-|(&F8)\""
	    ",\"flow|-|-\""
	    ",\"PKTLEN|-|-\""
	    );
}

static const char ecnidx[5][5] = {
	"\"00\"", "\"01\"", "\"10\"", "\"11\"", "\"??\""
};

static void
tsv_show(size_t idx)
{
	unsigned int t2, u1, u2, u3, u4;
	unsigned long long ul1, t1;
	char ipsrc[IPADDRFMTLEN], ipdst[IPADDRFMTLEN];
	char flow[2U * IPADDRFMTLEN + 28];

	ul1 = rbuf[idx].ts;
	t1 = ul1 / 1000000000UL;
	t2 = ul1 % 1000000000UL;
	switch (rbuf[idx].type) {
	case TC_JANZ_RELAY_SOJOURN:
		if (rbuf[idx].z.zSOJOURN.ipver) {
			ipfmt(ipsrc, rbuf[idx].x8, rbuf[idx].z.zSOJOURN.ipver);
			ipfmt(ipdst, rbuf[idx].y8, rbuf[idx].z.zSOJOURN.ipver);
			if (rbuf[idx].z.zSOJOURN.nexthdr == 6 ||
			    rbuf[idx].z.zSOJOURN.nexthdr == 17)
				snprintf(flow, sizeof(flow),
				    "IPv%u %s [%s]:%u->[%s]:%u",
				    (unsigned int)rbuf[idx].z.zSOJOURN.ipver,
				    rbuf[idx].z.zSOJOURN.nexthdr == 6 ? "TCP" : "UDP",
				    ipsrc, (unsigned int)rbuf[idx].z.zSOJOURN.sport,
				    ipdst, (unsigned int)rbuf[idx].z.zSOJOURN.dport);
			else
				snprintf(flow, sizeof(flow),
				    "IPv%u x%02X [%s]->[%s]",
				    (unsigned int)rbuf[idx].z.zSOJOURN.ipver,
				    (unsigned int)rbuf[idx].z.zSOJOURN.nexthdr,
				    ipsrc, ipdst);
		} else
			memcpy(flow, "noIP", sizeof("noIP"));
		ul1 = rbuf[idx].d32;
		ul1 <<= 10;
		u1 = ul1 / 1000000000UL;
		u2 = ul1 % 1000000000UL;
		ul1 = rbuf[idx].z.zSOJOURN.real_owd;
		ul1 <<= 10;
		u3 = ul1 / 1000000000UL;
		u4 = ul1 % 1000000000UL;
		printf("\"p\"\t%llu.%09u\t%u.%09u\t%u.%09u\t%04X\t%s\t%s\t%u\t%u\t%u\t\"%s\"\t%u\n",
		    t1, t2,
		    u3, u4,
		    u1, u2,
		    (unsigned int)rbuf[idx].e16,
		    ecnidx[!(rbuf[idx].f8 & BIT(2)) ? 5 : ((unsigned int)rbuf[idx].f8 & 3U)],
		    ecnidx[!(rbuf[idx].f8 & BIT(2)) ? 5 : (((unsigned int)rbuf[idx].f8 >> 3) & 3U)],
		    !!(rbuf[idx].f8 & BIT(5)),
		    !!(rbuf[idx].f8 & BIT(6)),
		    !!(rbuf[idx].f8 & BIT(7)),
		    flow,
		    (unsigned int)rbuf[idx].z.zSOJOURN.psize);
		break;

	case TC_JANZ_RELAY_QUEUESZ:
		ul1 = rbuf[idx].x64[1];
		u2 = ul1 % 1000000000UL;
		ul1 /= 1000000000UL;
		printf("\"q\"\t%llu.%09u\t%u\t%u\t%u\t%llu\t%llu.%09u\n",
		    t1, t2,
		    (unsigned int)rbuf[idx].d32,
		    (unsigned int)rbuf[idx].e16,
		    !!(rbuf[idx].f8 & BIT(0)),
		    (unsigned long long)rbuf[idx].x64[0],
		    ul1, u2);
		break;

	case TC_JANZ_RELAY_WDOGDBG:
		if (!(rbuf[idx].f8))
			printf("\"w\"\t%llu.%09u\t0\t%u\t%llu\t%llu\t%llu\t%llu\n",
			    t1, t2,
			    (unsigned int)rbuf[idx].e16,
			    (unsigned long long)rbuf[idx].x64[0],
			    (unsigned long long)rbuf[idx].x64[1],
			    (unsigned long long)rbuf[idx].y64[0],
			    (unsigned long long)rbuf[idx].y64[1]);
		else
			printf("\"w\"\t%llu.%09u\t1\t%u\t%llu\t%llu\t%llu\t%llu\t%u\t%02X\n",
			    t1, t2,
			    (unsigned int)rbuf[idx].e16,
			    (unsigned long long)rbuf[idx].x64[0],
			    (unsigned long long)rbuf[idx].x64[1],
			    (unsigned long long)rbuf[idx].y64[0],
			    (unsigned long long)rbuf[idx].y64[1],
			    (unsigned int)rbuf[idx].d32,
			    (unsigned int)rbuf[idx].f8);
		break;

	default:
		/* just ignore */
		break;
	}
}

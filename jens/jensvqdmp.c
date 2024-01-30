/*-
 * Copyright © 2021, 2022, 2023
 *	mirabilos <t.glaser@tarent.de>
 * Copyright © 2024
 *	mirabilos <t.glaser@qvest-digital.com>
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

#define RBUF_TARGETSIZE (65536U)
#define RBUF_SUBBUFSIZE (RBUF_TARGETSIZE / (TC_JENSVQ_RELAY_NRECORDS * sizeof(struct jensvq_relay)))
#define RBUF_ELEMENTLEN (RBUF_SUBBUFSIZE * TC_JENSVQ_RELAY_NRECORDS)

struct jensvq_relay rbuf[RBUF_SUBBUFSIZE < 1 ? -1 : (long)RBUF_ELEMENTLEN];
#define cbuf ((char *)rbuf)
/* compile-time assertion */
struct cta_rbufsize { char ok[sizeof(rbuf) == RBUF_TARGETSIZE ? 1 : -1]; };

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

	if (argc != 2)
		errx(255, "Usage: %s /path/to/debugfs/sch_jensvq/nnnn:",
		    argc > 0 ? argv[0] : "jensvqdmp");

#define setup_signal(sig) \
	if (sigaction((sig), &sa, NULL)) \
		err(1, "sigaction: %s", #sig)
	setup_signal(SIGHUP);
	setup_signal(SIGINT);
	setup_signal(SIGPIPE);
	setup_signal(SIGTERM);
#undef setup_signal

	if ((fd = open(argv[1], O_RDONLY)) == -1)
		err(1, "open");

	/* switch away from running as root */
	drop_privs();

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
	if (off < sizeof(struct jensvq_relay))
		goto loop;
	//printf(" consume(%04zX)\n", off);

	n = 0;
	while ((n + sizeof(struct jensvq_relay)) <= off) {
		tsv_show(n / sizeof(struct jensvq_relay));
		n += sizeof(struct jensvq_relay);
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
tsv_header(void)
{
	/*
	 * Format:
	 * - uppercase = number
	 *   - with period
	 *   - & hexadecimal
	 * - question mark-suffixed = boolean (number 0 or 1)
	 * - caret-suffixed = char
	 * - lowercase unsuffixed = string
	 */
	puts("\"VTS.\""
	    ",\"HTS.\""
	    ",\"flow\""
	    ",\"&FLAGS\""	/* 8 nybbles */
	    ",\"kind^\""	/* 1=pkt-ok 2=handover 4=pkt-drop */
	    ",\"mark?\""
	    ",\"ue^\""		/* 0‥7 or Y=bypass */
	    ",\"PSIZE\""
	    ",\"UEPKTS\""
	    ",\"UEBYTES\""
	    ",\"&IPTOS\""	/* 2 nybbles */
	    ",\"VBW\""
	    ",\"RBW\""
	    ",\"VQDELAY.\""
	    ",\"RQDELAY.\""
	    ",\"OWDELAY.\""
	    );
	fflush(NULL);
}

struct ts {
	unsigned long long s;
	unsigned int ns;
};

static inline struct ts
tots(__u64 inval)
{
	struct ts rv;

	rv.s = inval / 1000000000ULL;
	rv.ns = inval % 1000000000ULL;
	return (rv);
}

static void
tsv_show(size_t idx)
{
	char ipsrc[IPADDRFMTLEN], ipdst[IPADDRFMTLEN];
	/*       IPv  6   _  TCP  _[  <--ip---------->  ]: port ->[  <--ip---------->  ]: port NUL */
	char flow[3 + 1 + 1 + 3 + 2 + IPADDRFMTLEN - 1 + 2 + 5 + 3 + IPADDRFMTLEN - 1 + 2 + 5 + 1];
	struct ts vts, hts, vqdelay, rqdelay, owdelay;
	int ipv, kind, ue;

	vts = tots(rbuf[idx].vts);
	hts = tots(rbuf[idx].hts);
	switch (JENS_GET(JENSVQ_Fipv, rbuf[idx].flags)) {
	case 1:
		ipv = 6;
		if (0)
			/* FALLTHROUGH */
	case 2:
		  ipv = 4;
		ipfmt(ipsrc, rbuf[idx].srcip.s6_addr, ipv);
		ipfmt(ipdst, rbuf[idx].dstip.s6_addr, ipv);
		if (rbuf[idx].nh == 6 || rbuf[idx].nh == 17)
			snprintf(flow, sizeof(flow),
			    "IPv%d %s [%s]:%u->[%s]:%u",
			    ipv, rbuf[idx].nh == 6 ? "TCP" : "UDP",
			    ipsrc, (unsigned int)rbuf[idx].sport,
			    ipdst, (unsigned int)rbuf[idx].dport);
		else
			snprintf(flow, sizeof(flow),
			    "IPv%d x%02X [%s]->[%s]",
			    ipv, (unsigned int)rbuf[idx].nh,
			    ipsrc, ipdst);
		break;
	case 0:
		snprintf(flow, sizeof(flow), "not IP");
		break;
	default:
		snprintf(flow, sizeof(flow), "invalid IP field");
		break;
	}
	switch (JENS_GET(JENSVQ_Ftype, rbuf[idx].flags)) {
	case 0:
		/* padding, ignore */
		return;
	case 1:
		kind = JENS_GET(JENSVQ_Fdrop, rbuf[idx].flags) ? '4' : '1';
		break;
	case 2:
		snprintf(flow, sizeof(flow), "handover");
		kind = '2';
		break;
	default:
		snprintf(flow, sizeof(flow), "invalid type");
		kind = '0';
		break;
	}
	ue = JENS_GET(JENSVQ_Fbypass, rbuf[idx].flags) ? 'Y' :
	    '0' + JENS_GET(JENSVQ_Fuenum, rbuf[idx].flags);
	vqdelay = tots(rbuf[idx].vqdelay);
	rqdelay = tots(rbuf[idx].rqdelay);
	owdelay = tots(rbuf[idx].owdelay);
	printf("%llu.%09u"
	    "	%llu.%09u"
	    "	\"%s\""
	    "	%08X"
	    "	%c"
	    "	%d"
	    "	%c"
	    "	%u"
	    "	%u"
	    "	%u"
	    "	%02X"
	    "	%llu"
	    "	%llu"
	    "	%llu.%09u"
	    "	%llu.%09u"
	    "	%llu.%09u"
	    "\n",
	    vts.s, vts.ns,
	    hts.s, hts.ns,
	    flow,
	    (unsigned int)rbuf[idx].flags,
	    kind,
	    !!JENS_GET(JENSVQ_Fmark, rbuf[idx].flags),
	    ue,
	    (unsigned int)rbuf[idx].psize,
	    (unsigned int)rbuf[idx].upkts,
	    (unsigned int)rbuf[idx].ubytes,
	    (unsigned int)rbuf[idx].tos,
	    (unsigned long long)rbuf[idx].vbw,
	    (unsigned long long)rbuf[idx].rbw,
	    vqdelay.s, vqdelay.ns,
	    rqdelay.s, rqdelay.ns,
	    owdelay.s, owdelay.ns);
}

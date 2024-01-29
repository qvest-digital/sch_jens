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
#define RBUF_SUBBUFSIZE (RBUF_TARGETSIZE / (TC_JENSVQ_RELAY_NRECORDS * sizeof(struct tc_jensvq_relay)))
#define RBUF_ELEMENTLEN (RBUF_SUBBUFSIZE * TC_JENSVQ_RELAY_NRECORDS)

struct tc_jensvq_relay rbuf[RBUF_SUBBUFSIZE < 1 ? -1 : (long)RBUF_ELEMENTLEN];
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
	if (off < sizeof(struct tc_jensvq_relay))
		goto loop;
	//printf(" consume(%04zX)\n", off);

	n = 0;
	while ((n + sizeof(struct tc_jensvq_relay)) <= off) {
		tsv_show(n / sizeof(struct tc_jensvq_relay));
		n += sizeof(struct tc_jensvq_relay);
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

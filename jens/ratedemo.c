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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* prerequisite kernel headers */
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/pkt_sched.h>
#include "../janz/janz_uapi.h"

#if JANZ_CTLFILE_VERSION != 1
# error adapt me to the JANZ_CTLFILE_VERSION
#else

static volatile sig_atomic_t do_exit = 0;

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
	int direction = 0;
	int fd;
	struct janz_ctlfile_pkt pkt;
	struct timespec ts;

	/* 10 Mbit/s as starting bandwidth */
	pkt.bits_per_second = 10000000ULL;

	if (argc != 2)
		errx(255, "Usage: %s /path/to/debugfs/sch_janz/nnnn:v1",
		    argc > 0 ? argv[0] : "ratedemo");

#define setup_signal(sig) \
	if (sigaction((sig), &sa, NULL)) \
		err(1, "sigaction: %s", #sig)
	setup_signal(SIGHUP);
	setup_signal(SIGINT);
	setup_signal(SIGPIPE);
	setup_signal(SIGTERM);
#undef setup_signal

	if ((fd = open(argv[1], O_WRONLY)) == -1)
		err(1, "open");

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		err(1, "clock_gettime");

 loop_forever:
	if (do_exit) {
 do_exit:
		printf("\rExiting from signal %d\n", do_exit);
		close(fd);
		return (0);
	}

	errno = 0;
	if (write(fd, &pkt, sizeof(pkt)) != sizeof(pkt)) {
		if (errno)
			warn("write");
		else
			warnx("short write");
	}

	/* sleep to the next multiple of 1/100th seconds */
	if ((ts.tv_nsec += 10000000LL) > 999999999LL) {
		ts.tv_nsec -= 1000000000LL;
		++ts.tv_sec;
		printf("I: rate is now %06.3f Mbit/s\n",
		    (double)pkt.bits_per_second / 1000000.);
	}
	errno = ENOSYS;
	while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL)) {
		if (do_exit)
			goto do_exit;
		if (errno != EINTR)
			err(1, "clock_nanosleep");
	}

	if (direction) {
		/* going down */
		pkt.bits_per_second -= 9000;
		/* minimum 5 Mbit/s */
		if (pkt.bits_per_second < 5000000ULL) {
			printf("I: rate is now %06.3f Mbit/s\n",
			    (double)pkt.bits_per_second / 1000000.);
			direction = 0;
		}
	} else {
		/* going up */
		pkt.bits_per_second += 9000;
		/* maximum 15 Mbit/s */
		if (pkt.bits_per_second > 15000000ULL) {
			printf("I: rate is now %06.3f Mbit/s\n",
			    (double)pkt.bits_per_second / 1000000.);
			direction = 1;
		}
	}

	goto loop_forever;
}

#endif /* prerequisite check */

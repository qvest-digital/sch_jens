/*-
 * Copyright © 2021, 2022, 2023
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

#define UENUM 8

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
	unsigned int i;
	int fd;
	__u64 xmin[UENUM], xmax[UENUM];
	unsigned char direction[UENUM];
	struct janz_ctlfile_pkt pkt[UENUM];
	struct timespec ts;

	if (argc != 2 + UENUM * 2)
		errx(255, "Usage: %s /path/to/debugfs/sch_janz/nnnn:v1 min0 max0 min1 … max6 min7 max7",
		    argc > 0 ? argv[0] : "mratedemo");

	for (i = 0; i < UENUM; ++i) {
		char *ep = NULL;

		errno = EDOM;
		xmin[i] = strtoull(argv[2U + 2U * i + 0U], &ep, 0);
		if (ep == argv[2U + 2U * i + 0U] || *ep != '\0')
			err(1, "%s%u %s: %s", "min", i, "invalid",
			    argv[2U + 2U * i + 0U]);
		if (xmin[i] < 1)
			err(1, "%s%u %s: %s", "min", i, "too small",
			    argv[2U + 2U * i + 0U]);
		if (xmin[i] >= 8000000ULL)
			err(1, "%s%u %s: %s", "min", i, "too large",
			    argv[2U + 2U * i + 0U]);

		errno = EDOM;
		xmax[i] = strtoull(argv[2U + 2U * i + 1U], &ep, 0);
		if (ep == argv[2U + 2U * i + 1U] || *ep != '\0')
			err(1, "%s%u %s: %s", "max", i, "invalid",
			    argv[2U + 2U * i + 1U]);
		if (xmax[i] < 1)
			err(1, "%s%u %s: %s", "max", i, "too small",
			    argv[2U + 2U * i + 1U]);
		if (xmax[i] >= 8000000ULL)
			err(1, "%s%u %s: %s", "max", i, "too large",
			    argv[2U + 2U * i + 1U]);

		xmin[i] *= 1000U;
		xmax[i] *= 1000U;
		pkt[i].bits_per_second = xmin[i];
		direction[i] = 0;

		if (xmin[i] > xmax[i]) {
			__u64 tmp;

			tmp = xmin[i];
			xmin[i] = xmax[i];
			xmax[i] = tmp;
			direction[i] = 1;
		}
		printf("UE#%02X start at %llu %swards, %llu-%llu kbps\n",
		    i, (unsigned long long)(pkt[i].bits_per_second / 1000U),
		    direction[i] ? "down" : "up",
		    (unsigned long long)(xmin[i] / 1000U),
		    (unsigned long long)(xmax[i] / 1000U));
	}

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
		printf("I: rate is now");
		for (i = 0; i < UENUM; ++i)
			printf(" %06.3f",
			    (double)pkt[i].bits_per_second / 1000000.);
		printf(" Mbit/s\n");
	}
	errno = ENOSYS;
	while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL)) {
		if (do_exit)
			goto do_exit;
		if (errno != EINTR)
			err(1, "clock_nanosleep");
	}

	for (i = 0; i < UENUM; ++i)
		if (direction[i]) {
			/* going down */
			if (pkt[i].bits_per_second < 9128)
				pkt[i].bits_per_second = xmin[i];
			else
				pkt[i].bits_per_second -= 9000;
			/* minimum */
			if (pkt[i].bits_per_second <= xmin[i])
				direction[i] = 0;
		} else {
			/* going up */
			pkt[i].bits_per_second += 9000;
			/* maximum */
			if (pkt[i].bits_per_second >= xmax[i])
				direction[i] = 1;
		}

	goto loop_forever;
}

#endif /* prerequisite check */

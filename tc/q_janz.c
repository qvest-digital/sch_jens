/*
 * Dǟ janz zesammene Kuh-Disk
 *
 * Copyright © 2022 mirabilos <t.glaser@tarent.de>
 * Licensor: Deutsche Telekom LLCTO
 *
 * This tc module is published under the GPLv2 or later.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "utils.h"
#include "tc_util.h"

static void
explain(void)
{
	fprintf(stderr, "Usage: ... qdisc"
	       " add ... janz [limit PACKETS] [rate RATE] [handover TIME]"
		"\n\t	[markfree TIME] [markfull TIME]"
		"\n\t	[subbufs NUMBER] [fragcache NUMBER]"
		"\n");
}

static void
__janz_ejal(const char *opt, const char *arg)
{
	fprintf(stderr, "Invalid %s: \"%s\"\n", opt, arg);
	explain();
}
#define janz_ejal(opt) do { __janz_ejal(#opt, *argv); return (-1); } while (0)

static int
janz_parse_opt(struct qdisc_util *qu, int argc, char **argv,
    struct nlmsghdr *n, const char *dev)
{
	unsigned int limit = 0;
	__u64 rate64 = 0;
	unsigned int handover = 0;
	unsigned int markfree = ~0U;
	unsigned int markfull = ~0U;
	unsigned int subbufs = ~0U;
	unsigned int fragcache = ~0U;
	struct rtattr *tail;

	while (argc > 0) {
		if (!strcmp(*argv, "limit")) {
			NEXT_ARG();
			if (get_unsigned(&limit, *argv, 0))
				janz_ejal(limit);
		} else if (!strcmp(*argv, "rate")) {
			NEXT_ARG();
			if (strchr(*argv, '%')) {
				if (get_percent_rate64(&rate64, *argv, dev))
					janz_ejal(rate);
			} else if (get_rate64(&rate64, *argv))
				janz_ejal(rate);
		} else if (!strcmp(*argv, "handover")) {
			NEXT_ARG();
			if (get_time(&handover, *argv))
				janz_ejal(handover);
		} else if (!strcmp(*argv, "markfree")) {
			NEXT_ARG();
			if (get_unsigned(&markfree, *argv, 0))
				janz_ejal(markfree);
		} else if (!strcmp(*argv, "markfull")) {
			NEXT_ARG();
			if (get_unsigned(&markfull, *argv, 0))
				janz_ejal(markfull);
		} else if (!strcmp(*argv, "subbufs")) {
			NEXT_ARG();
			if (get_unsigned(&subbufs, *argv, 0))
				janz_ejal(subbufs);
		} else if (!strcmp(*argv, "fragcache")) {
			NEXT_ARG();
			if (get_unsigned(&fragcache, *argv, 0))
				janz_ejal(fragcache);
		} else {
			fprintf(stderr, "Invalid option: \"%s\"\n", *argv);
			explain();
			return (-1);
		}
		--argc;
		--argv;
	}

	tail = addattr_nest(n, 1024, TCA_OPTIONS);
	if (limit)
		addattr_l(n, 1024, TCA_JANZ_LIMIT, &limit, sizeof(limit));
	if (rate64)
		addattr_l(n, 1024, TCA_JANZ_RATE64, &rate64, sizeof(rate64));
	if (handover)
		addattr_l(n, 1024, TCA_JANZ_HANDOVER, &handover, sizeof(handover));
	if (markfree != ~0U)
		addattr_l(n, 1024, TCA_JANZ_MARKFREE, &markfree, sizeof(markfree));
	if (markfull != ~0U)
		addattr_l(n, 1024, TCA_JANZ_MARKFULL, &markfull, sizeof(markfull));
	if (subbufs != ~0U)
		addattr_l(n, 1024, TCA_JANZ_SUBBUFS, &subbufs, sizeof(subbufs));
	if (fragcache != ~0U)
		addattr_l(n, 1024, TCA_JANZ_FRAGCACHE, &fragcache, sizeof(fragcache));
	addattr_nest_end(n, tail);
	return (0);
}

static int
janz_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
	struct rtattr *tb[TCA_JANZ_MAX + 1];
	unsigned int limit;
	__u64 rate64;
	unsigned int handover;
	unsigned int markfree;
	unsigned int markfull;
	unsigned int subbufs;
	unsigned int fragcache;

	SPRINT_BUF(b1);

	if (!opt)
		return (NULL);

	parse_rtattr_nested(tb, TCA_JANZ_MAX, opt);

	if (tb[TCA_JANZ_LIMIT] &&
	    RTA_PAYLOAD(tb[TCA_JANZ_LIMIT]) >= sizeof(limit)) {
		limit = rta_getattr_u32(tb[TCA_JANZ_LIMIT]);
		print_uint(PRINT_ANY, "limit", "limit %u ", limit);
	}
	if (tb[TCA_JANZ_RATE64] &&
	    RTA_PAYLOAD(tb[TCA_JANZ_RATE64]) >= sizeof(rate64)) {
		rate64 = rta_getattr_u64(tb[TCA_JANZ_RATE64]);
		print_string(PRINT_FP, NULL, "rate %s ",
		    sprint_rate(rate64, b1));
		print_lluint(PRINT_JSON, "rate", NULL, rate64);
	}
	if (tb[TCA_JANZ_HANDOVER] &&
	    RTA_PAYLOAD(tb[TCA_JANZ_HANDOVER]) >= sizeof(handover)) {
		handover = rta_getattr_u32(tb[TCA_JANZ_HANDOVER]);
		print_string(PRINT_FP, NULL, "handover %s ",
		    sprint_time(handover, b1));
		print_uint(PRINT_JSON, "handover", NULL, handover);
	}
	if (tb[TCA_JANZ_MARKFREE] &&
	    RTA_PAYLOAD(tb[TCA_JANZ_MARKFREE]) >= sizeof(markfree)) {
		markfree = rta_getattr_u32(tb[TCA_JANZ_MARKFREE]);
		print_string(PRINT_FP, NULL, "markfree %s ",
		    sprint_time(markfree, b1));
		print_uint(PRINT_JSON, "markfree", NULL, markfree);
	}
	if (tb[TCA_JANZ_MARKFULL] &&
	    RTA_PAYLOAD(tb[TCA_JANZ_MARKFULL]) >= sizeof(markfull)) {
		markfull = rta_getattr_u32(tb[TCA_JANZ_MARKFULL]);
		print_string(PRINT_FP, NULL, "markfull %s ",
		    sprint_time(markfull, b1));
		print_uint(PRINT_JSON, "markfull", NULL, markfull);
	}
	if (tb[TCA_JANZ_SUBBUFS] &&
	    RTA_PAYLOAD(tb[TCA_JANZ_SUBBUFS]) >= sizeof(subbufs)) {
		subbufs = rta_getattr_u32(tb[TCA_JANZ_SUBBUFS]);
		print_uint(PRINT_ANY, "subbufs", "subbufs %u ", subbufs);
	}
	if (tb[TCA_JANZ_FRAGCACHE] &&
	    RTA_PAYLOAD(tb[TCA_JANZ_FRAGCACHE]) >= sizeof(fragcache)) {
		fragcache = rta_getattr_u32(tb[TCA_JANZ_FRAGCACHE]);
		print_uint(PRINT_ANY, "fragcache", "fragcache %u ", fragcache);
	}

	return (0);
}

struct qdisc_util janz_qdisc_util = {
	.id		= "janz",
	.parse_qopt	= janz_parse_opt,
	.print_qopt	= janz_print_opt,
};

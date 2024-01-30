/*
 * JENS virtual queue-based marking real queue-based delimiting multi-UE qdisc
 *
 * Copyright © 2022 mirabilos <t.glaser@tarent.de>
 * Copyright © 2024 mirabilos <t.glaser@qvest-digital.com>
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
	       " add ... jensvq [limit PACKETS] [markfree TIME] [markfull TIME]"
		"\n\t	[subbufs NUMBER] [fragcache NUMBER] [extralatency TIME]"
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
	unsigned int markfree = ~0U;
	unsigned int markfull = ~0U;
	unsigned int subbufs = ~0U;
	unsigned int fragcache = ~0U;
	unsigned int extralatency = ~0U;
	struct rtattr *tail;

	while (argc > 0) {
		if (!strcmp(*argv, "limit")) {
			NEXT_ARG();
			if (get_unsigned(&limit, *argv, 0))
				janz_ejal(limit);
		} else if (!strcmp(*argv, "markfree")) {
			NEXT_ARG();
			if (get_time(&markfree, *argv))
				janz_ejal(markfree);
		} else if (!strcmp(*argv, "markfull")) {
			NEXT_ARG();
			if (get_time(&markfull, *argv))
				janz_ejal(markfull);
		} else if (!strcmp(*argv, "subbufs")) {
			NEXT_ARG();
			if (get_unsigned(&subbufs, *argv, 0))
				janz_ejal(subbufs);
		} else if (!strcmp(*argv, "fragcache")) {
			NEXT_ARG();
			if (get_unsigned(&fragcache, *argv, 0))
				janz_ejal(fragcache);
		} else if (!strcmp(*argv, "extralatency")) {
			NEXT_ARG();
			if (get_time(&extralatency, *argv))
				janz_ejal(extralatency);
		} else {
			fprintf(stderr, "Invalid option: \"%s\"\n", *argv);
			explain();
			return (-1);
		}
		--argc;
		++argv;
	}

	tail = addattr_nest(n, 1024, TCA_OPTIONS);
	if (limit)
		addattr_l(n, 1024, TCA_JENSVQ_LIMIT, &limit, sizeof(limit));
	if (markfree != ~0U)
		addattr_l(n, 1024, TCA_JENSVQ_MARKFREE, &markfree, sizeof(markfree));
	if (markfull != ~0U)
		addattr_l(n, 1024, TCA_JENSVQ_MARKFULL, &markfull, sizeof(markfull));
	if (subbufs != ~0U)
		addattr_l(n, 1024, TCA_JENSVQ_SUBBUFS, &subbufs, sizeof(subbufs));
	if (fragcache != ~0U)
		addattr_l(n, 1024, TCA_JENSVQ_FRAGCACHE, &fragcache, sizeof(fragcache));
	if (extralatency != ~0U)
		addattr_l(n, 1024, TCA_JENSVQ_XLATENCY, &extralatency, sizeof(extralatency));
	addattr_nest_end(n, tail);
	return (0);
}

static int
janz_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
	struct rtattr *tb[TCA_JENSVQ_MAX + 1];
	unsigned int limit;
	unsigned int markfree;
	unsigned int markfull;
	unsigned int subbufs;
	unsigned int fragcache;
	unsigned int extralatency;

	SPRINT_BUF(b1);

	if (!opt)
		return (NULL);

	parse_rtattr_nested(tb, TCA_JENSVQ_MAX, opt);

	if (tb[TCA_JENSVQ_LIMIT] &&
	    RTA_PAYLOAD(tb[TCA_JENSVQ_LIMIT]) >= sizeof(limit)) {
		limit = rta_getattr_u32(tb[TCA_JENSVQ_LIMIT]);
		print_uint(PRINT_ANY, "limit", "limit %u ", limit);
	}
	if (tb[TCA_JENSVQ_MARKFREE] &&
	    RTA_PAYLOAD(tb[TCA_JENSVQ_MARKFREE]) >= sizeof(markfree)) {
		markfree = rta_getattr_u32(tb[TCA_JENSVQ_MARKFREE]);
		print_string(PRINT_FP, NULL, "markfree %s ",
		    sprint_time(markfree, b1));
		print_uint(PRINT_JSON, "markfree", NULL, markfree);
	}
	if (tb[TCA_JENSVQ_MARKFULL] &&
	    RTA_PAYLOAD(tb[TCA_JENSVQ_MARKFULL]) >= sizeof(markfull)) {
		markfull = rta_getattr_u32(tb[TCA_JENSVQ_MARKFULL]);
		print_string(PRINT_FP, NULL, "markfull %s ",
		    sprint_time(markfull, b1));
		print_uint(PRINT_JSON, "markfull", NULL, markfull);
	}
	if (tb[TCA_JENSVQ_SUBBUFS] &&
	    RTA_PAYLOAD(tb[TCA_JENSVQ_SUBBUFS]) >= sizeof(subbufs)) {
		subbufs = rta_getattr_u32(tb[TCA_JENSVQ_SUBBUFS]);
		print_uint(PRINT_ANY, "subbufs", "subbufs %u ", subbufs);
	}
	if (tb[TCA_JENSVQ_FRAGCACHE] &&
	    RTA_PAYLOAD(tb[TCA_JENSVQ_FRAGCACHE]) >= sizeof(fragcache)) {
		fragcache = rta_getattr_u32(tb[TCA_JENSVQ_FRAGCACHE]);
		print_uint(PRINT_ANY, "fragcache", "fragcache %u ", fragcache);
	}
	if (tb[TCA_JENSVQ_XLATENCY] &&
	    RTA_PAYLOAD(tb[TCA_JENSVQ_XLATENCY]) >= sizeof(extralatency)) {
		extralatency = rta_getattr_u32(tb[TCA_JENSVQ_XLATENCY]);
		print_string(PRINT_FP, NULL, "extralatency %s ",
		    sprint_time(extralatency, b1));
		print_uint(PRINT_JSON, "extralatency", NULL, extralatency);
	}

	return (0);
}

struct qdisc_util jensvq_qdisc_util = {
	.id		= "jensvq",
	.parse_qopt	= janz_parse_opt,
	.print_qopt	= janz_print_opt,
};

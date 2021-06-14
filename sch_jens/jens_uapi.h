/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

/* part of sch_jens (fork of sch_fq_codel), Deutsche Telekom LLCTO */

#ifndef __NET_SCHED_JENS_UAPI_H
#define __NET_SCHED_JENS_UAPI_H

/* JENS */

enum {
	TCA_JENS_UNSPEC,
	TCA_JENS_TARGET,
	TCA_JENS_LIMIT,
	TCA_JENS_INTERVAL,
	TCA_JENS_FLOWS,
	TCA_JENS_QUANTUM,
	TCA_JENS_CE_THRESHOLD,
	TCA_JENS_DROP_BATCH_SIZE,
	TCA_JENS_MEMORY_LIMIT,
	__TCA_JENS_MAX
};

#define TCA_JENS_MAX	(__TCA_JENS_MAX - 1)

enum {
	TCA_JENS_XSTATS_QDISC,
	TCA_JENS_XSTATS_CLASS,
};

struct tc_jens_qd_stats {
	__u32	maxpacket;	/* largest packet we've seen so far */
	__u32	drop_overlimit; /* number of time max qdisc
				 * packet limit was hit
				 */
	__u32	ecn_mark;	/* number of packets we ECN marked
				 * instead of being dropped
				 */
	__u32	new_flow_count; /* number of time packets
				 * created a 'new flow'
				 */
	__u32	new_flows_len;	/* count of flows in new list */
	__u32	old_flows_len;	/* count of flows in old list */
	__u32	ce_mark;	/* packets above ce_threshold */
	__u32	memory_usage;	/* in bytes */
	__u32	drop_overmemory;
};

struct tc_jens_cl_stats {
	__s32	deficit;
	__u32	ldelay;		/* in-queue delay seen by most recently
				 * dequeued packet
				 */
	__u32	count;
	__u32	lastcount;
	__u32	dropping;
	__s32	drop_next;
};

struct tc_jens_xstats {
	__u32	type;
	union {
		struct tc_jens_qd_stats qdisc_stats;
		struct tc_jens_cl_stats class_stats;
	};
};

#endif

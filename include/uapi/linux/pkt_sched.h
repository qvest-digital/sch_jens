/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

/*** excerpt ***/

/* HTB section */
#define TC_HTB_NUMPRIO		8
#define TC_HTB_MAXDEPTH		8
#define TC_HTB_PROTOVER		3 /* the same as HTB and TC's major */

struct tc_htb_opt {
	struct tc_ratespec 	rate;
	struct tc_ratespec 	ceil;
	__u32	buffer;
	__u32	cbuffer;
	__u32	quantum;
	__u32	level;		/* out only */
	__u32	prio;
};
struct tc_htb_glob {
	__u32 version;		/* to match HTB/TC */
    	__u32 rate2quantum;	/* bps->quantum divisor */
    	__u32 defcls;		/* default class number */
	__u32 debug;		/* debug flags */

	/* stats */
	__u32 direct_pkts; /* count of non shaped packets */
};
enum {
	TCA_HTB_UNSPEC,
	TCA_HTB_PARMS,
	TCA_HTB_INIT,
	TCA_HTB_CTAB,
	TCA_HTB_RTAB,
	TCA_HTB_DIRECT_QLEN,
	TCA_HTB_RATE64,
	TCA_HTB_CEIL64,
	TCA_HTB_PAD,
	__TCA_HTB_MAX,
};

#define TCA_HTB_MAX (__TCA_HTB_MAX - 1)

struct tc_htb_xstats {
	__u32 lends;
	__u32 borrows;
	__u32 giants;	/* too big packets (rate will not be accurate) */
	__u32 tokens;
	__u32 ctokens;
};

/* FQ_CODEL */

#define FQ_CODEL_QUANTUM_MAX (1 << 20)

enum {
	TCA_FQ_CODEL_UNSPEC,
	TCA_FQ_CODEL_TARGET,
	TCA_FQ_CODEL_LIMIT,
	TCA_FQ_CODEL_INTERVAL,
	TCA_FQ_CODEL_ECN,
	TCA_FQ_CODEL_FLOWS,
	TCA_FQ_CODEL_QUANTUM,
	TCA_FQ_CODEL_CE_THRESHOLD,
	TCA_FQ_CODEL_DROP_BATCH_SIZE,
	TCA_FQ_CODEL_MEMORY_LIMIT,
	__TCA_FQ_CODEL_MAX
};

#define TCA_FQ_CODEL_MAX	(__TCA_FQ_CODEL_MAX - 1)

enum {
	TCA_FQ_CODEL_XSTATS_QDISC,
	TCA_FQ_CODEL_XSTATS_CLASS,
};

struct tc_fq_codel_qd_stats {
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

struct tc_fq_codel_cl_stats {
	__s32	deficit;
	__u32	ldelay;		/* in-queue delay seen by most recently
				 * dequeued packet
				 */
	__u32	count;
	__u32	lastcount;
	__u32	dropping;
	__s32	drop_next;
};

struct tc_fq_codel_xstats {
	__u32	type;
	union {
		struct tc_fq_codel_qd_stats qdisc_stats;
		struct tc_fq_codel_cl_stats class_stats;
	};
};

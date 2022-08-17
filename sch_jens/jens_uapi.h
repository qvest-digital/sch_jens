/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

/* part of sch_jens (fork of sch_fq_codel), Deutsche Telekom LLCTO */

#ifndef __NET_SCHED_JENS_UAPI_H
#define __NET_SCHED_JENS_UAPI_H

/* janz */

enum {
	TCA_JANZ_UNSPEC,
	TCA_JANZ_PAD64,		/* for padding */
	TCA_JANZ_LIMIT,
	TCA_JANZ_RATE64,
	TCA_JANZ_HANDOVER,
	TCA_JANZ_MARKFREE,
	TCA_JANZ_MARKFULL,
	TCA_JANZ_SUBBUFS,
	TCA_JANZ_FRAGCACHE,
	__TCA_JANZ_MAX
};

#define TCA_JANZ_MAX	(__TCA_JANZ_MAX - 1)

/*
 * sch_janz also uses from below:
 * - TC_JENS_TIMESHIFT
 * - struct tc_jens_relay
 *   and related enum/constants, TC_JENS_RELAY_*
 */

/* JHTB */
#define TC_JHTB_NUMPRIO		8
#define TC_JHTB_MAXDEPTH	8
#define TC_JHTB_PROTOVER	3 /* the same as HTB and TC's major */

struct tc_jhtb_opt {
	struct tc_ratespec 	rate;
	struct tc_ratespec 	ceil;
	__u32	buffer;
	__u32	cbuffer;
	__u32	quantum;
	__u32	level;		/* out only */
	__u32	prio;
};
struct tc_jhtb_glob {
	__u32 version;		/* to match HTB/TC */
	__u32 rate2quantum;	/* bps->quantum divisor */
	__u32 defcls;		/* default class number */
	__u32 debug;		/* debug flags */

	/* stats */
	__u32 direct_pkts; /* count of non shaped packets */
};
enum {
	TCA_JHTB_UNSPEC,
	TCA_JHTB_PARMS,
	TCA_JHTB_INIT,
	TCA_JHTB_CTAB,
	TCA_JHTB_RTAB,
	TCA_JHTB_DIRECT_QLEN,
	TCA_JHTB_RATE64,
	TCA_JHTB_CEIL64,
	TCA_JHTB_PAD,
	TCA_JHTB_HANDOVER,
	__TCA_JHTB_MAX,
};

#define TCA_JHTB_MAX (__TCA_JHTB_MAX - 1)

struct tc_jhtb_xstats {
	__u32 lends;
	__u32 borrows;
	__s32 tokens;
	__s32 ctokens;
};

/* JENS */

#define JENS_QUANTUM_MAX (1 << 20)

enum {
	TCA_JENS_UNSPEC,
	TCA_JENS_TARGET,
	TCA_JENS_LIMIT,
	TCA_JENS_INTERVAL,
	TCA_JENS_MARKFREE,
	TCA_JENS_MARKFULL,
	TCA_JENS_FLOWS,
	TCA_JENS_QUANTUM,
	TCA_JENS_DROP_BATCH_SIZE,
	TCA_JENS_MEMORY_LIMIT,
	TCA_JENS_SUBBUFS,
	TCA_JENS_NOUSEPORT,
	TCA_JENS_FRAGCACHE,
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
	__u32	ce_mark;	/* packets ECN CE-marked due to sojourn time */
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

#define TC_JENS_TIMESHIFT 10

/* relay record */
struct tc_jens_relay {
	__u64 ts;		/* timestamp (CLOCK_MONOTONIC, ns) */
	__u8 type;		/* relay record type */
	__u8 f8;		/* 8 bits of even more user data */
	union {
		__u16 e16;
		__u8 e8[2];
	};			/* 16 bits of extra user data */
	union {
		__u32 d32;
		__u16 d16[2];
		__u8 d8[4];
	};			/* 32 bits of user data */
	union {
		__u8 x8[16];	/* 128 bits of extra data */
		struct in6_addr xip;
	};
	union {
		__u8 y8[16];	/* 128 bits of yet more extra data */
		struct in6_addr yip;
	};
	union {
		__u8 z8[16];	/* 128 bits of structured extra data */
		struct {
			__u32 psize;
			__u8 ipver;
			__u8 nexthdr;
			__u16 sport;	/* host byteorder */
			__u16 dport;	/* host byteorder */
			__u16 pad1;
			__u32 pad2;
		} zSOJOURN;
	} z;
};
/* compile-time check for correct size */
extern struct tc_jens_relay tc_jens_relay_cta[sizeof(struct tc_jens_relay) == 64 ? 1 : -1];

/* relay record types (see README for details) */
enum {
	/* invalid (0), not initialised */
	TC_JENS_RELAY_INVALID = 0,

	__TC_JENS_RELAY_OLDVER1,
	__TC_JENS_RELAY_OLDVER2,
	__TC_JENS_RELAY_OLDVER3,

	/* initialised but skip as subbuffer padding */
	TC_JENS_RELAY_PADDING,

	__TC_JENS_RELAY_OLDVER4,

	/* report length of queue periodically */
	/* d32 = memory usage in bytes */
	/* e16 = amount of packets in FIFO, 0xFFFF if more */
	TC_JENS_RELAY_QUEUESZ,

	/* report a single packet leaving our queue */
	/* d32 = sojourn time in 1024 ns units (-1 = drop on queue resize) */
	/* e16 = ECN marking range/percentage */
	/* f8 = bitfield: 0:1=ECN bits on enqueue, 2=ECN bits are valid,
		3:4=ECN bits on dequeue, TC_JENS_RELAY_SOJOURN_SLOW,
		TC_JENS_RELAY_SOJOURN_MARK, TC_JENS_RELAY_SOJOURN_DROP */
	/* x8 = source IP, y8 = destination IP */
	/* z.zSOJOURN = packet size, IP version (4, 6, 0 for not IP) */
	/* + if IP: L4 proto, if TCP/UDP also src/dst port */
	TC_JENS_RELAY_SOJOURN,

	/* invalid, too high */
	__TC_JENS_RELAY_MAX
};
#define TC_JENS_RELAY_MIN TC_JENS_RELAY_PADDING
#define TC_JENS_RELAY_MAX (__TC_JENS_RELAY_MAX - 1)

/* convert d32 to nanoseconds as __u64 */
#define TC_JENS_RELAY_SOJOURN_TO_NS(d32) ((__u64)(d32) << TC_JENS_TIMESHIFT)

/* divide e16 by this (and multiply with 100.0) to get a percentage */
#define TC_JENS_RELAY_SOJOURN_PCTDIV ((double)65535)

/* flags in f8 */
#define TC_JENS_RELAY_SOJOURN_SLOW (1U << 5)	/* target not reached (sch_jens only) */
#define TC_JENS_RELAY_SOJOURN_MARK (1U << 6)	/* markfree..markfull */
#define TC_JENS_RELAY_SOJOURN_DROP (1U << 7)	/* packet was dropped */

#define TC_JENS_RELAY_NRECORDS 256		/* per subbuffer */
#define TC_JENS_RELAY_SUBBUFSZ \
    (TC_JENS_RELAY_NRECORDS * sizeof(struct tc_jens_relay))

#endif

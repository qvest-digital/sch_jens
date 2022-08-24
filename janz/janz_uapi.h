/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

/* part of sch_janz, Deutsche Telekom LLCTO */

#ifndef __NET_SCHED_JANZ_UAPI_H
#define __NET_SCHED_JANZ_UAPI_H

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

#define TC_JANZ_TIMESHIFT 10

/* relay record */
struct tc_janz_relay {
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
extern struct tc_janz_relay tc_janz_relay_cta[sizeof(struct tc_janz_relay) == 64 ? 1 : -1];

/* relay record types (see README for details) */
enum {
	/* invalid (0), not initialised */
	TC_JANZ_RELAY_INVALID = 0,

	__TC_JANZ_RELAY_OLDVER1,
	__TC_JANZ_RELAY_OLDVER2,
	__TC_JANZ_RELAY_OLDVER3,

	/* initialised but skip as subbuffer padding */
	TC_JANZ_RELAY_PADDING,

	__TC_JANZ_RELAY_OLDVER4,

	/* report length of queue periodically */
	/* d32 = memory usage in bytes */
	/* e16 = amount of packets in FIFO, 0xFFFF if more */
	TC_JANZ_RELAY_QUEUESZ,

	/* report a single packet leaving our queue */
	/* d32 = sojourn time in 1024 ns units (-1 = drop on queue resize) */
	/* e16 = ECN marking range/percentage */
	/* f8 = bitfield: 0:1=ECN bits on enqueue, 2=ECN bits are valid,
		3:4=ECN bits on dequeue, TC_JANZ_RELAY_SOJOURN_xxxx,
		TC_JANZ_RELAY_SOJOURN_MARK, TC_JANZ_RELAY_SOJOURN_DROP */
	/* x8 = source IP, y8 = destination IP */
	/* z.zSOJOURN = packet size, IP version (4, 6, 0 for not IP) */
	/* + if IP: L4 proto, if TCP/UDP also src/dst port */
	TC_JANZ_RELAY_SOJOURN,

	/* invalid, too high */
	__TC_JANZ_RELAY_MAX
};
#define TC_JANZ_RELAY_MIN TC_JANZ_RELAY_PADDING
#define TC_JANZ_RELAY_MAX (__TC_JANZ_RELAY_MAX - 1)

/* convert d32 to nanoseconds as __u64 */
#define TC_JANZ_RELAY_SOJOURN_TO_NS(d32) ((__u64)(d32) << TC_JANZ_TIMESHIFT)

/* divide e16 by this (and multiply with 100.0) to get a percentage */
#define TC_JANZ_RELAY_SOJOURN_PCTDIV ((double)65535)

/* flags in f8 */
/*efine TC_JANZ_RELAY_SOJOURN_xxxx (1U << 5)	-- (currently unused) */
#define TC_JANZ_RELAY_SOJOURN_MARK (1U << 6)	/* markfree..markfull */
#define TC_JANZ_RELAY_SOJOURN_DROP (1U << 7)	/* packet was dropped */

#define TC_JANZ_RELAY_NRECORDS 256		/* per subbuffer */
#define TC_JANZ_RELAY_SUBBUFSZ \
    (TC_JANZ_RELAY_NRECORDS * sizeof(struct tc_janz_relay))

#endif
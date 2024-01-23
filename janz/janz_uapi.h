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
	TCA_JANZ_XLATENCY,
	TCA_JANZ_QOSMODE,
	TCA_MULTIJENS_UENUM,
	__TCA_JANZ_MAX
};

#define TCA_JANZ_MAX	(__TCA_JANZ_MAX - 1)

#define TC_JANZ_TIMESHIFT 10

#ifdef mbCTA
#define JANZ__SIZECHECK(name,len) \
		mbCTA_BEG(name); \
		mbCTA(name, sizeof(struct name) == (len)); \
		mbCTA_END(name)
#else
#define JANZ__SIZECHECK(name,len) \
		extern struct name name ## _cta[sizeof(struct name) == (len) ? 1 : -1]
#endif

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
		__u64 x64[2];
		struct in6_addr xip;
	};
	union {
		__u8 y8[16];	/* 128 bits of yet more extra data */
		__u64 y64[2];
		struct in6_addr yip;
	};
	union {
		__u8 z8[16];	/* 128 bits of structured extra data */
		struct {
			__u32 psize;	/* bit30‥31: FIFO# (1, 2 or 3) */
			__u8 ipver;
			__u8 nexthdr;
			__u16 sport;	/* host byteorder */
			__u16 dport;	/* host byteorder */
			__u16 vqnb_u;	/* vq_notbefore1024 bit8‥23 */
			__u32 real_owd;
		} zSOJOURN;
#if 0
		struct {
			__u32 pad0;
			__u32 pad1;
			__u32 pad2;
			__u32 pad3;
		} zQUEUESZ;
#endif
	} z;
};
/* compile-time check for correct size */
JANZ__SIZECHECK(tc_janz_relay, 64U);

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
	/* d32 = amount of bytes queued up */
	/* e16 = amount of packets in FIFO, 0xFFFF if more */
	/* f8 = bitfield: 0=handover started */
	/* x64[0] = current rate in bits/s */
	TC_JANZ_RELAY_QUEUESZ,

	__TC_JANZ_RELAY_OLDVER5,

	/* watchdog performance debugging */
	/* f8 = 0 (not scheduled because of watchdog) or bitfield: */
	/*	0x10=notbefore 0x20=nothingtosend 0x40=rexmit-delay */
	/*	0x01=now>=wdognext 0x02=now<wdognext */
	/* e16 = amount of times it was called too early */
	/* d32 = ns delay of this, if f8≠0 */
	/* x64[0] = amount of times delay < 50 us */
	/* x64[1] = amount of times delay < 1000 us */
	/* y64[0] = amount of times delay < 4000 us */
	/* y64[1] = amount of times delay >= 4 ms */
	TC_JANZ_RELAY_WDOGDBG,

	/* report a single packet leaving our queue */
	/* d32 = sojourn time in 1024 ns units
	         (-1 = drop on queue resize,
		  -2 = drop before enqueue with extralatency applied) */
	/* e16 = bitfield: 0:2=retransmission#total, 3:5=rexmit-#attempt,
		6:7=unused, 8:15=vq_notbefore1024(bit0:7) */
	/* f8 = bitfield: 0:1=ECN bits on enqueue, 2=ECN bits are valid,
		3:4=ECN bits on dequeue, 5=TC_JANZ_RELAY_SOJOURN_xxxx,
		6=TC_JANZ_RELAY_SOJOURN_MARK, 7=TC_JANZ_RELAY_SOJOURN_DROP */
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

/* flags in f8 */
/*efine TC_JANZ_RELAY_SOJOURN_xxxx (1U << 5)	-- (currently unused) */
#define TC_JANZ_RELAY_SOJOURN_MARK (1U << 6)	/* markfree..markfull */
#define TC_JANZ_RELAY_SOJOURN_DROP (1U << 7)	/* packet was dropped */
#define TC_JANZ_RELAY_QUEUESZ_HOVER (1U << 0)	/* handover starting */

#define TC_JANZ_RELAY_NRECORDS 256		/* per subbuffer */
#define TC_JANZ_RELAY_SUBBUFSZ \
    (TC_JANZ_RELAY_NRECORDS * sizeof(struct tc_janz_relay))

#define JANZ_CTLFILE_VERSION 1

struct janz_ctlfile_pkt {
	__u64 bits_per_second;
};
/* compile-time check for correct size */
JANZ__SIZECHECK(janz_ctlfile_pkt, 8U);

/* part of sch_jensvq, Deutsche Telekom LLCTO */

enum {
	TCA_JENSVQ_UNSPEC,
	TCA_JENSVQ_LIMIT,
	TCA_JENSVQ_MARKFREE,
	TCA_JENSVQ_MARKFULL,
	TCA_JENSVQ_SUBBUFS,
	TCA_JENSVQ_FRAGCACHE,
	TCA_JENSVQ_XLATENCY,
	__TCA_JENSVQ_MAX
};

#define TCA_JENSVQ_MAX (__TCA_JENSVQ_MAX - 1)

#define JENSVQ_NUE 8

struct jensvq_relay {
	__u64 vts;		// virtual timestamp (ns, CLOCK_MONOTONIC)
	__u64 hts;		// human timestamp (ns, time_t)
	struct in6_addr srcip;	// sender IP or Legacy IP addresses, if ipv ≠ 0
	struct in6_addr dstip;	// dito but recipient
	__u32 flags;		// bitfield, see below
	__u32 psize;		// raw packet size, including partial L2 framing
	__u16 sport;		// source port, if ipv ≠ 0 ∧ nh ∈ { 6, 17 }
	__u16 dport;		// destination port, dito
	__u16 upkts;		// # of packets enqueued for this UE
	__u8 nh;		// L3 protocol number (next header) if ipv ≠ 0
	__u8 reserved1;
	__u64 vbw;		// current virtual link capacity
	__u64 rbw;		// current physical link capacity
	__u64 vqdelay;		// queue delay ECN marking is calculated from
	__u64 rqdelay;		// queue delay from channel bandwidth limiting
	__u64 owdelay;		// extralatency + queue delay + retransmissions
	__u32 ubytes;		// # of bytes enqueued for this UE
	__u32 reserved2[5];
};
JANZ__SIZECHECK(jensvq_relay, 128U);

#define TC_JENSVQ_RELAY_NRECORDS 128		/* per subbuffer */
#define TC_JENSVQ_RELAY_SUBBUFSZ \
    (TC_JENSVQ_RELAY_NRECORDS * sizeof(struct jensvq_relay))

/* usage:
 *	val = JENS_GET(JENSVQ_Fuenum, flags);
 *	flags &= ~JENSVQ_Fuenum;
 *	flags |= JENS_FMK(JENSVQ_Fuenum, val);
 */
#define JENSVQ_Ftype	0x00000003U	// 0=padding, 1=packet, 2=handover
#define JENSVQ_Frexnum	0x0000001CU	// 0‥5=this# rexmit; 7=held up by rexmitted
#define JENSVQ_Frextot	0x000000E0U	// # of rexmits for this packet
#define JENSVQ_Fmark	0x00000100U	// ECN CE marked
#define JENSVQ_Fecnval	0x00000200U	// whether ecn{en,de}q are valid
#define JENSVQ_Fecnenq	0x00000C00U	// ECN bits on enqueue, incoming
#define JENSVQ_Fecndeq	0x00003000U	// ECN bits on dequeue, outgoing
#define JENSVQ_Fipv	0x0000C000U	// 0=not IP, 1=IPv6, 2=IPv4
#define JENSVQ_Fdrop	0x00010000U	// dropped
#define JENSVQ_Fbypass	0x00020000U	// bypass used
#define JENSVQ_Fuenum	0x001C0000U	// UE number

#define JENS__MASK2SHIFT(mask) (__builtin_ffsll(mask) - 1)
#define JENS_GET(mask,v) ((unsigned)(((unsigned)(v) & mask) >> JENS__MASK2SHIFT(mask)))
#define JENS_FMK(mask,v) (((unsigned)(v) << JENS__MASK2SHIFT(mask)) & mask)

struct jensvq_ctlfile_pkt {
	struct {
		__u64 vq_bps;
		__u64 rq_bps;
	} ue[JENSVQ_NUE];
};
JANZ__SIZECHECK(jensvq_ctlfile_pkt, 128U);

#endif

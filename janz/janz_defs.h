/*
 * JENS qdisc (shared parts, early in the file)
 *
 * Copyright © 2022, 2023 mirabilos <t.glaser@tarent.de>
 * Licensor: Deutsche Telekom LLCTO
 *
 * This module for the Linux kernel is published under the GPLv2.
 */

#ifndef __NET_SCHED_JANZ_DEFS_H
#define __NET_SCHED_JANZ_DEFS_H

#undef JANZ_IP_DECODER_DEBUG
#if 1
#define JANZ_IP_DECODER_DEBUG(fmt,...)	do { /* nothing */ } while (0)
#else
#define JANZ_IP_DECODER_DEBUG(fmt,...)	printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#endif

/* constant must fit 32 bits; 2'000'000'000 will do, should not be *too* large */
#define MAXXLATENCY nsmul(2, NSEC_PER_SEC)

#define nsmul(val, fac) ((u64)((u64)(val) * (u64)(fac)))

static inline u64
us_to_ns(u32 us)
{
	return (nsmul(us, NSEC_PER_USEC));
}

static inline u64
ns_to_us(u64 ns)
{
	return (div_u64(ns, NSEC_PER_USEC));
}

struct janz_fragcomp {
	struct in6_addr sip;			//@0    :16
	struct in6_addr dip;			//@16   :16
	u32 idp;				//@16   :4
	u8 v;					//@  +4 :1
} __attribute__((__packed__));

struct janz_fragcache {
	struct janz_fragcomp c;			//@0
	u8 nexthdr;				//@ +37 :1
	u8 _pad[6];				//@ +38 :6
	u16 sport;				//@ +44 :2
	u16 dport;				//@ +46 :2
	u64 ts;					//@16   :8
	struct janz_fragcache *next;		//@  +8 :ptr
} __attribute__((__packed__));

/* compile-time assertions */
mbCTA_BEG(janz_fragcache_check);
 mbCTA(cmp, sizeof(struct janz_fragcomp) == 37U);
 mbCTA(cac, sizeof(struct janz_fragcache) == (56U + sizeof(void *)));
 mbCTA(tot, sizeof(struct janz_fragcache) <= 64U);
 mbCTA(xip, mbccFSZ(struct tc_janz_relay, xip) == 16U);
 mbCTA(yip, mbccFSZ(struct tc_janz_relay, yip) == 16U);
 mbCTA(x_y, offsetof(struct tc_janz_relay, yip) == (offsetof(struct tc_janz_relay, xip) + 16U));
 mbCTA(s_d, offsetof(struct janz_fragcomp, dip) == (offsetof(struct janz_fragcomp, sip) + 16U));
mbCTA_END(janz_fragcache_check);

struct janz_skbfifo {
	struct sk_buff *first;
	struct sk_buff *last;
};

/* struct janz_skb *cb = get_janz_skb(skb); */
struct janz_skb {
	/* limited to QDISC_CB_PRIV_LEN (20) bytes! */
	u64 ts_enq;			/* real enqueue timestamp */		//@8   :8
	union {									//@8   :4
		/* up to and including janz_drop_pkt/janz_sendoff */
		u32 pktxlatency;	/* ts_enq adjustment */
		/* from qdelay_encode onwards */
		u32 qdelay1024;		/* for reporting */
	};									//…8   :4
	u16 srcport;								//@ +4 :2
	u16 dstport;								//@ +6 :2
	union {									//@8   :1
		/* before jq_enq call in janz_enq */
		u8 tosbyte;		/* from IPv4/IPv6 header or faked */
		/* post that */
		struct {
			u8 xqid:2;	/* qid (1/2/3) or 0=bypass */
			u8 xmitnum:3;	/* retransmissions done */
			u8 xmittot:3;	/* #retransmissions to do in total */
		};
	};
	u8 ipver;			/* 6 (IP) or 4 (Legacy IP) */		//@ +1 :1
	u8 nexthdr;								//@ +2 :1
	u8 record_flag;			/* for debugfs/relayfs reporting */	//@ +3 :1
} __attribute__((__packed__));

static inline struct janz_skb *
get_janz_skb(const struct sk_buff *skb)
{
	qdisc_cb_private_validate(skb, sizeof(struct janz_skb));
	return ((struct janz_skb *)qdisc_skb_cb(skb)->data);
}

/* compile-time assertions */
mbCTA_BEG(janz_misc);
 mbCTA(hasatomic64, sizeof(atomic64_t) == 8U);
 mbCTA(maxxlatency_ok, MAXXLATENCY <= 0xFFFFFFFFULL);
mbCTA_END(janz_misc);

#endif /* !__NET_SCHED_JANZ_DEFS_H */

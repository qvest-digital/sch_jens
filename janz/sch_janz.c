/*
 * Dǟ janz zesammene Kwejü-Disk
 *
 * Copyright © 2022 mirabilos <t.glaser@tarent.de>
 * Licensor: Deutsche Telekom LLCTO
 *
 * This module for the Linux kernel is published under the GPLv2.
 */

#undef JANZ_IP_DECODER_DEBUG
#if 1
#define JANZ_IP_DECODER_DEBUG(...)	do { /* nothing */ } while (0)
#else
#define JANZ_IP_DECODER_DEBUG(...)	printk(__VA_ARGS__)
#endif

#undef JANZ_REPORTING
#if 0
#define JANZ_REPORTING			1
#else
#define JANZ_REPORTING			0 /* for debugging without */
#endif

#include <linux/version.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/debugfs.h>
#include <linux/relay.h>
#include <net/ipv6.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/ip.h>
#include <net/inet_ecn.h>
#include <net/pkt_cls.h>

#include "janz_uapi.h"

#define nsmul(val, fac) ((u64)((u64)(val) * (u64)(fac)))

#if JANZ_REPORTING
static inline u32
ns_to_t1024(u64 ns)
{
	return ((u32)(ns >> TC_JANZ_TIMESHIFT));
}

static inline u64
t1024_to_ns(u32 ts1024)
{
	return ((u64)ts1024 << TC_JANZ_TIMESHIFT);
}
#endif

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

#if JANZ_REPORTING
struct janz_fragcomp {
	struct in6_addr sip;			//@0    :16
	struct in6_addr dip;			//@16   :16
	u32 idp;				//@16   :4
	u8 v;					//@  +4 :1
} __attribute__((__packed__));

struct janz_fragcache {
	struct janz_fragcomp c;			//@0
	u8 nexthdr;				//@ +37 :1
	u8 _pad[2];				//@ +38 :2
	u64 ts;					//@ +40 :8
	struct janz_fragcache *next;		//@16   :ptr
	u16 sport;				//@ +ptr:2
	u16 dport;				//@ +"" :2
} __attribute__((__packed__));

/* compile-time assertion */
struct janz_fragcache_check {
	int cmp[sizeof(struct janz_fragcomp) == 37 ? 1 : -1];
	int cac[sizeof(struct janz_fragcache) == (48 + sizeof(void *) + 4) ? 1 : -1];
	int tot[sizeof(struct janz_fragcache) <= 64 ? 1 : -1];
	int xip[sizeof_field(struct tc_janz_relay, xip) == 16 ? 1 : -1];
	int yip[sizeof_field(struct tc_janz_relay, yip) == 16 ? 1 : -1];
	int x_y[offsetof(struct tc_janz_relay, yip) ==
	    (offsetof(struct tc_janz_relay, xip) + 16) ? 1 : -1];
	int s_d[offsetof(struct janz_fragcomp, dip) ==
	    (offsetof(struct janz_fragcomp, sip) + 16) ? 1 : -1];
};
#endif

struct janz_skbfifo {
	struct sk_buff *first;
	struct sk_buff *last;
};

/* struct janz_priv *q = qdisc_priv(sch); */
struct janz_priv {
	struct janz_skbfifo q[3];	/* TOS FIFOs */					//@cacheline
	struct rchan *record_chan;	/* relay to userspace */			//@16
#if JANZ_REPORTING
#define QSZ_INTERVAL nsmul(5, NSEC_PER_MSEC)
	u64 qsz_next;			/* next time to emit queue-size */		//@  +8
#endif
#define DROPCHK_INTERVAL nsmul(200, NSEC_PER_MSEC)
	u64 drop_next;			/* next time to check drops */			//@16
	u64 notbefore;			/* ktime_get_ns() to send next, or 0 */		//@  +8
	u64 ns_pro_byte;		/* traffic shaping tgt bandwidth */		//@16
	u64 markfree;									//@  +8
	u64 markfull;									//@16
	u64 xlatency;			/* extra artificial pre-enqueue latency */	//@  +8
#if JANZ_REPORTING
	struct janz_fragcache *fragcache_used;						//@16
	struct janz_fragcache *fragcache_last; /* last used element */			//@  +8
	struct janz_fragcache *fragcache_free;						//@16
	struct janz_fragcache *fragcache_base;						//@  +8
	u64 fragcache_aged;								//@16
	u32 fragcache_num;								//@  +8
#endif
	u32 memusage;			/* enqueued packet truesize */			//@  +12
	struct qdisc_watchdog watchdog;	/* to schedule when traffic shaping */		//@16
#if JANZ_REPORTING
	spinlock_t record_lock;		/* for record_chan */				//@?
#endif
	u32 nsubbufs;
	u8 crediting;
};

/* struct janz_skb *cb = get_janz_skb(skb); */
struct janz_skb {
	/* limited to QDISC_CB_PRIV_LEN (20) bytes! */
	u64 enq_ts;			/* enqueue timestamp */			//@8   :8
	unsigned int truesz;		/* memory usage */			//@ +8 :4

	u16 srcport;								//@ +12:2
	u16 dstport;								//@ +14:2
	u8 tosbyte;			/* from IPv4/IPv6 header or faked */	//@8   :1
	u8 ipver;			/* 6 (IP) or 4 (Legacy IP) */		//@ +1 :1
	u8 nexthdr;								//@ +2 :1
#if JANZ_REPORTING
	u8 record_flag;			/* for debugfs/relayfs reporting */	//@ +3 :1
#endif
} __attribute__((__packed__));

static inline struct janz_skb *
get_janz_skb(const struct sk_buff *skb)
{
	qdisc_cb_private_validate(skb, sizeof(struct janz_skb));
	return ((struct janz_skb *)qdisc_skb_cb(skb)->data);
}

#if JANZ_REPORTING
static inline void
janz_record_write(struct tc_janz_relay *record, struct janz_priv *q)
{
	unsigned long flags;	/* used by spinlock macros */

	spin_lock_irqsave(&q->record_lock, flags);
	__relay_write(q->record_chan, record, sizeof(struct tc_janz_relay));
	spin_unlock_irqrestore(&q->record_lock, flags);
}

static inline void
janz_record_queuesz(struct Qdisc *sch, struct janz_priv *q, u64 now, u8 f)
{
	struct tc_janz_relay r = {0};

	r.ts = now;
	r.type = TC_JANZ_RELAY_QUEUESZ;
	r.d32 = q->memusage;
	r.e16 = sch->q.qlen > 0xFFFFU ? 0xFFFFU : sch->q.qlen;
	r.f8 = f;
	r.x64[0] = div64_u64(NSEC_PER_SEC, q->ns_pro_byte) * 8ULL;
	r.x64[1] = (u64)ktime_to_ns(ktime_mono_to_real(ns_to_ktime(now))) - now;
	janz_record_write(&r, q);

	/* use of ktime_get_ns() is deliberate */
	q->qsz_next = ktime_get_ns() + QSZ_INTERVAL;
}

static inline void
janz_record_packet(struct janz_priv *q,
    struct sk_buff *skb, struct janz_skb *cb, u64 now,
    u32 queuedelay, u16 chance)
{
	struct tc_janz_relay r = {0};

	r.ts = now;
	r.type = TC_JANZ_RELAY_SOJOURN;
	r.d32 = queuedelay;
	r.e16 = chance;
	r.f8 = cb->record_flag;
	r.z.zSOJOURN.psize = skb->len;
	r.z.zSOJOURN.ipver = cb->ipver;
	r.z.zSOJOURN.nexthdr = cb->nexthdr;
	r.z.zSOJOURN.sport = cb->srcport;
	r.z.zSOJOURN.dport = cb->dstport;

	switch (cb->ipver) {
	case 4: {
		struct iphdr *ih4 = ip_hdr(skb);

		ipv6_addr_set_v4mapped(ih4->saddr, &r.xip);
		ipv6_addr_set_v4mapped(ih4->daddr, &r.yip);
		break;
	    }
	case 6: {
		struct ipv6hdr *ih6 = ipv6_hdr(skb);

		memcpy(r.x8, ih6->saddr.s6_addr, 16);
		memcpy(r.y8, ih6->daddr.s6_addr, 16);
		break;
	    }
	}

	janz_record_write(&r, q);
}

static inline void
janz_fragcache_maint(struct janz_priv *q, u64 now)
{
	u64 old;
	struct janz_fragcache *lastnew;
	struct janz_fragcache *firstold;
	struct janz_fragcache *lastold;

	if (!q->fragcache_used)
		return;

	old = now - nsmul(60, NSEC_PER_SEC);

	if (old <= q->fragcache_aged)
		return;

	if (old <= q->fragcache_used->ts) {
		lastnew = q->fragcache_used;
		while (lastnew->next && (old <= lastnew->next->ts))
			lastnew = lastnew->next;
		q->fragcache_aged = lastnew->ts;
		if (!lastnew->next) {
			/* shouldn’t happen, but… */
			return;
		}
		firstold = lastnew->next;
		lastold = q->fragcache_last;
		lastnew->next = NULL;
		q->fragcache_last = lastnew;
		lastold->next = q->fragcache_free;
		q->fragcache_free = firstold;
	} else {
		q->fragcache_last->next = q->fragcache_free;
		q->fragcache_free = q->fragcache_used;
		q->fragcache_used = NULL;
		q->fragcache_last = NULL;
	}
}
#endif

static inline void
janz_drop_pkt(struct Qdisc *sch, struct janz_priv *q, u64 now, int qid,
    bool resizing)
{
	struct sk_buff *skb;
	struct janz_skb *cb;
#if JANZ_REPORTING
	u64 qdelay;
	u32 qd1024;
#endif

	skb = q->q[qid].first;
	if (!(q->q[qid].first = skb->next))
		q->q[qid].last = NULL;
	--sch->q.qlen;
	cb = get_janz_skb(skb);
	q->memusage -= cb->truesz;
	qdisc_qstats_backlog_dec(sch, skb);
#if JANZ_REPORTING
	cb->record_flag |= TC_JANZ_RELAY_SOJOURN_DROP;
	if (resizing)
		qd1024 = 0xFFFFFFFFUL;
	else if (unlikely(cb->enq_ts > now))
		qd1024 = 0xFFFFFFFEUL;
	else if ((qdelay = now - cb->enq_ts) > t1024_to_ns(0xFFFFFFFDUL))
		qd1024 = 0xFFFFFFFDUL;
	else
		qd1024 = ns_to_t1024(qdelay);
	janz_record_packet(q, skb, cb, now, qd1024, 0);
#endif
	/* inefficient for large reduction in sch->limit (resizing = true) */
	/* but we assume this doesn’t happen often, if at all */
	rtnl_kfree_skbs(skb, skb);
}

static inline void
janz_drop_1pkt(struct Qdisc *sch, struct janz_priv *q, u64 now, bool resizing)
{
	if (q->q[2].first)
		janz_drop_pkt(sch, q, now, 2, resizing);
	else if (q->q[1].first)
		janz_drop_pkt(sch, q, now, 1, resizing);
	else if (likely(q->q[0].first))
		janz_drop_pkt(sch, q, now, 0, resizing);
}

static inline void
janz_drop_overlen(struct Qdisc *sch, struct janz_priv *q, u64 now, bool isenq)
{
	do {
		janz_drop_1pkt(sch, q, now, !isenq);
	} while (unlikely(sch->q.qlen > sch->limit));
}

static inline bool
janz_qheadolder(u64 ots, struct janz_priv *q, int qid)
{
	struct janz_skb *cb;

	if (unlikely(!q->q[qid].first))
		return (false);
	cb = get_janz_skb(q->q[qid].first);
	return ((unlikely(cb->enq_ts < ots)) ? true : false);
}

static inline void
janz_dropchk(struct Qdisc *sch, struct janz_priv *q, u64 now)
{
	u64 ots;
	int qid;

	if (now < q->drop_next)
		return;

	/* drop one packet if one or more packets are older than 100 ms */
	ots = now - nsmul(100, NSEC_PER_MSEC);
	if (janz_qheadolder(ots, q, 2) ||
	    janz_qheadolder(ots, q, 1) ||
	    janz_qheadolder(ots, q, 0))
		janz_drop_1pkt(sch, q, now, false);

	/* drop all packets older than 500 ms */
	ots = now - nsmul(500, NSEC_PER_MSEC);
	for (qid = 0; qid <= 2; ++qid)
		while (janz_qheadolder(ots, q, qid))
			janz_drop_pkt(sch, q, now, qid, false);

	q->drop_next += DROPCHK_INTERVAL;
	now = ktime_get_ns();
	if (q->drop_next < now)
		q->drop_next = now + DROPCHK_INTERVAL;
}

static inline struct sk_buff *
janz_getnext(struct Qdisc *sch, struct janz_priv *q, bool is_peek)
{
	u64 now, rs;
	struct sk_buff *skb;
	struct janz_skb *cb;
	int qid;

	now = ktime_get_ns();
	rs = (u64)~(u64)0U;
	janz_dropchk(sch, q, now);

	if (now < q->notbefore) {
		if (!is_peek)
			qdisc_watchdog_schedule_range_ns(&q->watchdog,
			    min(q->notbefore, q->drop_next),
			    NSEC_PER_MSEC);
		skb = NULL;
		goto out;
	}

	/* we have reached notbefore, previous packet is fully sent */

	if (!sch->q.qlen) {
		/* nothing to send, start subsequent packet later */
 nothing_to_send:
		q->crediting = 0;
		skb = NULL;
		goto out;
	}

#define try_qid(i) do {							\
	qid = (i);							\
	skb = q->q[qid].first;						\
	if (skb) {							\
		cb = get_janz_skb(skb);					\
		if (is_peek)						\
			return (skb);					\
		if (now >= cb->enq_ts)					\
			goto got_skb;					\
		/* now < enq_ts: packet has not reached us yet */	\
		if (cb->enq_ts < rs)					\
			rs = cb->enq_ts;				\
	}								\
} while (/* CONSTCOND */ 0)

	try_qid(0);
	try_qid(1);
	try_qid(2);

	/* nothing to send, but we have to reschedule first */
	/* if we end up here, rs has been assigned at least once */
	qdisc_watchdog_schedule_range_ns(&q->watchdog, rs, 0);
	goto nothing_to_send;

 got_skb:
	if (!(q->q[qid].first = skb->next))
		q->q[qid].last = NULL;
	--sch->q.qlen;
	q->memusage -= cb->truesz;
	skb->next = NULL;
	qdisc_qstats_backlog_dec(sch, skb);
	qdisc_bstats_update(sch, skb);

	q->notbefore = (q->crediting ? q->notbefore : now) +
	    (q->ns_pro_byte * (u64)skb->len);
	q->crediting = 1;

 out:
#if JANZ_REPORTING
	if (now >= q->qsz_next)
		janz_record_queuesz(sch, q, now, 0);
#endif
	return (skb);
}

static inline void
janz_sendoff(struct Qdisc *sch, struct janz_priv *q, struct sk_buff *skb)
{
	u64 qdelay;
	u64 now = ktime_get_ns();
	struct janz_skb *cb = get_janz_skb(skb);
	u16 chance;

	qdelay = now - cb->enq_ts;

	/**
	 * maths proof, by example:
	 *
	 * tmin=0 tmax=10 - select a random number r ∈ [tmin;tmax[
	 *
	 * t	  %	list r < t | r >= t
	 * ----+-------+----------------------
	 * 0	  0	| 0,1,2,3,4,5,6,7,8,9	← can’t happen (as t > tmin)
	 * 1	 10	0 | 1,2,3,4,5,6,7,8,9	10% of all possible r are < t
	 * 2	 20	0,1 | 2,3,4,5,6,7,8,9	20%     "      "
	 * 3	 30	0,1,2 | 3,4,5,6,7,8,9	(etc. pp)
	 * 4	 40	0,1,2,3 | 4,5,6,7,8,9
	 * 5	 50	0,1,2,3,4 | 5,6,7,8,9
	 * 6	 60	0,1,2,3,4,5 | 6,7,8,9
	 * 7	 70	0,1,2,3,4,5,6 | 7,8,9
	 * 8	 80	0,1,2,3,4,5,6,7 | 8,9	(…)
	 * 9	 90	0,1,2,3,4,5,6,7,8 | 9	90% of all possible r are < t
	 * 10	100	0,1,2,3,4,5,6,7,8,9 |	← can’t happen (as t < tmax)
	 *
	 * even the cases that can’t happen would work correctly
	 */
	if (qdelay >= q->markfull) {
		chance = 0xFFFFU;
		goto domark;
	} else if (qdelay <= q->markfree)
		chance = 0;
	else {
		/* we know: tmin < t < tmax */
		/* tmin = markfree, t = qdelay, tmax = markfull */
		u64 t = qdelay - q->markfree;
		u64 tmax = q->markfull - q->markfree;
		/* now we have: 0 < t' < tmax' */

		/* scale tmax' for fitting into u32 for below */
		while (unlikely(tmax > (u64)0xFFFFFFFFUL)) {
			tmax >>= 1;
			t >>= 1;
		}

		{
			/* scale tmax' to 65535 to calculate the chance */
			u64 c = t;
			c *= 65535U;
			/* for rounding */
			c += (tmax / 2U);
			/* result [0; 65535] */
			chance = div_u64(c, tmax);
		}

		/*
		 * we want to mark with (t' / tmax' * 100)% probability
		 * therefore we need a random number in [0; tmax'[ then
		 * ECN CE mark if the number is smaller than t'
		 */
		if (prandom_u32_max(tmax) < t) {
 domark:
#if JANZ_REPORTING
			cb->record_flag |= TC_JANZ_RELAY_SOJOURN_MARK;
			if (INET_ECN_set_ce(skb))
				cb->record_flag |= (u8)INET_ECN_CE << 3;
#else
			INET_ECN_set_ce(skb);
#endif
		}
	}
#if JANZ_REPORTING
	janz_record_packet(q, skb, cb, now, ns_to_t1024(qdelay), chance);
#endif
}

static inline void
janz_initcb(struct Qdisc *sch, struct janz_priv *q,
    struct sk_buff *skb, struct janz_skb *cb, u64 now)
{
	cb->enq_ts = now + q->xlatency;
	cb->truesz = skb->truesize;
	/* init values */
	cb->srcport = 0;
	cb->dstport = 0;
	cb->tosbyte = 0;
	cb->ipver = 0;
	cb->nexthdr = 0;
#if JANZ_REPORTING
	cb->record_flag = 0;
#endif
}

#if JANZ_REPORTING
static inline void
janz_init_record_flag(struct janz_skb *cb)
{
	u8 ecnbits;

	ecnbits = cb->tosbyte & INET_ECN_MASK;
	/* assuming out=in, at first */
	ecnbits |= ecnbits << 3;
	/* we get called if valid only */
	ecnbits |= 4U;
	cb->record_flag = ecnbits;
}

static inline void
janz_analyse(struct Qdisc *sch, struct janz_priv *q,
    struct sk_buff *skb, struct janz_skb *cb, u64 now)
{
	unsigned char *hdrp;
	unsigned char *endoflineardata = skb->data + skb_headlen(skb);
	/* normally: the nexthdr for IPv6’s no payload marker */
	u8 noportinfo = 59;
	int fragoff = -1;
	struct janz_fragcomp fc;
	struct ipv6hdr *ih6;
	struct iphdr *ih4;

	janz_initcb(sch, q, skb, cb, now);

	/* addresses */
	switch (skb->protocol) {
	case htons(ETH_P_IP):
		ih4 = ip_hdr(skb);
		hdrp = (void *)ih4;
		if ((hdrp + sizeof(struct iphdr)) > endoflineardata) {
			JANZ_IP_DECODER_DEBUG(KERN_DEBUG "sch_janz: IPv4 too short\n");
			return;
		}
		JANZ_IP_DECODER_DEBUG(KERN_DEBUG "sch_janz: IPv4 %08X->%08X proto %u frag %d\n",
		    htonl(ih4->saddr), htonl(ih4->daddr), ih4->protocol, ip_is_fragment(ih4) ? 1 : 0);
		cb->tosbyte = ih4->tos;
		janz_init_record_flag(cb);
		cb->ipver = 4;
		cb->nexthdr = ih4->protocol;
		hdrp += ih4->ihl * 4;
		/* Legacy IP fragmentation */
		if (ip_is_fragment(ih4)) {
			/* use nexthdr from IPv6 frag header as indicator */
			noportinfo = 44;
			/* fragment information */
			ipv6_addr_set_v4mapped(ih4->saddr, &fc.sip);
			ipv6_addr_set_v4mapped(ih4->daddr, &fc.dip);
			fc.idp = ((u32)ih4->protocol << 24) | ((u32)ih4->id & 0xFFFFU);
			fc.v = 4;	/* must be same as ipver */
			if ((fragoff = ntohs(ih4->frag_off) & IP_OFFSET) != 0) {
				/* higher fragment */
				/* use cached fragments info */
				goto higher_fragment;
			}
			/* first fragment */
			/* fall through to unfragmented packet handler */
		}
		break;
	case htons(ETH_P_IPV6):
		ih6 = ipv6_hdr(skb);
		hdrp = (void *)ih6;
		if ((hdrp + sizeof(struct ipv6hdr)) > endoflineardata) {
			JANZ_IP_DECODER_DEBUG(KERN_DEBUG "sch_janz: IPv6 too short\n");
			return;
		}
		JANZ_IP_DECODER_DEBUG(KERN_DEBUG "sch_janz: IPv6 %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X->%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X nexthdr %u\n",
		    ih6->saddr.s6_addr[0], ih6->saddr.s6_addr[1], ih6->saddr.s6_addr[2], ih6->saddr.s6_addr[3],
		    ih6->saddr.s6_addr[4], ih6->saddr.s6_addr[5], ih6->saddr.s6_addr[6], ih6->saddr.s6_addr[7],
		    ih6->saddr.s6_addr[8], ih6->saddr.s6_addr[9], ih6->saddr.s6_addr[10], ih6->saddr.s6_addr[11],
		    ih6->saddr.s6_addr[12], ih6->saddr.s6_addr[13], ih6->saddr.s6_addr[14], ih6->saddr.s6_addr[15],
		    ih6->daddr.s6_addr[0], ih6->daddr.s6_addr[1], ih6->daddr.s6_addr[2], ih6->daddr.s6_addr[3],
		    ih6->daddr.s6_addr[4], ih6->daddr.s6_addr[5], ih6->daddr.s6_addr[6], ih6->daddr.s6_addr[7],
		    ih6->daddr.s6_addr[8], ih6->daddr.s6_addr[9], ih6->daddr.s6_addr[10], ih6->daddr.s6_addr[11],
		    ih6->daddr.s6_addr[12], ih6->daddr.s6_addr[13], ih6->daddr.s6_addr[14], ih6->daddr.s6_addr[15],
		    ih6->nexthdr);
		cb->tosbyte = ipv6_get_dsfield(ih6);
		janz_init_record_flag(cb);
		cb->ipver = 6;
		cb->nexthdr = ih6->nexthdr;
		hdrp += 40;
		break;
	/* fake iptos for the rest */
	case htons(ETH_P_ARP):
		JANZ_IP_DECODER_DEBUG(KERN_DEBUG "sch_janz: ARP packet\n");
		cb->tosbyte = 0x10;	/* interactive/lodelay */
		return;
	case htons(ETH_P_RARP):
		JANZ_IP_DECODER_DEBUG(KERN_DEBUG "sch_janz: RARP packet\n");
		cb->tosbyte = 0x10;
		return;
	case htons(ETH_P_PPP_DISC):
		JANZ_IP_DECODER_DEBUG(KERN_DEBUG "sch_janz: PPPoE discovery packet\n");
		cb->tosbyte = 0x10;
		return;
	case htons(ETH_P_LOOP):
	case htons(ETH_P_LOOPBACK):
		JANZ_IP_DECODER_DEBUG(KERN_DEBUG "sch_janz: ethernet loopback packet\n");
		cb->tosbyte = 0x08;	/* bulk */
		return;
	default:
		JANZ_IP_DECODER_DEBUG(KERN_DEBUG "sch_janz: unknown proto htons(0x%04X)\n", (unsigned)ntohs(skb->protocol));
		return;
	}
	/* we end here only if the packet is IPv4 or IPv6 */

 try_nexthdr:
	switch (cb->nexthdr) {
	case 6:		/* TCP */
	case 17:	/* UDP */
		/* both begin with src and dst ports in this order */
		if ((hdrp + 4) > endoflineardata) {
			JANZ_IP_DECODER_DEBUG(KERN_DEBUG "sch_janz: %u too short\n", cb->nexthdr);
			goto no_ports;
		}
		cb->srcport = ((unsigned int)hdrp[0] << 8) | hdrp[1];
		cb->dstport = ((unsigned int)hdrp[2] << 8) | hdrp[3];
		break;
	case 0:		/* IPv6 hop-by-hop options */
	case 43:	/* IPv6 routing */
	case 60:	/* IPv6 destination options */
		if ((hdrp + 4) > endoflineardata) {
			JANZ_IP_DECODER_DEBUG(KERN_DEBUG "sch_janz: %u too short\n", cb->nexthdr);
			goto no_ports;
		}
		cb->nexthdr = hdrp[0];
		hdrp += ((unsigned int)hdrp[1] + 1U) * 8U;
		goto try_nexthdr;
	case 44:	/* IPv6 fragment */
		if ((hdrp + 8) > endoflineardata) {
			JANZ_IP_DECODER_DEBUG(KERN_DEBUG "sch_janz: %u too short\n", cb->nexthdr);
			goto no_ports;
		}
		if (fragoff != -1) {
			JANZ_IP_DECODER_DEBUG(KERN_DEBUG "sch_janz: two fragment headers\n");
			goto no_ports;
		}
		if (cb->ipver != 6) {
			JANZ_IP_DECODER_DEBUG(KERN_DEBUG "sch_janz: IPv6 fragment header in %d packet\n", cb->ipver);
			goto no_ports;
		}
		memcpy(&fc.sip, ih6->saddr.s6_addr, 16);
		memcpy(&fc.dip, ih6->daddr.s6_addr, 16);
		memcpy(&fc.idp, hdrp + 4, 4);
		fc.v = 6;	/* must be same as ipver */
		/* update failure cause */
		noportinfo = 44;
		/* first fragment? */
		fragoff = (((unsigned int)hdrp[2] << 8) | hdrp[3]) & 0xFFF8U;
		JANZ_IP_DECODER_DEBUG(KERN_DEBUG "sch_janz: frag, ofs %u, nexthdr %u\n", fragoff, hdrp[0]);
		if (fragoff) {
			/* nope */
			goto higher_fragment;
		}
		cb->nexthdr = hdrp[0];
		hdrp += 8;
		goto try_nexthdr;
	case 51:	/* IPsec AH */
		if ((hdrp + 4) > endoflineardata) {
			JANZ_IP_DECODER_DEBUG(KERN_DEBUG "sch_janz: %u too short\n", cb->nexthdr);
			goto no_ports;
		}
		cb->nexthdr = hdrp[0];
		hdrp += ((unsigned int)hdrp[1] + 2U) * 4U;
		goto try_nexthdr;
	case 135:	/* Mobile IP */
	case 139:	/* Host Identity Protocol v2 */
	case 140:	/* SHIM6: Site Multihoming by IPv6 Intermediation */
		if ((hdrp + 4) > endoflineardata) {
			JANZ_IP_DECODER_DEBUG(KERN_DEBUG "sch_janz: %u too short\n", cb->nexthdr);
			goto done_addresses;
		}
		/* this kind of extension header has no payload normally */
		if (hdrp[0] == 59)
			goto done_addresses;
		cb->nexthdr = hdrp[0];
		hdrp += ((unsigned int)hdrp[1] + 1U) * 8U;
		goto try_nexthdr;
	default:	/* any other L4 protocol, unknown extension headers */
		JANZ_IP_DECODER_DEBUG(KERN_DEBUG "sch_janz: unknown exthdr %u\n", cb->nexthdr);
		break;
	}
	/* we end here if either nexthdr is TCP/UDP and ports are filled in */
	/* or it’s another L4 proto; ports are 0 then */
 done_addresses:
	if (fragoff != -1) {
		struct janz_fragcache *fe;

		janz_fragcache_maint(q, now);
		/* record for later packets */

		if (unlikely(q->fragcache_free == NULL)) {
			net_warn_ratelimited("sch_janz: no free fragment cache, please raise count\n");
			/* reuse last one */
			fe = q->fragcache_used;
			while (fe->next->next != NULL)
				fe = fe->next;
			q->fragcache_last = fe;
			q->fragcache_aged = fe->ts;
			fe = fe->next;
			q->fragcache_last->next = NULL;
		} else {
			fe = q->fragcache_free;
			q->fragcache_free = fe->next;
		}
		memcpy(&(fe->c), &fc, sizeof(struct janz_fragcomp));
		fe->nexthdr = cb->nexthdr;
		fe->ts = cb->enq_ts;
		fe->sport = cb->srcport;
		fe->dport = cb->dstport;
		fe->next = q->fragcache_used;
		if (unlikely(!fe->next)) {
			q->fragcache_last = fe;
			q->fragcache_aged = fe->ts;
		}
		q->fragcache_used = fe;
	}
	return;

 higher_fragment: {
	struct janz_fragcache *fe;

	janz_fragcache_maint(q, now);
	fe = q->fragcache_used;
	while (fe) {
		if (!memcmp(&fc, &(fe->c), sizeof(struct janz_fragcomp))) {
			cb->nexthdr = fe->nexthdr;
			cb->srcport = fe->sport;
			cb->dstport = fe->dport;
			return;
		}
		fe = fe->next;
	}
    }

 no_ports:
	/* we end here if the packet buffer does not contain enough info */
	cb->nexthdr = noportinfo;
	return;
}
#else
static inline void
janz_analyse(struct Qdisc *sch, struct janz_priv *q,
    struct sk_buff *skb, struct janz_skb *cb, u64 now)
{
	janz_initcb(sch, q, skb, cb, now);
}
#endif

static struct dentry *
janz_debugfs_create(const char *filename, struct dentry *parent,
    umode_t mode, struct rchan_buf *buf, int *is_global)
{
	*is_global = 1;
	return (debugfs_create_file(filename, mode, parent, buf,
	    &relay_file_operations));
}

static int
janz_debugfs_destroy(struct dentry *dentry)
{
	debugfs_remove(dentry);
	return (0);
}

static int
janz_subbuf_init(struct rchan_buf *buf, void *subbuf_,
    void *prev_subbuf, size_t prev_padding)
{
	size_t n;
	struct tc_janz_relay *subbuf = (struct tc_janz_relay *)subbuf_;
	struct tc_janz_relay bufinit = { 0, TC_JANZ_RELAY_PADDING };

	for (n = 0; n < TC_JANZ_RELAY_NRECORDS; ++n)
		subbuf[n] = bufinit;

	return (1);
}

static int
janz_enq(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free)
{
	struct janz_priv *q = qdisc_priv(sch);
	struct janz_skb *cb = get_janz_skb(skb);
	u8 qid;
	u32 prev_backlog = sch->qstats.backlog;
	bool overlimit;
	u64 now;

	now = ktime_get_ns();
	janz_dropchk(sch, q, now);
	janz_analyse(sch, q, skb, cb, now);

	qid = 1;
	if (cb->tosbyte & 0x10)
		--qid;
	if (cb->tosbyte & 0x08)
		++qid;

	// assumption is 1 packet is passed
	if (WARN(skb->next != NULL, "janz_enq passed multiple packets?"))
		skb->next = NULL;

	q->memusage += cb->truesz;
	if (unlikely(overlimit = (++sch->q.qlen > sch->limit)))
		janz_drop_overlen(sch, q, now, true);
	if (!q->q[qid].first) {
		q->q[qid].first = skb;
		q->q[qid].last = skb;
	} else {
		q->q[qid].last->next = skb;
		q->q[qid].last = skb;
	}
	qdisc_qstats_backlog_inc(sch, skb);

#if JANZ_REPORTING
	if (now >= q->qsz_next)
		janz_record_queuesz(sch, q, now, 0);
#endif

	if (unlikely(overlimit)) {
		qdisc_qstats_overlimit(sch);
		qdisc_tree_reduce_backlog(sch, 0,
		    prev_backlog - sch->qstats.backlog);
		return (NET_XMIT_CN);
	}
	return (NET_XMIT_SUCCESS);
}

static struct sk_buff *
janz_deq(struct Qdisc *sch)
{
	struct janz_priv *q = qdisc_priv(sch);
	struct sk_buff *skb;

	if ((skb = janz_getnext(sch, q, false)))
		janz_sendoff(sch, q, skb);
	return (skb);
}

static struct sk_buff *
janz_peek(struct Qdisc *sch)
{
	struct janz_priv *q = qdisc_priv(sch);
	static bool warned_about_peek = false;

	if (!warned_about_peek) {
		printk(KERN_WARNING "sch_janz: .peek called... why exactly?\n");
		warned_about_peek = true;
	}
	return (janz_getnext(sch, q, true));
}

static inline void
janz_reset(struct Qdisc *sch)
{
	struct janz_priv *q = qdisc_priv(sch);

	ASSERT_RTNL();
	if (sch->q.qlen) {
		rtnl_kfree_skbs(q->q[0].first, q->q[0].last);
		rtnl_kfree_skbs(q->q[1].first, q->q[1].last);
		rtnl_kfree_skbs(q->q[2].first, q->q[2].last);
		sch->q.qlen = 0;
	}
	q->q[0].first = NULL; q->q[0].last = NULL;
	q->q[1].first = NULL; q->q[1].last = NULL;
	q->q[2].first = NULL; q->q[2].last = NULL;
	q->memusage = 0;
	sch->qstats.backlog = 0;
	sch->qstats.overlimits = 0;
	q->notbefore = 0;
	q->crediting = 0;
	if (q->record_chan)
		relay_flush(q->record_chan);
}

static const struct nla_policy janz_nla_policy[TCA_JANZ_MAX + 1] = {
	[TCA_JANZ_LIMIT]	= { .type = NLA_U32 },
	[TCA_JANZ_RATE64]	= { .type = NLA_U64 },
	[TCA_JANZ_HANDOVER]	= { .type = NLA_U32 },
	[TCA_JANZ_MARKFREE]	= { .type = NLA_U32 },
	[TCA_JANZ_MARKFULL]	= { .type = NLA_U32 },
	[TCA_JANZ_SUBBUFS]	= { .type = NLA_U32 },
	[TCA_JANZ_FRAGCACHE]	= { .type = NLA_U32 },
};

static inline int
janz_chg(struct Qdisc *sch, struct nlattr *opt, struct netlink_ext_ack *extack)
{
	struct janz_priv *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_JANZ_MAX + 1];
	int err;
	bool rate_changed = false;
	bool handover_started = false;

	if (!opt)
		return (-EINVAL);

	if ((err = nla_parse_nested_deprecated(tb, TCA_JANZ_MAX, opt,
	    janz_nla_policy, extack)) < 0)
		return (err);

	/* anything that can throw first */

	if (q->nsubbufs) {
		/* only at load time */
		if (tb[TCA_JANZ_SUBBUFS] || tb[TCA_JANZ_FRAGCACHE])
			return (-EINVAL);
	}

	/* now actual configuring */
	sch_tree_lock(sch);
	/* no memory allocation, returns, etc. now */

	if (tb[TCA_JANZ_LIMIT])
		sch->limit = nla_get_u32(tb[TCA_JANZ_LIMIT]) ? : 1;

	if (tb[TCA_JANZ_RATE64]) {
		u64 tmp = nla_get_u64(tb[TCA_JANZ_RATE64]);

		tmp = div64_u64(NSEC_PER_SEC, tmp);
		if (tmp < 1)
			tmp = 1;
		if (q->ns_pro_byte != tmp) {
			q->ns_pro_byte = tmp;
			rate_changed = true;
		}
	}

	if (tb[TCA_JANZ_HANDOVER]) {
		u64 tmp = nla_get_u32(tb[TCA_JANZ_HANDOVER]);

		handover_started = tmp != 0;
		tmp *= NSEC_PER_USEC;
		tmp += ktime_get_ns();
		/* implementation of handover */
		q->notbefore = tmp < q->notbefore ? q->notbefore : tmp;
		q->crediting = 0;
	}

	if (tb[TCA_JANZ_MARKFREE])
		q->markfree = us_to_ns(nla_get_u32(tb[TCA_JANZ_MARKFREE]));

	if (tb[TCA_JANZ_MARKFULL])
		q->markfull = us_to_ns(nla_get_u32(tb[TCA_JANZ_MARKFULL]));

	if (tb[TCA_JANZ_SUBBUFS])
		/* only at load time */
		q->nsubbufs = nla_get_u32(tb[TCA_JANZ_SUBBUFS]);

#if JANZ_REPORTING
	if (tb[TCA_JANZ_FRAGCACHE])
		/* only at load time */
		q->fragcache_num = nla_get_u32(tb[TCA_JANZ_FRAGCACHE]);
#endif

	if (tb[TCA_JANZ_XLATENCY])
		q->xlatency = us_to_ns(nla_get_u32(tb[TCA_JANZ_XLATENCY]));

	/* assert: sch->q.qlen == 0 || q->record_chan != nil */
	/* assert: sch->limit > 0 */
	if (unlikely(sch->q.qlen > sch->limit))
		janz_drop_overlen(sch, q, ktime_get_ns(), false);

#if JANZ_REPORTING
	if (q->record_chan) {
		/* report if rate changes or a handover starts */
		if (rate_changed || handover_started)
			janz_record_queuesz(sch, q, ktime_get_ns(), 1);
		/* flush subbufs before handover */
		if (handover_started)
			relay_flush(q->record_chan);
	}
#endif

	sch_tree_unlock(sch);
	return (0);
}

static struct dentry *janz_debugfs_main __read_mostly;

static /*const*/ struct rchan_callbacks janz_debugfs_relay_hooks = {
	.create_buf_file = janz_debugfs_create,
	.remove_buf_file = janz_debugfs_destroy,
	.subbuf_start = janz_subbuf_init,
};

static int
janz_init(struct Qdisc *sch, struct nlattr *opt, struct netlink_ext_ack *extack)
{
	struct janz_priv *q = qdisc_priv(sch);
	int err;
	char name[6];
	u64 now;
#if JANZ_REPORTING
	int i;
#endif

	/* config values’ defaults */
	sch->limit = 10240;
	q->ns_pro_byte = 800; /* 10 Mbit/s */
	q->markfree = nsmul(4, NSEC_PER_MSEC);
	q->markfull = nsmul(14, NSEC_PER_MSEC);
	q->nsubbufs = 0;
#if JANZ_REPORTING
	q->fragcache_num = 0;
#endif
	q->xlatency = 0;

	/* qdisc state */
	sch->q.qlen = 0;
	/* needed so janz_reset DTRT */
	q->record_chan = NULL;
	janz_reset(sch);
	qdisc_watchdog_init_clockid(&q->watchdog, sch, CLOCK_MONOTONIC);

	if (opt && (err = janz_chg(sch, opt, extack)))
		goto init_fail;

	if (q->nsubbufs < 4U || q->nsubbufs > 0x000FFFFFU)
		q->nsubbufs = 1024;

#if JANZ_REPORTING
	if (q->fragcache_num < 16U || q->fragcache_num > 0x00FFFFFFU)
		q->fragcache_num = 1024;
#endif

	snprintf(name, sizeof(name), "%04X:", sch->handle >> 16);
	q->record_chan = relay_open(name, janz_debugfs_main,
	    TC_JANZ_RELAY_SUBBUFSZ, q->nsubbufs,
	    &janz_debugfs_relay_hooks, sch);
	if (!q->record_chan) {
		printk(KERN_WARNING "sch_janz: relay channel creation failed\n");
		err = -ENOENT;
		goto init_fail;
	}
#if JANZ_REPORTING
	spin_lock_init(&q->record_lock);

	q->fragcache_base = kvcalloc(q->fragcache_num,
	    sizeof(struct janz_fragcache), GFP_KERNEL);
	if (!q->fragcache_base) {
		err = -ENOMEM;
		goto init_fail;
	}
	q->fragcache_used = NULL;
	q->fragcache_last = NULL;
	q->fragcache_free = &(q->fragcache_base[0]);
	for (i = 1; i < q->fragcache_num; ++i)
		q->fragcache_base[i - 1].next = &(q->fragcache_base[i]);
	q->fragcache_base[q->fragcache_num - 1].next = NULL;
	q->fragcache_aged = 0;
#endif

	now = ktime_get_ns();
#if JANZ_REPORTING
	q->qsz_next = now + QSZ_INTERVAL;
#endif
	q->drop_next = now + DROPCHK_INTERVAL;

	sch->flags &= ~TCQ_F_CAN_BYPASS;
	return (0);

 init_fail:
	if (q->record_chan) {
		relay_close(q->record_chan);
		q->record_chan = NULL;
	}
	return (err);
}

#if JANZ_REPORTING
/* workaround to relay_close late using the global workqueue */

struct janz_gwq_ovl {
	struct delayed_work dwork;
	struct rchan *record_chan;
};

static void
janz_gwq_fn(struct work_struct *work)
{
	struct janz_gwq_ovl *ovl = container_of(to_delayed_work(work),
	    struct janz_gwq_ovl, dwork);

	relay_close(ovl->record_chan);
	kvfree(ovl);
}
#endif

static void
janz_done(struct Qdisc *sch)
{
	struct janz_priv *q = qdisc_priv(sch);
#if JANZ_REPORTING
	struct janz_gwq_ovl *ovl;
#endif

	qdisc_watchdog_cancel(&q->watchdog);

	if (!q->record_chan) {
		/* the fast/easy path out, do everything now */
#if JANZ_REPORTING
		kvfree(q->fragcache_base);
#endif
		return;
	}

#if JANZ_REPORTING
	if (!q->fragcache_base) {
#endif
		/* all bets off… */
		relay_close(q->record_chan);
		return;
#if JANZ_REPORTING
	}

	/*
	 * we need to relay_flush() now but relay_close() later so that
	 * userspace has a chance to actually read the information; for
	 * that, deferred work can be used, but where to put the struct
	 * for that? easy, reuse q->fragcache_base memory, free it last
	 * inside the worker function (this is explicitly permitted) ;)
	 */

	relay_flush(q->record_chan);

	ovl = (void *)q->fragcache_base;
	ovl->record_chan = q->record_chan;
	INIT_DELAYED_WORK(&ovl->dwork, janz_gwq_fn);

	schedule_delayed_work(&ovl->dwork, msecs_to_jiffies(1000));
#endif
}

static int
janz_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct janz_priv *q = qdisc_priv(sch);
	struct nlattr *opts;

	opts = nla_nest_start(skb, TCA_OPTIONS);
	if (opts == NULL)
		goto nla_put_failure;

	if (nla_put_u64_64bit(skb, TCA_JANZ_RATE64,
	      div64_u64(NSEC_PER_SEC, q->ns_pro_byte), TCA_JANZ_PAD64) ||
	    nla_put_u32(skb, TCA_JANZ_MARKFREE, ns_to_us(q->markfree)) ||
	    nla_put_u32(skb, TCA_JANZ_MARKFULL, ns_to_us(q->markfull)) ||
	    nla_put_u32(skb, TCA_JANZ_SUBBUFS, q->nsubbufs) ||
#if JANZ_REPORTING
	    nla_put_u32(skb, TCA_JANZ_FRAGCACHE, q->fragcache_num) ||
#endif
	    nla_put_u32(skb, TCA_JANZ_XLATENCY, ns_to_us(q->xlatency)) ||
	    nla_put_u32(skb, TCA_JANZ_LIMIT, sch->limit))
		goto nla_put_failure;

	return (nla_nest_end(skb, opts));

 nla_put_failure:
	return (-1);
}

static struct Qdisc_ops janz_ops __read_mostly = {
	.id		= "janz",
	.priv_size	= sizeof(struct janz_priv),
	.enqueue	= janz_enq,
	.dequeue	= janz_deq,
	.peek		= janz_peek,
	.init		= janz_init,
	.reset		= janz_reset,
	.destroy	= janz_done,
	.change		= janz_chg,
	.dump		= janz_dump,
	.owner		= THIS_MODULE
};

static int __init
janz_modinit(void)
{
	int rv;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
	printk(KERN_WARNING "sch_janz: kernel too old: will misfunction for locally originating packets, see README\n");
#endif

	if (!(janz_debugfs_main = debugfs_create_dir("sch_janz", NULL)))
		rv = -ENOSYS;
	else
		rv = PTR_ERR_OR_ZERO(janz_debugfs_main);
	if (rv) {
		printk(KERN_WARNING "sch_janz: debugfs initialisation error\n");
		goto e0;
	}

	rv = register_qdisc(&janz_ops);

	if (rv)
		debugfs_remove(janz_debugfs_main);

 e0:
	return (rv);
}

static void __exit
janz_modexit(void)
{
	unregister_qdisc(&janz_ops);
	debugfs_remove(janz_debugfs_main);
}

module_init(janz_modinit);
module_exit(janz_modexit);
MODULE_AUTHOR("Deutsche Telekom LLCTO");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("bespoke egress traffic scheduler for the JENS network simulator");

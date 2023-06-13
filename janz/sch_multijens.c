/*
 * JENS qdisc with multiple UE support
 *
 * Copyright © 2022, 2023 mirabilos <t.glaser@tarent.de>
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

static inline s32
cmp1024(u32 lhs, u32 rhs)
{
	u32 delta = (0U + lhs) - (0U + rhs);

	return ((s32)delta); /* guaranteed in Linux */
}

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
	u8 _pad[2];				//@ +38 :2
	u32 ts;					//@ +40 :4
	u16 sport;				//@ +44 :2
	u16 dport;				//@ +46 :2
	struct janz_fragcache *next;		//@16   :ptr
} __attribute__((__packed__));

/* compile-time assertion */
struct janz_fragcache_check {
	int hasatomic64[sizeof(atomic64_t) == 8 ? 1 : -1];
	int cmp[sizeof(struct janz_fragcomp) == 37 ? 1 : -1];
	int cac[sizeof(struct janz_fragcache) == (48 + sizeof(void *)) ? 1 : -1];
	int tot[sizeof(struct janz_fragcache) <= 64 ? 1 : -1];
	int xip[sizeof_field(struct tc_janz_relay, xip) == 16 ? 1 : -1];
	int yip[sizeof_field(struct tc_janz_relay, yip) == 16 ? 1 : -1];
	int x_y[offsetof(struct tc_janz_relay, yip) ==
	    (offsetof(struct tc_janz_relay, xip) + 16) ? 1 : -1];
	int s_d[offsetof(struct janz_fragcomp, dip) ==
	    (offsetof(struct janz_fragcomp, sip) + 16) ? 1 : -1];
};

/* workaround to relay_close late using the global workqueue */
struct janz_gwq_ovl {
	struct delayed_work dwork;
	u32 uenum;
	struct rchan *record_chans[];
};

struct janz_skbfifo {
	struct sk_buff *first;
	struct sk_buff *last;
};

struct sjanz_priv {
	struct janz_skbfifo q[3];	/* TOS FIFOs */					//@16
	struct rchan *record_chan;	/* relay to userspace */			//@16
#define QSZ_INTERVAL nsmul(500, NSEC_PER_MSEC)
	u64 qsz_next;			/* next time to emit queue-size */		//@  +8
#define DROPCHK_INTERVAL nsmul(200, NSEC_PER_MSEC)
	u64 drop_next;			/* next time to check drops */			//@16
	u64 notbefore;			/* ktime_get_ns() to send next, or 0 */		//@  +8
	atomic64_t ns_pro_byte;		/* traffic shaping tgt bandwidth */		//@16
	u64 markfree;									//@  +8
	u64 markfull;									//@16
	u64 xlatency;			/* extra artificial pre-enqueue latency */	//@  +8
	u64 lastknownrate;								//@16
	u32 memusage;			/* enqueued packet truesize */			//@  +8
	unsigned int qosmode;								//@  +12
	spinlock_t record_lock;		/* for record_chan */				//@16
	u8 crediting;									//@?
};

/* struct mjanz_priv *q = qdisc_priv(sch); */
struct mjanz_priv {
	struct sjanz_priv *subqueues;	/* per-UE sch_janz data */			//@cacheline
	u32 uenum;			/* size of subqueues, ctldata */		//@  +8
	u32 uecur;			/* round-robin pointer */			//@  +12
	struct janz_fragcache *fragcache_used;						//@16
	struct janz_fragcache *fragcache_last; /* last used element */			//@  +8
	struct janz_fragcache *fragcache_free;						//@16
	struct janz_fragcache *fragcache_base;						//@  +8
	struct dentry *ctlfile;								//@16
	u32 fragcache_aged;								//@  +8
	u32 fragcache_num;								//@  +12
	struct janz_ctlfile_pkt *ctldata;	/* per-UE */				//@16
	struct qdisc_watchdog watchdog;	/* to schedule when traffic shaping */		//@  +8
	u32 nsubbufs;									//@?
};

/* struct janz_skb *cb = get_janz_skb(skb); */
struct janz_skb {
	/* limited to QDISC_CB_PRIV_LEN (20) bytes! */
	u32 ts_begin;			/* real enqueue ts1024 */		//@8   :4
	u32 ts_arrive;			/* adjusted by extralatency */		//@ +4 :4
	unsigned int truesz;		/* memory usage */			//@ +8 :4

	u16 srcport;								//@ +12:2
	u16 dstport;								//@ +14:2
	u8 tosbyte;			/* from IPv4/IPv6 header or faked */	//@8   :1
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

static inline ssize_t
janz_ctlfile_write(struct file *filp, const char __user *buf,
    size_t count, loff_t *posp)
{
	u64 newrate;
	u32 ue;
	struct mjanz_priv *q = filp->private_data;

	if (count != sizeof(struct janz_ctlfile_pkt) * (size_t)q->uenum)
		return (-EINVAL);
	if (copy_from_user(q->ctldata, buf, count))
		return (-EFAULT);

	for (ue = 0; ue < q->uenum; ++ue) {
		newrate = div64_u64(8ULL * NSEC_PER_SEC,
		    q->ctldata[ue].bits_per_second);
		if (newrate < 1)
			newrate = 1;
		atomic64_set_release(&(q->subqueues[ue].ns_pro_byte),
		    (s64)newrate);
	}

	return (count);
}

static inline void
janz_record_write(struct tc_janz_relay *record, struct sjanz_priv *q)
{
	unsigned long flags;	/* used by spinlock macros */

	spin_lock_irqsave(&q->record_lock, flags);
	__relay_write(q->record_chan, record, sizeof(struct tc_janz_relay));
	spin_unlock_irqrestore(&q->record_lock, flags);
}

static inline void
janz_record_queuesz(struct Qdisc *sch, struct sjanz_priv *q, u64 now,
    u64 rate, u8 f)
{
	struct tc_janz_relay r = {0};

	if (!rate)
		rate = (u64)atomic64_read_acquire(&(q->ns_pro_byte));
	q->lastknownrate = rate;

	r.ts = now;
	r.type = TC_JANZ_RELAY_QUEUESZ;
	r.d32 = q->memusage;
	r.e16 = sch->q.qlen > 0xFFFFU ? 0xFFFFU : sch->q.qlen;
	r.f8 = f;
	r.x64[0] = div64_u64(NSEC_PER_SEC, rate) * 8ULL;
	r.x64[1] = (u64)ktime_to_ns(ktime_mono_to_real(ns_to_ktime(now))) - now;
	janz_record_write(&r, q);

	/* use of ktime_get_ns() is deliberate */
	q->qsz_next = ktime_get_ns() + QSZ_INTERVAL;
}

static inline void
janz_record_packet(struct sjanz_priv *q,
    struct sk_buff *skb, struct janz_skb *cb, u64 now,
    u32 queuedelay, u16 chance, int qid)
{
	struct tc_janz_relay r = {0};

	r.ts = now;
	r.type = TC_JANZ_RELAY_SOJOURN;
	r.d32 = queuedelay;
	r.e16 = chance;
	r.f8 = cb->record_flag;
	r.z.zSOJOURN.psize = ((u32)(qid + 1)) << 30 | (skb->len & 0x3FFFFFFFU);
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

	r.z.zSOJOURN.real_owd = (u32)cmp1024(ns_to_t1024(ktime_get_ns()),
	    cb->ts_begin);
	janz_record_write(&r, q);
}

static inline void
janz_fragcache_maint(struct mjanz_priv *q, u64 now)
{
	u32 old;
	struct janz_fragcache *lastnew;
	struct janz_fragcache *firstold;
	struct janz_fragcache *lastold;

	if (!q->fragcache_used)
		return;

	old = ns_to_t1024(now - nsmul(60, NSEC_PER_SEC));

	if (cmp1024(old, q->fragcache_aged) <= 0)
		return;

	if (cmp1024(old, q->fragcache_used->ts) <= 0) {
		lastnew = q->fragcache_used;
		while (lastnew->next && (cmp1024(old, lastnew->next->ts) <= 0))
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

static inline void
janz_drop_pkt(struct Qdisc *sch, struct sjanz_priv *q, u64 now, u32 now1024,
    int qid, bool resizing)
{
	struct sk_buff *skb;
	struct janz_skb *cb;
	u32 qd1024;

	skb = q->q[qid].first;
	if (!(q->q[qid].first = skb->next))
		q->q[qid].last = NULL;
	--sch->q.qlen;
	cb = get_janz_skb(skb);
	q->memusage -= cb->truesz;
	qdisc_qstats_backlog_dec(sch, skb);
	cb->record_flag |= TC_JANZ_RELAY_SOJOURN_DROP;
	if (resizing)
		qd1024 = 0xFFFFFFFFUL;
	else if (unlikely(cmp1024(cb->ts_arrive, now1024) > 0))
		qd1024 = 0xFFFFFFFEUL;
	else if (unlikely((qd1024 = now1024 - cb->ts_arrive) > 0xFFFFFFFDUL))
		qd1024 = 0xFFFFFFFDUL;
	janz_record_packet(q, skb, cb, now, qd1024, 0, qid);
	/* inefficient for large reduction in sch->limit (resizing = true) */
	/* but we assume this doesn’t happen often, if at all */
	kfree_skb(skb);
}

static inline void
janz_drop_1pkt_whenold(struct Qdisc *sch, struct sjanz_priv *q,
    u64 now, u32 now1024, bool resizing)
{
	if (q->q[0].first)
		janz_drop_pkt(sch, q, now, now1024, 0, resizing);
	else if (likely(q->q[1].first))
		janz_drop_pkt(sch, q, now, now1024, 1, resizing);
	else if (likely(q->q[2].first))
		janz_drop_pkt(sch, q, now, now1024, 2, resizing);
}

static inline void
janz_drop_1pkt_overlen(struct Qdisc *sch, struct janz_priv *q,
    u64 now, u32 now1024, bool resizing)
{
	if (q->q[2].first)
		janz_drop_pkt(sch, q, now, now1024, 2, resizing);
	else if (q->q[1].first)
		janz_drop_pkt(sch, q, now, now1024, 1, resizing);
	else if (q->q[0].first)
		janz_drop_pkt(sch, q, now, now1024, 0, resizing);
}

static inline void
janz_drop_overlen(struct Qdisc *sch, struct mjanz_priv *q, u64 now, u32 now1024,
    bool isenq)
{
	goto into_the_loop;
	do {
		if (++(q->uecur) == q->uenum)
			q->uecur = 0;
 into_the_loop:
		janz_drop_1pkt_overlen(sch, &q->subqueues[q->uecur],
		    now, now1024, !isenq);
	} while (unlikely(sch->q.qlen > sch->limit));
}

static inline bool
janz_qheadolder(struct sjanz_priv *q, u32 ots, int qid)
{
	struct janz_skb *cb;

	if (unlikely(!q->q[qid].first))
		return (false);
	cb = get_janz_skb(q->q[qid].first);
	return ((unlikely(cmp1024(cb->ts_arrive, ots) < 0)) ? true : false);
}

static inline void
janz_dropchk(struct Qdisc *sch, struct sjanz_priv *q, u64 now, u32 now1024)
{
	u32 ots;
	int qid;

	if (now < q->drop_next)
		return;

	/* drop one packet if one or more packets are older than 100 ms */
	ots = ns_to_t1024(now - nsmul(100, NSEC_PER_MSEC));
	if (janz_qheadolder(q, ots, 0) ||
	    janz_qheadolder(q, ots, 1) ||
	    janz_qheadolder(q, ots, 2))
		janz_drop_1pkt_whenold(sch, q, now, now1024, false);

	/* drop all packets older than 500 ms */
	ots = ns_to_t1024(now - nsmul(500, NSEC_PER_MSEC));
	for (qid = 0; qid <= 2; ++qid)
		while (janz_qheadolder(q, ots, qid))
			janz_drop_pkt(sch, q, now, now1024, qid, false);

	q->drop_next += DROPCHK_INTERVAL;
	now = ktime_get_ns();
	if (q->drop_next < now)
		q->drop_next = now + DROPCHK_INTERVAL;
}

static inline void
janz_sendoff(struct Qdisc *sch, struct sjanz_priv *q, struct sk_buff *skb,
    int qid)
{
	u64 qdelay;
	u64 now = ktime_get_ns();
	struct janz_skb *cb = get_janz_skb(skb);
	u16 chance;

	qdelay = t1024_to_ns((u32)cmp1024(ns_to_t1024(now), cb->ts_arrive));

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
			cb->record_flag |= TC_JANZ_RELAY_SOJOURN_MARK;
			if (INET_ECN_set_ce(skb))
				cb->record_flag |= (u8)INET_ECN_CE << 3;
		}
	}
	janz_record_packet(q, skb, cb, now, ns_to_t1024(qdelay), chance, qid);
}

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
janz_analyse(struct Qdisc *sch, struct mjanz_priv *q,
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
		fe->ts = cb->ts_begin;
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

//TODO: janz_enq

//TODO: janz_deq inlining janz_getnext

static struct sk_buff *
janz_peek(struct Qdisc *sch)
{
	net_warn_ratelimited("sch_multijens: .peek called... why exactly?\n");
	return (NULL);
}

static inline void
janz_reset(struct Qdisc *sch)
{
	u32 ue;
	struct mjanz_priv *q = qdisc_priv(sch);

	ASSERT_RTNL();
	if (sch->q.qlen) {
		for (ue = 0; ue < q->uenum; ++ue) {
			rtnl_kfree_skbs(q->subqueues[ue].q[0].first,
			    q->subqueues[ue].q[0].last);
			rtnl_kfree_skbs(q->subqueues[ue].q[1].first,
			    q->subqueues[ue].q[1].last);
			rtnl_kfree_skbs(q->subqueues[ue].q[2].first,
			    q->subqueues[ue].q[2].last);
		}
		sch->q.qlen = 0;
	}
	for (ue = 0; ue < q->uenum; ++ue) {
		q->subqueues[ue].q[0].first = NULL;
		q->subqueues[ue].q[0].last = NULL;
		q->subqueues[ue].q[1].first = NULL;
		q->subqueues[ue].q[1].last = NULL;
		q->subqueues[ue].q[2].first = NULL;
		q->subqueues[ue].q[2].last = NULL;
		q->subqueues[ue].memusage = 0;
		q->subqueues[ue].notbefore = 0;
		q->subqueues[ue].crediting = 0;
		if (q->subqueues[ue].record_chan)
			relay_flush(q->subqueues[ue].record_chan);
	}
	sch->qstats.backlog = 0;
	sch->qstats.overlimits = 0;
}

static const struct nla_policy janz_nla_policy[TCA_JANZ_MAX + 1] = {
	[TCA_JANZ_LIMIT]	= { .type = NLA_U32 },
	[TCA_JANZ_RATE64]	= { .type = NLA_U64 },
	[TCA_JANZ_HANDOVER]	= { .type = NLA_U32 },
	[TCA_JANZ_QOSMODE]	= { .type = NLA_U32 },
	[TCA_JANZ_MARKFREE]	= { .type = NLA_U32 },
	[TCA_JANZ_MARKFULL]	= { .type = NLA_U32 },
	[TCA_JANZ_SUBBUFS]	= { .type = NLA_U32 },
	[TCA_JANZ_FRAGCACHE]	= { .type = NLA_U32 },
	[TCA_JANZ_XLATENCY]	= { .type = NLA_U32 },
	[TCA_MULTIJENS_UENUM]	= { .type = NLA_U32 },
};

static inline int
janz_chg(struct Qdisc *sch, struct nlattr *opt, struct netlink_ext_ack *extack)
{
	u32 ue;
	struct mjanz_priv *q = qdisc_priv(sch);
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
		if (tb[TCA_JANZ_SUBBUFS] || tb[TCA_JANZ_FRAGCACHE] ||
		    tb[TCA_MULTIJENS_UENUM])
			return (-EINVAL);
	} else {
		/* this is load time */
		if (!(tb[TCA_MULTIJENS_UENUM]))
			return (-EINVAL);
		/* allocate sch_janz subqueues */
		q->uenum = nla_get_u32(tb[TCA_MULTIJENS_UENUM]);
		/* range-check uenum; the “arbitrary” max also protects fragcache_num */
		if (q->uenum < 1U ||
		    ((SIZE_MAX / sizeof(struct janz_ctlfile_pkt)) >= (size_t)q->uenum) ||
		    (((SIZE_MAX - sizeof(struct janz_gwq_ovl)) / sizeof(struct rchan *)) >= (size_t)q->uenum) ||
		    q->uenum > /* arbitrary */ 65535U) {
			/* nothing has been allocated yet */
			q->uenum = 0;
			/* out of bounds */
			return (-EDOM);
		}
		q->subqueues = kvcalloc(q->uenum,
		    sizeof(struct sjanz_priv), GFP_KERNEL);
		q->ctldata = kvcalloc(q->uenum,
		    sizeof(struct janz_ctlfile_pkt), GFP_KERNEL);
		if (!q->subqueues || !q->ctldata) {
			if (q->subqueues)
				kvfree(q->subqueues);
			if (q->ctldata)
				kvfree(q->ctldata)
			q->uenum = 0;
			return (-ENOMEM);
		}
		/* from here on, q->uenum holds good */
		for (ue = 0; ue < q->uenum; ++ue) {
			/* per-UE stuff from sch_janz janz_init() */
			atomic64_set_release(&(q->subqueues[ue].ns_pro_byte),
			    /* 10 Mbit/s */ 800);
			q->subqueues[ue].lastknownrate = 800; /* same as above */
			q->subqueues[ue].markfree = nsmul(4, NSEC_PER_MSEC);
			q->subqueues[ue].markfull = nsmul(14, NSEC_PER_MSEC);
			q->subqueues[ue].xlatency = 0;
			q->subqueues[ue].qosmode = 0;
			/* needed so janz_reset DTRT */
			q->subqueues[ue].record_chan = NULL;
			q->subqueues[ue].ctlfile = NULL;
		}
		janz_reset(sch);
	}

	/* now actual configuring */
	sch_tree_lock(sch);
	/* no memory allocation, returns, etc. now */

	if (tb[TCA_JANZ_LIMIT])
		sch->limit = nla_get_u32(tb[TCA_JANZ_LIMIT]) ? : 1;

	if (tb[TCA_JANZ_RATE64]) {
		u64 tmp = nla_get_u64(tb[TCA_JANZ_RATE64]);
		u64 old;

		tmp = div64_u64(NSEC_PER_SEC, tmp);
		if (tmp < 1)
			tmp = 1;
		rate_changed = 0;
		for (ue = 0; ue < q->uenum; ++ue) {
			old = (u64)atomic64_read_acquire(&(q->subqueues[ue].ns_pro_byte));
			atomic64_set_release(&(q->subqueues[ue].ns_pro_byte), (s64)tmp);
			rate_changed |= old != tmp;
		}
	}

	if (tb[TCA_JANZ_HANDOVER]) {
		u64 tmp = nla_get_u32(tb[TCA_JANZ_HANDOVER]);

		handover_started = tmp != 0;
		tmp *= NSEC_PER_USEC;
		tmp += ktime_get_ns();
		/* implementation of handover */
		for (ue = 0; ue < q->uenum; ++ue) {
			q->subqueues[ue].notbefore =
			    tmp < q->subqueues[ue].notbefore ?
			    q->subqueues[ue].notbefore : tmp;
			q->subqueues[ue].crediting = 0;
		}
	}

	if (tb[TCA_JANZ_QOSMODE])
		for (ue = 0; ue < q->uenum; ++ue)
			q->subqueues[ue].qosmode = nla_get_u32(tb[TCA_JANZ_QOSMODE]);

	if (tb[TCA_JANZ_MARKFREE])
		for (ue = 0; ue < q->uenum; ++ue)
			q->subqueues[ue].markfree = us_to_ns(nla_get_u32(tb[TCA_JANZ_MARKFREE]));

	if (tb[TCA_JANZ_MARKFULL])
		for (ue = 0; ue < q->uenum; ++ue)
			q->subqueues[ue].markfull = us_to_ns(nla_get_u32(tb[TCA_JANZ_MARKFULL]));

	if (tb[TCA_JANZ_SUBBUFS])
		/* only at load time */
		q->nsubbufs = nla_get_u32(tb[TCA_JANZ_SUBBUFS]);

	if (tb[TCA_JANZ_FRAGCACHE])
		/* only at load time */
		q->fragcache_num = nla_get_u32(tb[TCA_JANZ_FRAGCACHE]);

	if (tb[TCA_JANZ_XLATENCY])
		for (ue = 0; ue < q->uenum; ++ue)
			q->subqueues[ue].xlatency = us_to_ns(nla_get_u32(tb[TCA_JANZ_XLATENCY]));

	/* assert: sch->q.qlen == 0 || q->record_chan != nil */
	/* assert: sch->limit > 0 */
	if (unlikely(sch->q.qlen > sch->limit)) {
		u64 now = ktime_get_ns();

		janz_drop_overlen(sch, q, now, ns_to_t1024(now), false);
	}

	if (q->subqueues[0].record_chan) for (ue = 0; ue < q->uenum; ++ue) {
		/* report if rate changes or a handover starts */
		if (rate_changed || handover_started)
			janz_record_queuesz(sch, &q->subqueues[ue], ktime_get_ns(), 0, 1);
		/* flush subbufs before handover */
		if (handover_started)
			relay_flush(q->subqueues[ue].record_chan);
	}

	sch_tree_unlock(sch);
	return (0);
}

static struct dentry *janz_debugfs_main __read_mostly;

static /*const*/ struct rchan_callbacks janz_debugfs_relay_hooks = {
	.create_buf_file = janz_debugfs_create,
	.remove_buf_file = janz_debugfs_destroy,
	.subbuf_start = janz_subbuf_init,
};

static const struct file_operations janz_ctlfile_fops = {
	.open = simple_open,
	.write = janz_ctlfile_write,
	.llseek = no_llseek,
};

static int
janz_init(struct Qdisc *sch, struct nlattr *opt, struct netlink_ext_ack *extack)
{
	struct mjanz_priv *q = qdisc_priv(sch);
	int err;
	char name[21];
	u64 now;
	u32 ue;
	int i;

	/* config values’ defaults */
	sch->limit = 10240;
	q->nsubbufs = 0;
	q->fragcache_num = 0;
	/* qdisc state */
	sch->q.qlen = 0;
	q->uenum = 0;
	qdisc_watchdog_init_clockid(&q->watchdog, sch, CLOCK_MONOTONIC);

	if ((err = janz_chg(sch, opt, extack)))
		goto init_fail;

	if (q->nsubbufs < 4U || q->nsubbufs > 0x000FFFFFU)
		q->nsubbufs = 1024;

	if (q->fragcache_num < 16U || q->fragcache_num > 0x00FFFFFFU)
		q->fragcache_num = 1024;

	for (ue = 0; ue < q->uenum; ++ue) {
		snprintf(name, sizeof(name), "%04X-%02X:", sch->handle >> 16, ue);
		q->subqueues[ue].record_chan = relay_open(name, janz_debugfs_main,
		    TC_JANZ_RELAY_SUBBUFSZ, q->nsubbufs,
		    &janz_debugfs_relay_hooks, sch);
		if (!q->subqueues[ue].record_chan) {
			printk(KERN_WARNING "sch_janz: relay channel creation failed\n");
			err = -ENOENT;
			goto init_fail;
		}
		spin_lock_init(&q->subqueues[ue].record_lock);
	}

	snprintf(name, sizeof(name), "%04X:v" __stringify(JANZ_CTLFILE_VERSION),
	    sch->handle >> 16);
	q->ctlfile = debugfs_create_file(name, 0200, janz_debugfs_main,
	    q, &janz_ctlfile_fops);
	if (IS_ERR_OR_NULL(q->ctlfile)) {
		err = q->ctlfile ? PTR_ERR(q->ctlfile) : -ENOENT;
		q->ctlfile = NULL;
		printk(KERN_WARNING "sch_janz: control channel creation failed\n");
		goto init_fail;
	}
	d_inode(q->ctlfile)->i_size = sizeof(struct janz_ctlfile_pkt) * (size_t)q->uenum;

	/* raise q->fragcache_base memory size until we can fit janz_gwq_* */
	while (((size_t)q->fragcache_num * sizeof(struct janz_fragcache)) <
	    (sizeof(struct janz_gwq_ovl) + (size_t)q->uenum * sizeof(struct rchan *)))
		++q->fragcache_num;
	/* allocate q->fragcache_base memory */
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

	now = ktime_get_ns();
	for (ue = 0; ue < q->uenum; ++ue) {
		q->qsz_next = now + QSZ_INTERVAL;
		q->drop_next = now + DROPCHK_INTERVAL;
	}

	sch->flags &= ~TCQ_F_CAN_BYPASS;
	return (0);

 init_fail:
	if (q->ctlfile) {
		debugfs_remove(q->ctlfile);
		q->ctlfile = NULL;
	}
	if (q->uenum && q->subqueues[0].record_chan)
		for (ue = 0; ue < q->uenum; ++ue)
			if (q->subqueues[ue].record_chan) {
				relay_close(q->subqueues[ue].record_chan);
				q->subqueues[ue].record_chan = NULL;
			}
	if (q->uenum) {
		kvfree(q->subqueues);
		kvfree(q->ctldata)
		q->uenum = 0;
	}
	return (err);
}

/* workaround to relay_close late using the global workqueue */

static void
janz_gwq_fn(struct work_struct *work)
{
	u32 ue;
	struct janz_gwq_ovl *ovl = container_of(to_delayed_work(work),
	    struct janz_gwq_ovl, dwork);

	for (ue = 0; ue < ovl->uenum; ++ue)
		relay_close(ovl->record_chan[ue]);
	kvfree(ovl);
}

//TODO: janz_done

static int
janz_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct mjanz_priv *q = qdisc_priv(sch);
	struct nlattr *opts;
	u64 rate;

	opts = nla_nest_start(skb, TCA_OPTIONS);
	if (opts == NULL)
		goto nla_put_failure;

	rate = (u64)atomic64_read_acquire(&(q->subqueues[0].ns_pro_byte));
	if (nla_put_u64_64bit(skb, TCA_JANZ_RATE64,
	      div64_u64(NSEC_PER_SEC, rate), TCA_JANZ_PAD64) ||
	    nla_put_u32(skb, TCA_JANZ_QOSMODE, q->subqueues[0].qosmode) ||
	    nla_put_u32(skb, TCA_JANZ_MARKFREE, ns_to_us(q->subqueues[0].markfree)) ||
	    nla_put_u32(skb, TCA_JANZ_MARKFULL, ns_to_us(q->subqueues[0].markfull)) ||
	    nla_put_u32(skb, TCA_JANZ_SUBBUFS, q->nsubbufs) ||
	    nla_put_u32(skb, TCA_JANZ_FRAGCACHE, q->fragcache_num) ||
	    nla_put_u32(skb, TCA_JANZ_XLATENCY, ns_to_us(q->subqueues[0].xlatency)) ||
	    nla_put_u32(skb, TCA_MULTIJENS_UENUM, q->uenum) ||
	    nla_put_u32(skb, TCA_JANZ_LIMIT, sch->limit))
		goto nla_put_failure;

	return (nla_nest_end(skb, opts));

 nla_put_failure:
	return (-1);
}

static struct Qdisc_ops janz_ops __read_mostly = {
	.id		= "multijens",
	.priv_size	= sizeof(struct mjanz_priv),
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
MODULE_DESCRIPTION("bespoke egress traffic scheduler for the JENS network simulator, multiple UE simulation");
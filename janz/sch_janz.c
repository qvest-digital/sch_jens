/*
 * Dǟ janz zesammene Kwejü-Disk
 *
 * Copyright © 2022, 2023 mirabilos <t.glaser@tarent.de>
 * Licensor: Deutsche Telekom LLCTO
 *
 * This module for the Linux kernel is published under the GPLv2.
 */

#undef JANZ_IP_DECODER_DEBUG
#if 1
#define JANZ_IP_DECODER_DEBUG(fmt,...)	do { /* nothing */ } while (0)
#else
#define JANZ_IP_DECODER_DEBUG(fmt,...)	printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#endif

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

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
#include "gru32b.h"

/* constant must fit 32 bits; 2'000'000'000 will do */
#define MAXXLATENCY nsmul(2, NSEC_PER_SEC)

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
	int maxxlatency_ok[(MAXXLATENCY <= 0xFFFFFFFFULL) ? 1 : -1];
};

struct janz_skbfifo {
	struct sk_buff *first;
	struct sk_buff *last;
};

/* struct janz_priv *q = qdisc_priv(sch); */
struct janz_priv {
	struct janz_skbfifo q[3];	/* TOS FIFOs */					//@cacheline
	struct rchan *record_chan;	/* relay to userspace */			//@16
#define QSZ_INTERVAL nsmul(500, NSEC_PER_MSEC)
	u64 qsz_next;			/* next time to emit queue-size */		//@  +8
#define DROPCHK_INTERVAL nsmul(200, NSEC_PER_MSEC)
	u64 drop_next;			/* next time to check drops */			//@16
	u64 notbefore;			/* ktime_get_ns() to send next, or 0 */		//@  +8
	atomic64_t ns_pro_byte;		/* traffic shaping tgt bandwidth */		//@16
	u64 markfree;									//@  +8
	u64 markfull;									//@16
	struct janz_fragcache *fragcache_used;						//@  +8
	struct janz_fragcache *fragcache_last; /* last used element */			//@16
	struct janz_fragcache *fragcache_free;						//@  +8
	struct janz_fragcache *fragcache_base;						//@16
	u32 fragcache_aged;								//@  +8
	u32 fragcache_num;								//@  +12
	u32 nsubbufs;									//@16
	u32 memusage;			/* enqueued packet truesize */			//@  +4
	struct dentry *ctlfile;								//@  +8
	u64 lastknownrate;								//@16
	struct qdisc_watchdog watchdog;	/* to schedule when traffic shaping */		//@  +8
	spinlock_t record_lock;		/* for record_chan */				//@?
	u8 crediting;
	u8 qosmode;
#ifdef SCH_JANZDBG
	u8 wdogreason;			/* 10=notbefore 20=nothingtosend */
	u16 wdogearly;
	u64 wdogtimers[4];		/* <50us <1000us <4000us >=4ms */
	u64 wdognext;
#endif
	u32 xlatency;			/* extra artificial pre-enqueue latency */	//@ 4
};

/* struct janz_skb *cb = get_janz_skb(skb); */
struct janz_skb {
	/* limited to QDISC_CB_PRIV_LEN (20) bytes! */
	u32 ts_begin;			/* real enqueue ts1024 */		//@8   :4
	union {									//  +4 :4
		struct {		/* up to and including janz_drop_pkt/janz_sendoff */
			u32 pktxlatency;	/* ts_begin adjustment */	//@ +4 :4
		};
		struct {		/* past these, just before janz_record_packet */
			u16 chance;		/* janz_sendoff / 0 */		//@ +4 :2
			short qid;		/* -1/0/1/2 */			//@ +6 :2
		};
	};									//… +4 :4
	unsigned int truesz;		/* memory usage */			//@8   :4
	u16 srcport;								//@ +4 :2
	u16 dstport;								//@ +6 :2
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
	struct janz_priv *q = filp->private_data;
	struct janz_ctlfile_pkt data;

	if (count != sizeof(data))
		return (-EINVAL);
	if (copy_from_user(&data, buf, sizeof(data)))
		return (-EFAULT);

	newrate = div64_u64(8ULL * NSEC_PER_SEC, data.bits_per_second);
	if (newrate < 1)
		newrate = 1;
	atomic64_set_release(&(q->ns_pro_byte), (s64)newrate);

	return (sizeof(data));
}

static inline void
janz_record_write(struct tc_janz_relay *record, struct janz_priv *q)
{
	unsigned long flags;	/* used by spinlock macros */

	spin_lock_irqsave(&q->record_lock, flags);
	__relay_write(q->record_chan, record, sizeof(struct tc_janz_relay));
	spin_unlock_irqrestore(&q->record_lock, flags);
}

static inline void
janz_record_queuesz(struct Qdisc *sch, struct janz_priv *q, u64 now,
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
	r.x64[0] = max(div64_u64(8ULL * NSEC_PER_SEC, rate), 1ULL);
	r.x64[1] = (u64)ktime_to_ns(ktime_mono_to_real(ns_to_ktime(now))) - now;
	janz_record_write(&r, q);

	/* use of ktime_get_ns() is deliberate */
	q->qsz_next = ktime_get_ns() + QSZ_INTERVAL;
}

#ifdef SCH_JANZDBG
static inline void
janz_record_wdog(struct janz_priv *q, u64 now)
{
	struct tc_janz_relay r = {0};

	r.ts = now;
	r.type = TC_JANZ_RELAY_WDOGDBG;
	if (q->wdogreason != 0) {
		u64 delay;

		r.f8 = q->wdogreason;
		q->wdogreason = 0;
		if (q->wdognext > now) {
			r.f8 |= 2;
			delay = q->wdognext - now;
			++q->wdogearly;
		} else {
			r.f8 |= 1;
			delay = now - q->wdognext;
			++q->wdogtimers[ \
			    delay < us_to_ns(50U) ? 0 : \
			    delay < us_to_ns(1000U) ? 1 : \
			    delay < us_to_ns(4000U) ? 2 : 3];
		}
		if (delay > 0xFFFFFFFFUL)
			delay = 0xFFFFFFFFUL;
		r.d32 = (u32)delay;
	}
	r.e16 = q->wdogearly;
	r.x64[0] = q->wdogtimers[0];
	r.x64[1] = q->wdogtimers[1];
	r.y64[0] = q->wdogtimers[2];
	r.y64[1] = q->wdogtimers[3];
	janz_record_write(&r, q);
}
#endif

static inline void
janz_record_packet(struct janz_priv *q,
    struct sk_buff *skb, struct janz_skb *cb, u32 qdelay1024, u64 now)
{
	struct tc_janz_relay r = {0};

	r.ts = now;
	r.type = TC_JANZ_RELAY_SOJOURN;
	r.d32 = qdelay1024;
	r.e16 = cb->chance;
	r.f8 = cb->record_flag;
	r.z.zSOJOURN.psize = ((u32)(cb->qid + 1)) << 30 |
	    (qdisc_pkt_len(skb) & 0x3FFFFFFFU);
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
janz_fragcache_maint(struct janz_priv *q, u64 now)
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
janz_drop_pkt(struct Qdisc *sch, struct janz_priv *q, u64 now, u32 now1024,
    int qid, bool resizing)
{
	struct sk_buff *skb;
	struct janz_skb *cb;
	u32 qd1024, ts_arrive;

	skb = q->q[qid].first;
	if (!(q->q[qid].first = skb->next))
		q->q[qid].last = NULL;
	--sch->q.qlen;
	cb = get_janz_skb(skb);
	q->memusage -= cb->truesz;
	qdisc_qstats_backlog_dec(sch, skb);
	cb->record_flag |= TC_JANZ_RELAY_SOJOURN_DROP;
	ts_arrive = cb->ts_begin + ns_to_t1024(cb->pktxlatency);
	if (resizing)
		qd1024 = 0xFFFFFFFFUL;
	else if (unlikely(cmp1024(ts_arrive, now1024) > 0))
		qd1024 = 0xFFFFFFFEUL;
	else if (unlikely((qd1024 = now1024 - ts_arrive) > 0xFFFFFFFDUL))
		qd1024 = 0xFFFFFFFDUL;
	/* these both overlay cb->pktxlatency, do not move up */
	cb->chance = 0;
	cb->qid = qid;
	janz_record_packet(q, skb, cb, qd1024, now);
	/* inefficient for large reduction in sch->limit (resizing = true) */
	/* but we assume this doesn’t happen often, if at all */
	kfree_skb(skb);
}

static inline void
janz_drop_1pkt_whenold(struct Qdisc *sch, struct janz_priv *q,
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
	else if (likely(q->q[0].first))
		janz_drop_pkt(sch, q, now, now1024, 0, resizing);
}

static inline void
janz_drop_overlen(struct Qdisc *sch, struct janz_priv *q, u64 now, u32 now1024,
    bool isenq)
{
	do {
		janz_drop_1pkt_overlen(sch, q, now, now1024, !isenq);
	} while (unlikely(sch->q.qlen > sch->limit));
}

static inline bool
janz_qheadolder(struct janz_priv *q, u64 ots, int qid)
{
	struct janz_skb *cb;
	u64 ts_arrive;

	if (unlikely(!q->q[qid].first))
		return (false);
	cb = get_janz_skb(q->q[qid].first);
	ts_arrive = t1024_to_ns(cb->ts_begin) + cb->pktxlatency;
	return ((unlikely(ts_arrive < ots)) ? true : false);
}

static inline void
janz_dropchk(struct Qdisc *sch, struct janz_priv *q, u64 now, u32 now1024)
{
	u64 ots;
	int qid;

	if (now < q->drop_next)
		return;

	/* drop one packet if one or more packets are older than 100 ms */
	ots = now - nsmul(100, NSEC_PER_MSEC);
	if (janz_qheadolder(q, ots, 0) ||
	    janz_qheadolder(q, ots, 1) ||
	    janz_qheadolder(q, ots, 2))
		janz_drop_1pkt_whenold(sch, q, now, now1024, false);

	/* drop all packets older than 500 ms */
	ots = now - nsmul(500, NSEC_PER_MSEC);
	for (qid = 0; qid <= 2; ++qid)
		while (janz_qheadolder(q, ots, qid))
			janz_drop_pkt(sch, q, now, now1024, qid, false);

	q->drop_next += DROPCHK_INTERVAL;
	now = ktime_get_ns();
	if (q->drop_next < now)
		q->drop_next = now + DROPCHK_INTERVAL;
}

static inline struct sk_buff *
janz_sendoff(struct Qdisc *sch, struct janz_priv *q, struct sk_buff *skb,
    struct janz_skb *cb, u64 now, u32 now1024, int qid)
{
	u64 qdelay;
	u16 chance;

	u32 ts_arrive = cb->ts_begin + ns_to_t1024(cb->pktxlatency); //XXX
	qdelay = t1024_to_ns((u32)cmp1024(now1024, ts_arrive));

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
		if (get_random_u32_below(tmax) < t) {
 domark:
			cb->record_flag |= TC_JANZ_RELAY_SOJOURN_MARK;
			if (INET_ECN_set_ce(skb))
				cb->record_flag |= (u8)INET_ECN_CE << 3;
		}
	}
	cb->chance = chance;
	cb->qid = qid;
	janz_record_packet(q, skb, cb, ns_to_t1024(qdelay), now);
	return (skb);
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

	/* addresses */
	switch (skb->protocol) {
	case htons(ETH_P_IP):
		ih4 = ip_hdr(skb);
		hdrp = (void *)ih4;
		if ((hdrp + sizeof(struct iphdr)) > endoflineardata) {
			JANZ_IP_DECODER_DEBUG("IPv4 too short\n");
			return;
		}
		JANZ_IP_DECODER_DEBUG("IPv4 %08X->%08X proto %u frag %d\n",
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
			JANZ_IP_DECODER_DEBUG("IPv6 too short\n");
			return;
		}
		JANZ_IP_DECODER_DEBUG("IPv6 %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X->%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X nexthdr %u\n",
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
		JANZ_IP_DECODER_DEBUG("ARP packet\n");
		cb->tosbyte = 0x10;	/* interactive/lodelay */
		return;
	case htons(ETH_P_RARP):
		JANZ_IP_DECODER_DEBUG("RARP packet\n");
		cb->tosbyte = 0x10;
		return;
	case htons(ETH_P_PPP_DISC):
		JANZ_IP_DECODER_DEBUG("PPPoE discovery packet\n");
		cb->tosbyte = 0x10;
		return;
	case htons(ETH_P_LOOP):
	case htons(ETH_P_LOOPBACK):
		JANZ_IP_DECODER_DEBUG("ethernet loopback packet\n");
		cb->tosbyte = 0x08;	/* bulk */
		return;
	default:
		JANZ_IP_DECODER_DEBUG("unknown proto htons(0x%04X)\n", (unsigned)ntohs(skb->protocol));
		return;
	}
	/* we end here only if the packet is IPv4 or IPv6 */

 try_nexthdr:
	switch (cb->nexthdr) {
	case 6:		/* TCP */
	case 17:	/* UDP */
		/* both begin with src and dst ports in this order */
		if ((hdrp + 4) > endoflineardata) {
			JANZ_IP_DECODER_DEBUG("%u too short\n", cb->nexthdr);
			goto no_ports;
		}
		cb->srcport = ((unsigned int)hdrp[0] << 8) | hdrp[1];
		cb->dstport = ((unsigned int)hdrp[2] << 8) | hdrp[3];
		break;
	case 0:		/* IPv6 hop-by-hop options */
	case 43:	/* IPv6 routing */
	case 60:	/* IPv6 destination options */
		if ((hdrp + 4) > endoflineardata) {
			JANZ_IP_DECODER_DEBUG("%u too short\n", cb->nexthdr);
			goto no_ports;
		}
		cb->nexthdr = hdrp[0];
		hdrp += ((unsigned int)hdrp[1] + 1U) * 8U;
		goto try_nexthdr;
	case 44:	/* IPv6 fragment */
		if ((hdrp + 8) > endoflineardata) {
			JANZ_IP_DECODER_DEBUG("%u too short\n", cb->nexthdr);
			goto no_ports;
		}
		if (fragoff != -1) {
			JANZ_IP_DECODER_DEBUG("two fragment headers\n");
			goto no_ports;
		}
		if (cb->ipver != 6) {
			JANZ_IP_DECODER_DEBUG("IPv6 fragment header in %d packet\n", cb->ipver);
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
		JANZ_IP_DECODER_DEBUG("frag, ofs %u, nexthdr %u\n", fragoff, hdrp[0]);
		if (fragoff) {
			/* nope */
			goto higher_fragment;
		}
		cb->nexthdr = hdrp[0];
		hdrp += 8;
		goto try_nexthdr;
	case 51:	/* IPsec AH */
		if ((hdrp + 4) > endoflineardata) {
			JANZ_IP_DECODER_DEBUG("%u too short\n", cb->nexthdr);
			goto no_ports;
		}
		cb->nexthdr = hdrp[0];
		hdrp += ((unsigned int)hdrp[1] + 2U) * 4U;
		goto try_nexthdr;
	case 135:	/* Mobile IP */
	case 139:	/* Host Identity Protocol v2 */
	case 140:	/* SHIM6: Site Multihoming by IPv6 Intermediation */
		if ((hdrp + 4) > endoflineardata) {
			JANZ_IP_DECODER_DEBUG("%u too short\n", cb->nexthdr);
			goto done_addresses;
		}
		/* this kind of extension header has no payload normally */
		if (hdrp[0] == 59)
			goto done_addresses;
		cb->nexthdr = hdrp[0];
		hdrp += ((unsigned int)hdrp[1] + 1U) * 8U;
		goto try_nexthdr;
	default:	/* any other L4 protocol, unknown extension headers */
		JANZ_IP_DECODER_DEBUG("unknown exthdr %u\n", cb->nexthdr);
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
			net_warn_ratelimited("no free fragment cache, please raise count\n");
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

static int
janz_enq(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free)
{
	struct janz_priv *q = qdisc_priv(sch);
	struct janz_skb *cb = get_janz_skb(skb);
	u8 qid;
	u32 prev_backlog = sch->qstats.backlog;
	bool overlimit;
	u64 now;
	u32 now1024;

	now = ktime_get_ns();
	now1024 = ns_to_t1024(now);
	janz_dropchk(sch, q, now, now1024);

	/* initialise values in cb */
	cb->ts_begin = now1024;
	cb->pktxlatency = q->xlatency;
	cb->truesz = skb->truesize;
	/* init values from before analysis */
	cb->srcport = 0;
	cb->dstport = 0;
	cb->tosbyte = 0;
	cb->ipver = 0;
	cb->nexthdr = 0;
	cb->record_flag = 0;
	/* note ↑ struct order */

	/* analyse skb determining tosbyte etc. */
	janz_analyse(sch, q, skb, cb, now);

	switch (q->qosmode) {
	case 0:
	default:
		qid = 1;
		if (cb->tosbyte & 0x10)
			--qid;
		if (cb->tosbyte & 0x08)
			++qid;
		break;
	case 1:
		// IPv{4,6} traffic is not categorised
		qid = 1;
		if (skb->protocol != htons(ETH_P_IP) &&
		    skb->protocol != htons(ETH_P_IPV6)) {
			if (cb->tosbyte & 0x10)
				--qid;
			if (cb->tosbyte & 0x08)
				++qid;
		}
		break;
	case 2:
		// IPv{4,6} traffic is categorised by ECT(1) or else only
		qid = 1;
		if (skb->protocol != htons(ETH_P_IP) &&
		    skb->protocol != htons(ETH_P_IPV6)) {
			if (cb->tosbyte & 0x10)
				--qid;
			if (cb->tosbyte & 0x08)
				++qid;
		} else {
			if ((cb->record_flag & INET_ECN_MASK) == INET_ECN_ECT_1)
				--qid;
		}
		break;
	}

	// assumption is 1 packet is passed
	if (WARN(skb->next != NULL, "janz_enq passed multiple packets?"))
		skb->next = NULL;

	q->memusage += cb->truesz;
	if (unlikely(overlimit = (++sch->q.qlen > sch->limit)))
		janz_drop_overlen(sch, q, now, now1024, true);
	if (!q->q[qid].first) {
		q->q[qid].first = skb;
		q->q[qid].last = skb;
	} else {
		q->q[qid].last->next = skb;
		q->q[qid].last = skb;
	}
	qdisc_qstats_backlog_inc(sch, skb);

	if (now >= q->qsz_next)
		janz_record_queuesz(sch, q, now, 0, 0);

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
	u64 now, rate = 0;
	struct janz_skb *cb;
	int qid;
	u32 now1024, rs;
	s32 drs;

	qid = -1;
	now = ktime_get_ns();
	now1024 = ns_to_t1024(now);
#ifdef SCH_JANZDBG
	janz_record_wdog(q, now);
#endif
	rs = (u32)~(u32)0U;
	janz_dropchk(sch, q, now, now1024);

	if (now < q->notbefore) {
		register u64 nextns;

		nextns = min(q->notbefore, q->drop_next);
#ifdef SCH_JANZDBG
		q->wdogreason = 0x10;
		q->wdognext = nextns;
#endif
		qdisc_watchdog_schedule_ns(&q->watchdog, nextns);
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
		u32 ts_arrive; /*XXX*/					\
		cb = get_janz_skb(skb);					\
		ts_arrive = cb->ts_begin + ns_to_t1024(cb->pktxlatency); /*XXX*/ \
		drs = cmp1024(ts_arrive, now1024);			\
		if (drs <= 0)						\
			goto got_skb;					\
		/* ts_arrive > now: packet has not reached us yet */	\
		if (/* > 0 */ (u32)drs < rs)				\
			rs = (u32)drs;					\
	}								\
} while (/* CONSTCOND */ 0)

	try_qid(0);
	try_qid(1);
	try_qid(2);
	qid = -1;

	/* nothing to send, but we have to reschedule first */
	/* if we end up here, rs was set above */
	qdisc_watchdog_schedule_ns(&q->watchdog, now + t1024_to_ns(rs));
#ifdef SCH_JANZDBG
	q->wdognext = now + t1024_to_ns(rs);
	q->wdogreason = 0x20;
#endif
	goto nothing_to_send;

 got_skb:
	if (!(q->q[qid].first = skb->next))
		q->q[qid].last = NULL;
	--sch->q.qlen;
	q->memusage -= cb->truesz;
	skb->next = NULL;
	qdisc_qstats_backlog_dec(sch, skb);
	qdisc_bstats_update(sch, skb);

	rate = (u64)atomic64_read_acquire(&(q->ns_pro_byte));
	if (q->crediting) {
		u64 ts_arrive;

		ts_arrive = t1024_to_ns(cb->ts_begin) + cb->pktxlatency;
		q->notbefore = max(q->notbefore, ts_arrive) +
		    (rate * (u64)qdisc_pkt_len(skb));
	} else
		q->notbefore = now + (rate * (u64)qdisc_pkt_len(skb));
	q->crediting = 1;
	if (rate != q->lastknownrate)
		goto force_rate_and_out;

 out:
	if (now >= q->qsz_next) {
 force_rate_and_out:
		janz_record_queuesz(sch, q, now, rate, 0);
		++now;
	}

	if (!skb)
		return (NULL);
	return (janz_sendoff(sch, q, skb, cb, now, now1024, qid));
}

static struct sk_buff *
janz_peek(struct Qdisc *sch)
{
	struct janz_priv *q = qdisc_priv(sch);

	pr_warn(".peek called; this is not supported!\n");
	dump_stack();
	/* delay traffic noticeably, so the user knows to look */
	q->notbefore = ktime_get_ns() + NSEC_PER_SEC;
	q->crediting = 0;
	/* hard reply no packet to now send */
	return (NULL);
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
#ifdef SCH_JANZDBG
	q->wdogreason = 0;
	q->wdogearly = 0;
	q->wdogtimers[0] = 0;
	q->wdogtimers[1] = 0;
	q->wdogtimers[2] = 0;
	q->wdogtimers[3] = 0;
	q->wdognext = 0;
#endif
	if (q->record_chan)
		relay_flush(q->record_chan);
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
};

static inline int
janz_chg(struct Qdisc *sch, struct nlattr *opt, struct netlink_ext_ack *extack)
{
	struct janz_priv *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_JANZ_MAX + 1];
	int err;
	bool handover_started = false;
	u32 newqosmode;
	u64 newxlatency;

	if (!opt)
		return (-EINVAL);

	if ((err = nla_parse_nested_deprecated(tb, TCA_JANZ_MAX, opt,
	    janz_nla_policy, extack)) < 0)
		return (err);

	/* anything that can throw first */

	if (tb[TCA_JANZ_QOSMODE]) {
		newqosmode = nla_get_u32(tb[TCA_JANZ_QOSMODE]);
		if (newqosmode > 2) {
			NL_SET_ERR_MSG_MOD(extack, "invalid qosmode");
			return (-EINVAL);
		}
	}

	if (tb[TCA_JANZ_XLATENCY]) {
		newxlatency = us_to_ns(nla_get_u32(tb[TCA_JANZ_XLATENCY]));
		if (newxlatency > MAXXLATENCY) {
			NL_SET_ERR_MSG_MOD(extack, "xlatency too large");
			return (-EINVAL);
		}
	}

	if (q->nsubbufs) {
		/* only at load time */
		if (tb[TCA_JANZ_SUBBUFS] || tb[TCA_JANZ_FRAGCACHE]) {
			NL_SET_ERR_MSG_MOD(extack, "subbufs and fragcache can only be set at initialisation");
			return (-EINVAL);
		}
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
		atomic64_set_release(&(q->ns_pro_byte), (s64)tmp);
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

	if (tb[TCA_JANZ_QOSMODE])
		q->qosmode = newqosmode;

	if (tb[TCA_JANZ_MARKFREE])
		q->markfree = us_to_ns(nla_get_u32(tb[TCA_JANZ_MARKFREE]));

	if (tb[TCA_JANZ_MARKFULL])
		q->markfull = us_to_ns(nla_get_u32(tb[TCA_JANZ_MARKFULL]));

	if (tb[TCA_JANZ_SUBBUFS])
		/* only at load time */
		q->nsubbufs = nla_get_u32(tb[TCA_JANZ_SUBBUFS]);

	if (tb[TCA_JANZ_FRAGCACHE])
		/* only at load time */
		q->fragcache_num = nla_get_u32(tb[TCA_JANZ_FRAGCACHE]);

	if (tb[TCA_JANZ_XLATENCY])
		q->xlatency = newxlatency;

	/* assert: sch->q.qlen == 0 || q->record_chan != nil */
	/* assert: sch->limit > 0 */
	if (unlikely(sch->q.qlen > sch->limit)) {
		u64 now = ktime_get_ns();

		janz_drop_overlen(sch, q, now, ns_to_t1024(now), false);
	}

	/* report if a handover starts */
	if (unlikely(handover_started) && likely(q->record_chan)) {
		u64 now = ktime_get_ns();

		janz_record_queuesz(sch, q, now, 0, 1);
		/* flush subbufs before handover */
		relay_flush(q->record_chan);
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
	struct janz_priv *q = qdisc_priv(sch);
	int err;
	char name[12];
	u64 now;
	int i;

	/* config values’ defaults */
	sch->limit = 10240;
	atomic64_set_release(&(q->ns_pro_byte), /* 10 Mbit/s */ 800);
	q->lastknownrate = 800; /* same as above */
	q->markfree = nsmul(4, NSEC_PER_MSEC);
	q->markfull = nsmul(14, NSEC_PER_MSEC);
	q->nsubbufs = 0;
	q->fragcache_num = 0;
	q->xlatency = 0;
	q->qosmode = 0;

	/* qdisc state */
	sch->q.qlen = 0;
	q->fragcache_base = NULL;
	q->ctlfile = NULL;
	qdisc_watchdog_init_clockid(&q->watchdog, sch, CLOCK_MONOTONIC);

	/* needed so janz_reset and janz_done DTRT */
	q->record_chan = NULL;
	janz_reset(sch);

	if (opt && (err = janz_chg(sch, opt, extack)))
		goto init_fail;

	if (q->nsubbufs < 4U || q->nsubbufs > 0x000FFFFFU)
		q->nsubbufs = 1024;

	if (q->fragcache_num < 16U || q->fragcache_num > 0x00FFFFFFU)
		q->fragcache_num = 1024;

	snprintf(name, sizeof(name), "%04X:", sch->handle >> 16);
	q->record_chan = relay_open(name, janz_debugfs_main,
	    TC_JANZ_RELAY_SUBBUFSZ, q->nsubbufs,
	    &janz_debugfs_relay_hooks, sch);
	if (!q->record_chan) {
		NL_SET_ERR_MSG_MOD(extack, "relay channel creation failed");
		err = -ENOENT;
		goto init_fail;
	}
	spin_lock_init(&q->record_lock);

	snprintf(name, sizeof(name), "%04X:v" __stringify(JANZ_CTLFILE_VERSION),
	    sch->handle >> 16);
	q->ctlfile = debugfs_create_file(name, 0200, janz_debugfs_main,
	    q, &janz_ctlfile_fops);
	if (IS_ERR_OR_NULL(q->ctlfile)) {
		err = q->ctlfile ? PTR_ERR(q->ctlfile) : -ENOENT;
		q->ctlfile = NULL;
		NL_SET_ERR_MSG_MOD(extack, "control channel creation failed");
		goto init_fail;
	}
	d_inode(q->ctlfile)->i_size = sizeof(struct janz_ctlfile_pkt);

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
	q->qsz_next = now;
	q->drop_next = now + DROPCHK_INTERVAL;

	sch->flags &= ~TCQ_F_CAN_BYPASS;
	return (0);

 init_fail:
	if (q->ctlfile) {
		debugfs_remove(q->ctlfile);
		q->ctlfile = NULL;
	}
	if (q->record_chan) {
		relay_close(q->record_chan);
		q->record_chan = NULL;
	}
	return (err);
}

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

static void
janz_done(struct Qdisc *sch)
{
	struct janz_priv *q = qdisc_priv(sch);
	struct janz_gwq_ovl *ovl;

	qdisc_watchdog_cancel(&q->watchdog);

	if (q->ctlfile) {
		debugfs_remove(q->ctlfile);
		q->ctlfile = NULL;
	}

	if (!q->record_chan) {
		/* the fast/easy path out, do everything now */
		kvfree(q->fragcache_base);
		return;
	}

	if (!q->fragcache_base) {
		/* all bets off… */
		relay_close(q->record_chan);
		return;
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
}

static int
janz_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct janz_priv *q = qdisc_priv(sch);
	struct nlattr *opts;
	u64 rate;

	opts = nla_nest_start(skb, TCA_OPTIONS);
	if (opts == NULL)
		goto nla_put_failure;

	rate = (u64)atomic64_read_acquire(&(q->ns_pro_byte));
	if (nla_put_u64_64bit(skb, TCA_JANZ_RATE64,
	      max(div64_u64(NSEC_PER_SEC, rate), 1ULL), TCA_JANZ_PAD64) ||
	    nla_put_u32(skb, TCA_JANZ_QOSMODE, q->qosmode) ||
	    nla_put_u32(skb, TCA_JANZ_MARKFREE, ns_to_us(q->markfree)) ||
	    nla_put_u32(skb, TCA_JANZ_MARKFULL, ns_to_us(q->markfull)) ||
	    nla_put_u32(skb, TCA_JANZ_SUBBUFS, q->nsubbufs) ||
	    nla_put_u32(skb, TCA_JANZ_FRAGCACHE, q->fragcache_num) ||
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
	pr_warn("kernel too old: will misfunction for locally originating packets, see README\n");
#endif

	if (!(janz_debugfs_main = debugfs_create_dir(KBUILD_MODNAME, NULL)))
		rv = -ENOSYS;
	else
		rv = PTR_ERR_OR_ZERO(janz_debugfs_main);
	if (rv) {
		pr_warn("debugfs initialisation error\n");
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
MODULE_DESCRIPTION("bespoke egress traffic scheduler for the JENS network simulator, single UE simulation");

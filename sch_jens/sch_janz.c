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
#define JANZ_IP_DECODER_DEBUG(...)	/* nothing */
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
#include "jens_uapi.h"
#include <net/ip.h>
#include <net/inet_ecn.h>
#include <net/pkt_cls.h>
#include "jens_codel.h"

struct janz_fragcomp {
	__u8 sip[16];				//@0    :16
	__u8 dip[16];				//@16   :16
	__u32 idp;				//@16   :4
	__u8 v;					//@  +4 :1
} __attribute__((__packed__));

struct janz_fragcache {
	struct janz_fragcomp c;			//@0
	__u8 nexthdr;				//@ +37 :1
	__u8 _pad[2];				//@ +38 :2
	codel_time_t ts;			//@ +40 :4
	__u16 sport;				//@ +44 :2
	__u16 dport;				//@ +46 :2
	struct janz_fragcache *next;		//@16
};

/* compile-time assertion */
struct janz_fragcache_check {
	int cmp[sizeof(struct janz_fragcomp) == 37 ? 1 : -1];
	int cac[sizeof(struct janz_fragcache) == (48 + sizeof(void *)) ? 1 : -1];
	int tot[sizeof(struct janz_fragcache) <= 64 ? 1 : -1];
	int xip[sizeof_field(struct tc_jens_relay, xip) == 16 ? 1 : -1];
	int x_y[offsetof(struct tc_jens_relay, yip) ==
	    (offsetof(struct tc_jens_relay, xip) + 16) ? 1 : -1];
};

struct janz_skbfifo {
	struct sk_buff *first;
	struct sk_buff *last;
};

/* struct janz_priv *q = qdisc_priv(sch); */
struct janz_priv {
	struct janz_skbfifo q[3];	/* TOS FIFOs */					//@cacheline
	struct rchan *record_chan;	/* relay to userspace */			//@16
#define QSZ_INTERVAL ((u64)(5UL * NSEC_PER_MSEC))
	u64 qsz_next;			/* next time to emit queue-size */		//@  +8
	u64 notbefore;			/* ktime_get_ns() to send next, or 0 */		//@16
	u64 ns_pro_byte;		/* traffic shaping tgt bandwidth */		//@  +8
	u64 handover;			/* time past next handover (or 0) */		//@16
	codel_time_t markfree;								//@  +8
	codel_time_t markfull;								//@  +12
	struct janz_fragcache *fragcache_used;						//@16
	struct janz_fragcache *fragcache_last; /* last used element */			//@  +8
	struct janz_fragcache *fragcache_free;						//@16
	struct janz_fragcache *fragcache_base;						//@  +8
	struct qdisc_watchdog watchdog;	/* to schedule when traffic shaping */		//@16
	u32 nsubbufs;									//@?
	u32 fragcache_num;
	codel_time_t fragcache_aged;
	spinlock_t record_lock;		/* for record_chan */
	u8 crediting;
};

/* struct janz_skb *cb = get_janz_skb(skb); */
struct janz_skb {
	/* limited to QDISC_CB_PRIV_LEN (20) bytes! */
	codel_time_t enq_ts;		/* enqueue timestamp */			//@8   :4
	u16 chance;			/* chance on ECN CE marking */		//@ +4 :2
	u16 srcport;								//@ +6 :2
	u16 dstport;								//@8   :2
	u8 record_flag;			/* for debugfs/relayfs reporting */	//@ +2 :1
	u8 tosbyte;			/* from IPv4/IPv6 header or faked */	//@ +3 :1
	u8 ipver;								//@ +4 :1
	u8 nexthdr;								//@ +5 :1
};

static inline struct janz_skb *
get_janz_skb(const struct sk_buff *skb)
{
	qdisc_cb_private_validate(skb, sizeof(struct janz_skb));
	return ((struct janz_skb *)qdisc_skb_cb(skb)->data);
}

static inline void
janz_record_write(struct tc_jens_relay *record, struct janz_priv *q)
{
	unsigned long flags;	/* used by spinlock macros */

	spin_lock_irqsave(&q->record_lock, flags);
	__relay_write(q->record_chan, record, sizeof(struct tc_jens_relay));
	spin_unlock_irqrestore(&q->record_lock, flags);
}

static inline void
janz_record_queuesz(struct Qdisc *sch, struct janz_priv *q, u64 now)
{
	struct tc_jens_relay r = {0};

	r.ts = now;
	r.type = TC_JENS_RELAY_QUEUESZ;
	r.d32 = /* q->memory_usage */ 0;
	r.e16 = sch->q.qlen > 0xFFFFU ? 0xFFFFU : sch->q.qlen;
	r.f8 = 0;
	janz_record_write(&r, q);

	/* use of ktime_get_ns() is deliberate */
	q->qsz_next = ktime_get_ns() + QSZ_INTERVAL;
}

static inline struct sk_buff *
janz_getnext(struct Qdisc *sch, struct janz_priv *q, bool is_peek)
{
	u64 now = ktime_get_ns();
	struct sk_buff *skb;
	int qid;

	if (now < q->notbefore) {
		if (!is_peek)
			qdisc_watchdog_schedule_range_ns(&q->watchdog,
			    q->notbefore, NSEC_PER_MSEC);
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

	skb = (q->q[(qid = 0)].first) ? : \
	      (q->q[(qid = 1)].first) ? : \
	      (q->q[(qid = 2)].first);
	if (WARN(!skb, "supposed to equal !sch->q.qlen"))
		goto nothing_to_send;
	if (is_peek)
		goto out;
	if (!(q->q[qid].first = skb->next))
		q->q[qid].last = NULL;
	--sch->q.qlen;
	skb->next = NULL;
	qdisc_qstats_backlog_dec(sch, skb);
	qdisc_bstats_update(sch, skb);

	q->notbefore = (q->crediting ? q->notbefore : now) +
	    (q->ns_pro_byte * (u64)skb->len);
	q->crediting = 1;

 out:
	if (!is_peek && (now >= q->qsz_next))
		janz_record_queuesz(sch, q, now);
	return (skb);
}

static void
janz_drop_headroom(struct Qdisc *sch, struct janz_priv *q)
{
	struct sk_buff *skb;
	int qid;

	do {
		skb = (q->q[(qid = 2)].first) ? : \
		      (q->q[(qid = 1)].first) ? : \
		      (q->q[(qid = 0)].first);
		if (unlikely(!skb))
			/* nothing to drop?! */
			break;
		if (!(q->q[qid].first = skb->next))
			q->q[qid].last = NULL;
		--sch->q.qlen;
		qdisc_qstats_backlog_dec(sch, skb);
		/* inefficient for large reduction in sch->limit */
		/* but we assume this doesn’t happen often, if at all */
		rtnl_kfree_skbs(skb, skb);
	} while (unlikely(sch->q.qlen >= sch->limit));
}

static inline u8
janz_get_iptos(struct sk_buff *skb)
{
	unsigned char *endoflineardata = skb->data + skb_headlen(skb);
	unsigned char *hdrp;

	switch (skb->protocol) {
	case htons(ETH_P_IP): {
		struct iphdr *ih4 = ip_hdr(skb);

		hdrp = (void *)ih4;
		if ((hdrp + sizeof(struct iphdr)) > endoflineardata)
			return (0);
		return (ih4->tos);
	    }
	case htons(ETH_P_IPV6): {
		struct ipv6hdr *ih6 = ipv6_hdr(skb);

		hdrp = (void *)ih6;
		if ((hdrp + sizeof(struct ipv6hdr)) > endoflineardata)
			return (0);
		return (ipv6_get_dsfield(ih6));
	    }
	/* fake the rest */
	case htons(ETH_P_ARP):
	case htons(ETH_P_RARP):
	case htons(ETH_P_PPP_DISC):
		return (0x10);
	case htons(ETH_P_LOOP):
	case htons(ETH_P_LOOPBACK):
		return (0x08);
	default:
		return (0x00);
	}
}

static inline void
janz_analyse(struct Qdisc *sch, struct janz_priv *q,
    struct sk_buff *skb, struct janz_skb *cb)
{
	//XXX fold later, plus ipver, nexthdr, srcport, dstport
	// enq_ts done in caller
	// chance done at dequeueing
	// record_flag… tbd?
	cb->tosbyte = janz_get_iptos(skb);
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
	struct tc_jens_relay *subbuf = (struct tc_jens_relay *)subbuf_;
	struct tc_jens_relay bufinit = { 0, TC_JENS_RELAY_PADDING };

	for (n = 0; n < TC_JENS_RELAY_NRECORDS; ++n)
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
	cb->enq_ts = codel_mktime(now);
	janz_analyse(sch, q, skb, cb);

	qid = 1;
	if (cb->tosbyte & 0x10)
		--qid;
	if (cb->tosbyte & 0x08)
		++qid;

	// assumption is 1 packet is passed
	if (WARN(skb->next != NULL, "janz_enq passed multiple packets?"))
		skb->next = NULL;

	if (unlikely(overlimit = (++sch->q.qlen >= sch->limit)))
		janz_drop_headroom(sch, q);
	if (!q->q[qid].first) {
		q->q[qid].first = skb;
		q->q[qid].last = skb;
	} else {
		q->q[qid].last->next = skb;
		q->q[qid].last = skb;
	}
	qdisc_qstats_backlog_inc(sch, skb);

	if (now >= q->qsz_next)
		janz_record_queuesz(sch, q, now);

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

	if ((skb = janz_getnext(sch, q, false))) {
		//… reporting etc.
	}
	return (skb);
}

static struct sk_buff *
janz_peek(struct Qdisc *sch)
{
	struct janz_priv *q = qdisc_priv(sch);

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
	sch->qstats.backlog = 0;
	sch->qstats.overlimits = 0;
	q->notbefore = 0;
	q->crediting = 0;
	//XXX flush subbufs?
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

	if (!opt)
		return (-EINVAL);

	if ((err = nla_parse_nested_deprecated(tb, TCA_JANZ_MAX, opt,
	    janz_nla_policy, extack)) < 0)
		return (err);

	/* anything that can throw first */

	if (q->fragcache_num) {
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

		tmp = ((u64)NSEC_PER_SEC) / tmp;
		q->ns_pro_byte = tmp > 0 ? tmp : 1;
	}

	if (tb[TCA_JANZ_HANDOVER]) {
		u64 tmp = nla_get_u32(tb[TCA_JANZ_HANDOVER]);

		tmp *= NSEC_PER_USEC;
		q->handover = ktime_get_ns() + tmp;
		/* implementation of handover */
		q->notbefore = q->handover < q->notbefore ?
		    q->notbefore : q->handover;
		q->crediting = 0;
	}

	if (tb[TCA_JANZ_MARKFREE]) {
		u64 tmp = nla_get_u32(tb[TCA_JANZ_MARKFREE]);

		tmp *= NSEC_PER_USEC;
		tmp >>= CODEL_SHIFT;
		/* guaranteed to fit: * 1000 / 2¹⁰ */
		q->markfree = (u32)tmp;
	}

	if (tb[TCA_JANZ_MARKFULL]) {
		u64 tmp = nla_get_u32(tb[TCA_JANZ_MARKFULL]);

		tmp *= NSEC_PER_USEC;
		tmp >>= CODEL_SHIFT;
		/* guaranteed to fit: * 1000 / 2¹⁰ */
		q->markfull = (u32)tmp;
	}

	if (tb[TCA_JANZ_SUBBUFS])
		/* only at load time */
		q->nsubbufs = nla_get_u32(tb[TCA_JANZ_SUBBUFS]);

	if (tb[TCA_JANZ_FRAGCACHE])
		/* only at load time */
		q->fragcache_num = nla_get_u32(tb[TCA_JANZ_FRAGCACHE]);

	if (sch->q.qlen > sch->limit)
		janz_drop_headroom(sch, q);

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
	int err, i;
	char name[6];

	/* config values’ defaults */
	sch->limit = 10240;
	q->ns_pro_byte = 800; /* 10 Mbit/s */
	q->handover = 0;
	q->markfree = MS2TIME(4);
	q->markfull = MS2TIME(14);
	q->nsubbufs = 0;
	q->fragcache_num = 0;

	/* qdisc state */
	sch->q.qlen = 0;
	janz_reset(sch);
	qdisc_watchdog_init_clockid(&q->watchdog, sch, CLOCK_MONOTONIC);

	if (opt && (err = janz_chg(sch, opt, extack)))
		goto init_fail;

	if (q->nsubbufs < 4U || q->nsubbufs > 0x000FFFFFU)
		q->nsubbufs = 1024;

	if (q->fragcache_num < 16U || q->fragcache_num > 0x00FFFFFFU)
		q->fragcache_num = 1024;

	snprintf(name, sizeof(name), "%04X:", sch->handle >> 16);
	q->record_chan = relay_open(name, janz_debugfs_main,
	    TC_JENS_RELAY_SUBBUFSZ, q->nsubbufs,
	    &janz_debugfs_relay_hooks, sch);
	if (!q->record_chan) {
		printk(KERN_WARNING "sch_janz: relay channel creation failed\n");
		err = -ENOENT;
		goto init_fail;
	}
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

	q->qsz_next = ktime_get_ns() + QSZ_INTERVAL;

	sch->flags &= ~TCQ_F_CAN_BYPASS;
	return (0);

 init_fail:
	if (q->record_chan) {
		relay_close(q->record_chan);
		q->record_chan = NULL;
	}
	return (err);
}

static void
janz_done(struct Qdisc *sch)
{
	struct janz_priv *q = qdisc_priv(sch);

	qdisc_watchdog_cancel(&q->watchdog);
	if (q->record_chan)
		relay_close(q->record_chan);
	kvfree(q->fragcache_base);
}

static int
janz_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct janz_priv *q = qdisc_priv(sch);
	struct nlattr *opts;

	opts = nla_nest_start(skb, TCA_OPTIONS);
	if (opts == NULL)
		goto nla_put_failure;

	if (q->handover && nla_put_u32(skb, TCA_JANZ_HANDOVER,
	    (q->handover - ktime_get_ns()) / NSEC_PER_USEC))
		goto nla_put_failure;

	if (nla_put_u64_64bit(skb, TCA_JANZ_RATE64,
	      ((u64)NSEC_PER_SEC) / q->ns_pro_byte, TCA_JANZ_PAD64) ||
	    nla_put_u32(skb, TCA_JANZ_MARKFREE, codel_time_to_us(q->markfree)) ||
	    nla_put_u32(skb, TCA_JANZ_MARKFULL, codel_time_to_us(q->markfull)) ||
	    nla_put_u32(skb, TCA_JANZ_SUBBUFS, q->nsubbufs) ||
	    nla_put_u32(skb, TCA_JANZ_FRAGCACHE, q->fragcache_num) ||
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
MODULE_DESCRIPTION("bespoke packet scheduler for JENS");

/*
 * Dǟ janz zesammene Kuh-Disk
 *
 * Copyright © 2022 mirabilos <t.glaser@tarent.de>
 * Licensor: Deutsche Telekom LLCTO
 *
 * This module for the Linux kernel is published under the GPLv2.
 */

#undef JENS_IP_DECODER_DEBUG
#if 1
#define JENS_IP_DECODER_DEBUG(...)	/* nothing */
#else
#define JENS_IP_DECODER_DEBUG(...)	printk(__VA_ARGS__)
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

struct janz_skbfifo {
	struct sk_buff *first;
	struct sk_buff *last;
};

/* struct janz_priv *q = qdisc_priv(sch); */
struct janz_priv {
	struct janz_skbfifo q[3];	/* TOS FIFOs */					//@cacheline
	u64 notbefore;			/* ktime_get_ns() to send next, or 0 */		//@16
	u64 ns_pro_byte;		/* traffic shaping tgt bandwidth */		//@  +8
	u64 handover;			/* time past next handover (or 0) */		//@16
	codel_time_t markfree;								//@  +8
	codel_time_t markfull;								//@  +12
	struct qdisc_watchdog watchdog;	/* to schedule when traffic shaping */		//@16
	u32 nsubbufs;									//@?
	u32 fragcache_num;
	u8 crediting;
};

/* struct janz_skb *cb = get_janz_skb(skb); */
struct janz_skb {
	/* limited to QDISC_CB_PRIV_LEN (20) bytes! */
	codel_time_t enq_ts;		/* enqueue timestamp */			//@8   :4
	u16 chance;			/* chance on ECN CE marking */		//@ +4 :2
	u8 record_flag;			/* for debugfs/relayfs reporting */	//@ +6 :1
	u8 tosbyte;			/* from IPv4/IPv6 header or faked */	//@ +7 :1
};

static struct dentry *janz_debugfs_main;

static inline struct janz_skb *
get_janz_skb(const struct sk_buff *skb)
{
	qdisc_cb_private_validate(skb, sizeof(struct janz_skb));
	return ((struct janz_skb *)qdisc_skb_cb(skb)->data);
}

static struct sk_buff *
janz_getnext(struct Qdisc *sch, struct janz_priv *q, bool is_peek)
{
	u64 now = ktime_get_ns();
	struct sk_buff *skb;
	int qid;

	if (now < q->notbefore) {
		if (!is_peek)
			qdisc_watchdog_schedule_range_ns(&q->watchdog,
			    q->notbefore, NSEC_PER_MSEC);
		return (NULL);
	}

	/* we have reached notbefore, previous packet is fully sent */

	if (!sch->q.qlen) {
		/* nothing to send, start subsequent packet later */
 nothing_to_send:
		q->crediting = 0;
		return (NULL);
	}

	skb = (q->q[(qid = 0)].first) ? : \
	      (q->q[(qid = 1)].first) ? : \
	      (q->q[(qid = 2)].first);
	if (WARN(!skb, "supposed to equal !sch->q.qlen"))
		goto nothing_to_send;
	if (is_peek)
		return (skb);
	if (!(q->q[qid].first = skb->next))
		q->q[qid].last = NULL;
	--sch->q.qlen;
	skb->next = NULL;

	q->notbefore = (q->crediting ? q->notbefore : now) +
	    (q->ns_pro_byte * (u64)skb->len);
	q->crediting = 1;

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

static int
janz_enq(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free)
{
	struct janz_priv *q = qdisc_priv(sch);
	struct janz_skb *cb = get_janz_skb(skb);
	u8 qid;
	u32 prev_backlog = sch->qstats.backlog;
	bool overlimit;

	cb->enq_ts = codel_get_time();
	cb->tosbyte = janz_get_iptos(skb);

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

static void
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
	//XXX qsz_next

	//XXX empty fragcache
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

static int
janz_chg(struct Qdisc *sch, struct nlattr *opt, struct netlink_ext_ack *extack)
{
	struct janz_priv *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_JANZ_MAX + 1];
	int err;

	if (!opt)
		return (-EINVAL);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
	err = nla_parse_nested(tb, TCA_JANZ_MAX, opt, janz_nla_policy, extack);
#else
	err = nla_parse_nested_deprecated(tb, TCA_JANZ_MAX, opt,
	    janz_nla_policy, extack);
#endif
	if (err < 0)
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

static int
janz_init(struct Qdisc *sch, struct nlattr *opt, struct netlink_ext_ack *extack)
{
	struct janz_priv *q = qdisc_priv(sch);
	int err;

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
	//q->record_chan = NULL;
	//spin_lock_init(&q->record_lock);

	if (opt && (err = janz_chg(sch, opt, extack)))
		goto init_fail;

	if (q->nsubbufs < 4 || q->nsubbufs > 0x000FFFFF)
		q->nsubbufs = 1024;

	if (q->fragcache_num < 16 || q->fragcache_num > 0x00FFFFFF)
		q->fragcache_num = 1024;

	//XXX subbufs, record_chan
	//XXX fragcache

	sch->flags &= ~TCQ_F_CAN_BYPASS;
	return (0);

// alloc_fail:
 init_fail:
	//if (q->record_chan)
	//	relay_close(q->record_chan);
	return (err);
}

static void
janz_done(struct Qdisc *sch)
{
	struct janz_priv *q = qdisc_priv(sch);

	qdisc_watchdog_cancel(&q->watchdog);
	//free fragcache
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
	printk(KERN_WARNING "sch_jens: kernel too old: will misfunction for locally originating packets, see README\n");
#endif

	if (!(janz_debugfs_main = debugfs_create_dir("sch_janz", NULL)))
		rv = -ENOSYS;
	else
		rv = PTR_ERR_OR_ZERO(janz_debugfs_main);
	if (rv) {
		janz_debugfs_main = NULL;
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
MODULE_DESCRIPTION("packet scheduler for JENS");

/*
 * JENS qdisc with multiple UE support
 *
 * Copyright © 2022, 2023 mirabilos <t.glaser@tarent.de>
 * Licensor: Deutsche Telekom LLCTO
 *
 * This module for the Linux kernel is published under the GPLv2.
 */

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

#include "mbsdcc.h"
#include "janz_uapi.h"
#include "gru32b.h"
#define Sjanz struct sjanz_priv
#define Mjanz struct mjanz_priv
#define lacks_retransmissions
#include "janz_defs.h"

/* workaround to relay_close late using the global workqueue */
struct janz_gwq_ovl {
	struct delayed_work dwork;
	u32 uenum;
	struct rchan *record_chans[];
};

struct sjanz_priv {
	struct janz_skbfifo rexmit;	/* retransmission loop */			//@16
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
	u64 lastknownrate;								//@  +8
	u32 pktlensum;			/* amount of bytes queued up */			//@  +4
	u32 xlatency;			/* extra artificial pre-enqueue latency */	//@  +4
	spinlock_t record_lock;		/* for record_chan */				//@  +8
	u8 crediting;									//@?
	u8 qosmode;
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
	u64 fragcache_aged;								//@  +8
	u32 fragcache_num;								//@16
	u32 nsubbufs;									//   +4
	struct janz_ctlfile_pkt *ctldata;	/* per-UE */				//@  +8
	struct janz_skbfifo yfifo;	/* bypass */					//@16
	struct qdisc_watchdog watchdog;	/* to schedule when traffic shaping */		//@16
#ifdef notyet
	/*XXX bypass? rexmit? */
	u8 has_pkts_in_bypass;		/* visit bypasses[0‥uenum+1[ before subqueues? */
#endif
};

#include "janz_impl.h"

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
janz_drop_overlen(struct Qdisc *sch, struct mjanz_priv *q, u64 now,
    bool isenq)
{
	goto into_the_loop;
	do {
		if (++(q->uecur) == q->uenum)
			q->uecur = 0;
 into_the_loop:
		janz_drop_1pkt_overlen(sch, &q->subqueues[q->uecur],
		    now, !isenq);
	} while (unlikely(sch->q.qlen > sch->limit));
}

static int
janz_enq(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free)
{
	struct mjanz_priv *q = qdisc_priv(sch);
	struct sjanz_priv *sq;
	struct janz_skb *cb = get_janz_skb(skb);
	u8 qid;
	u32 prev_backlog = sch->qstats.backlog;
	u64 now;
	struct janz_skbfifo *dstfifo;

	now = ktime_get_ns();

	/* initialise values in cb */
	cb->ts_enq = now;
	/* cb->pktxlatency below */
	/* init values from before analysis */
	cb->srcport = 0;
	cb->dstport = 0;
	cb->tosbyte = 0;
	cb->ipver = 0;
	cb->nexthdr = 0;
	cb->record_flag = 0;
	/* note ↑ struct order */

	/* analyse skb determining tosbyte, etc. */
	if (janz_analyse(sch, q, skb, cb, now)) {
		/* use the bypass; cb->tosbyte isn’t valid */
		dstfifo = &(q->yfifo);
		sq = &(q->subqueues[0]);
		cb->pktxlatency = 0;
		cb->xqid = 0;
		goto enq_bypass;
	}

	sq = &(q->subqueues[(u32)skb->mark < q->uenum ? (u32)skb->mark : 0]);
	cb->pktxlatency = sq->xlatency;

	switch (sq->qosmode) {
	case 0:
	default:
		qid = 1;
		if (cb->tosbyte & 0x10)
			--qid;
		if (cb->tosbyte & 0x08)
			++qid;
		break;
	case 1:
		// traffic is not categorised
		qid = 1;
		break;
	case 2:
		// traffic is categorised by ECT(1) or else only
		qid = 1;
		if (((cb->record_flag & INET_ECN_MASK) == INET_ECN_ECT_1) ||
		    ((cb->record_flag & INET_ECN_MASK) == INET_ECN_CE))
			--qid;
		break;
	}
	dstfifo = &(sq->q[qid]);
	/* from here, cb->tosbyte is no longer valid */
	cb->xqid = qid + 1;
 enq_bypass:
	cb->xmittot = 0;
	cb->xmitnum = 0;
	janz_dropchk(sch, sq, now);
	return (jq_enq(sch, q, sq, dstfifo, skb, now, to_free, prev_backlog));
}

static struct sk_buff *
janz_deq(struct Qdisc *sch)
{
	struct mjanz_priv * const q = qdisc_priv(sch);
	struct sjanz_priv *sq;
	struct sk_buff *skb;
	u64 now, rate, rs;
	u32 ue;
	struct janz_skb *cb;
	int qid;
	u64 mnextns;

 redo_deq:
	now = ktime_get_ns();

	/* check bypass at first */
	if (q->yfifo.first) {
		skb = q_deq(sch, &(q->subqueues[0]), &(q->yfifo));
		cb = get_janz_skb(skb);
		qdisc_bstats_update(sch, skb);
		/* from janz_sendoff */
		qdelay_encode(cb, now, NULL, false);
		janz_record_packet(&(q->subqueues[0]), skb, cb, now);
		return (skb);
	}

	mnextns = (u64)~(u64)0;
	ue = q->uecur;
 find_subqueue_to_send:
	sq = &(q->subqueues[ue]);
	/* next UE for next loop or next time to send */
	if (++ue == q->uenum)
		ue = 0;

	janz_dropchk(sch, sq, now);

	if (now < sq->notbefore) {
		register u64 nextns;

		nextns = min(sq->notbefore, sq->drop_next);
		mnextns = min(mnextns, nextns);
		goto try_next_subqueue;
	}

	/* we have reached notbefore, previous packet is fully sent */

	if (!sq->q[0].first && !sq->q[1].first && !sq->q[2].first) {
		/* nothing to send, start subsequent packet later */
 nothing_to_send:
		sq->crediting = 0;
		goto try_next_subqueue;
	}

#define try_qid(i) do {							\
	qid = (i);							\
	if (sq->q[qid].first) {						\
		cb = get_janz_skb(sq->q[qid].first);			\
		if (cb->ts_enq + cb->pktxlatency <= now)		\
			goto got_skb;					\
		/* ts_arrive > now: packet has not reached us yet */	\
		if (cb->ts_enq + cb->pktxlatency < rs)			\
			rs = cb->ts_enq + cb->pktxlatency;		\
	}								\
} while (/* CONSTCOND */ 0)

	rs = (u64)~(u64)0U;
	try_qid(0);
	try_qid(1);
	try_qid(2);
	qid = -1;

	/* nothing to send, but we have to reschedule first */
	/* if we end up here, rs was set above */
	mnextns = min(mnextns, rs);
	goto nothing_to_send;

 try_next_subqueue:
	if (now >= sq->qsz_next)
		janz_record_queuesz(sch, sq, now, 0, 0);
	/* loop, only one full loop though */
	if (ue != q->uecur)
		goto find_subqueue_to_send;

	/* nothing to send in all subqueues, drops/qsz_next checked etc. */
	if (mnextns != (u64)~(u64)0)
		qdisc_watchdog_schedule_ns(&q->watchdog, mnextns);
	return (NULL);

 got_skb:
	/* try next subqueue next time */
	q->uecur = ue;

	/* process this skb */
	skb = q_deq(sch, sq, &(sq->q[qid]));
	cb = get_janz_skb(skb);
	qdisc_bstats_update(sch, skb);

	rate = (u64)atomic64_read_acquire(&(sq->ns_pro_byte));
	sq->notbefore = (sq->crediting ?
	    max(sq->notbefore, cb->ts_enq + cb->pktxlatency) : now) +
	    (rate * (u64)qdisc_pkt_len(skb));
	sq->crediting = 1;
	if (rate != sq->lastknownrate)
		goto force_rate_and_out;

	if (now >= sq->qsz_next) {
 force_rate_and_out:
		janz_record_queuesz(sch, sq, now, rate, 0);
		++now;
	}

	if (janz_sendoff(sch, sq, skb, cb, now))
		/* sent to retransmission loop; fastpath recalling */
		goto redo_deq;
	return (skb);
}

static struct sk_buff *
janz_peek(struct Qdisc *sch)
{
	u64 then;
	u32 ue;
	struct mjanz_priv *q = qdisc_priv(sch);

	pr_warn(".peek called; this is not supported!\n");
	dump_stack();
	/* delay traffic noticeably, so the user knows to look */
	then = ktime_get_ns() + NSEC_PER_SEC;
	for (ue = 0; ue < q->uenum; ++ue) {
		q->subqueues[ue].notbefore = then;
		q->subqueues[ue].crediting = 0;
	}
	/* hard reply no packet to now send */
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
			rtnl_kfree_skbs(q->subqueues[ue].rexmit.first,
			    q->subqueues[ue].rexmit.last);
			rtnl_kfree_skbs(q->subqueues[ue].q[0].first,
			    q->subqueues[ue].q[0].last);
			rtnl_kfree_skbs(q->subqueues[ue].q[1].first,
			    q->subqueues[ue].q[1].last);
			rtnl_kfree_skbs(q->subqueues[ue].q[2].first,
			    q->subqueues[ue].q[2].last);
		}
		rtnl_kfree_skbs(q->yfifo.first, q->yfifo.last);
		sch->q.qlen = 0;
	}
	for (ue = 0; ue < q->uenum; ++ue) {
		q->subqueues[ue].rexmit.first = NULL;
		q->subqueues[ue].rexmit.last = NULL;
		q->subqueues[ue].q[0].first = NULL;
		q->subqueues[ue].q[0].last = NULL;
		q->subqueues[ue].q[1].first = NULL;
		q->subqueues[ue].q[1].last = NULL;
		q->subqueues[ue].q[2].first = NULL;
		q->subqueues[ue].q[2].last = NULL;
		q->subqueues[ue].pktlensum = 0;
		q->subqueues[ue].notbefore = 0;
		q->subqueues[ue].crediting = 0;
		if (q->subqueues[ue].record_chan)
			relay_flush(q->subqueues[ue].record_chan);
	}
	q->yfifo.first = NULL; q->yfifo.last = NULL;
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
	bool handover_started = false;
	u32 newqosmode = 0;
	u64 newxlatency = 0;

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
		if (tb[TCA_JANZ_SUBBUFS] || tb[TCA_JANZ_FRAGCACHE] ||
		    tb[TCA_MULTIJENS_UENUM]) {
			NL_SET_ERR_MSG_MOD(extack, "subbufs, fragcache and uenum can only be set at initialisation");
			return (-EINVAL);
		}
	} else {
		/* this is load time */
		if (!(tb[TCA_MULTIJENS_UENUM])) {
			NL_SET_ERR_MSG_MOD(extack, "missing uenum");
			return (-EINVAL);
		}
		/* allocate sch_janz subqueues */
		q->uenum = nla_get_u32(tb[TCA_MULTIJENS_UENUM]);
		/* range-check uenum; the “arbitrary” max also protects fragcache_num */
		/* and if too much, OOM killing ensues (already at 384 for me) */
		if (q->uenum < 2U ||
		    ((SIZE_MAX / sizeof(struct janz_ctlfile_pkt)) < (size_t)q->uenum) ||
		    (((SIZE_MAX - sizeof(struct janz_gwq_ovl)) / sizeof(struct rchan *)) < (size_t)q->uenum) ||
		    q->uenum > /* arbitrary */ 256U) {
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
				kvfree(q->ctldata);
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
			/* needed so janz_reset and janz_done DTRT */
			q->subqueues[ue].record_chan = NULL;
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

		tmp = div64_u64(NSEC_PER_SEC, tmp);
		if (tmp < 1)
			tmp = 1;
		for (ue = 0; ue < q->uenum; ++ue) {
			atomic64_set_release(&(q->subqueues[ue].ns_pro_byte), (s64)tmp);
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
			q->subqueues[ue].qosmode = newqosmode;

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
			q->subqueues[ue].xlatency = newxlatency;

	/* assert: sch->q.qlen == 0 || q->record_chan != nil */
	/* assert: sch->limit > 0 */
	if (unlikely(sch->q.qlen > sch->limit)) {
		u64 now = ktime_get_ns();

		janz_drop_overlen(sch, q, now, false);
	}

	/* report if a handover starts */
	if (unlikely(handover_started) && likely(q->subqueues[0].record_chan)) {
		u64 now = ktime_get_ns();

		for (ue = 0; ue < q->uenum; ++ue) {
			janz_record_queuesz(sch, &q->subqueues[ue], now, 0, 1);
			/* flush subbufs before handover */
			relay_flush(q->subqueues[ue].record_chan);
		}
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
	q->fragcache_base = NULL;
	q->ctlfile = NULL;
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
			NL_SET_ERR_MSG_MOD(extack, "relay channel creation failed");
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
		NL_SET_ERR_MSG_MOD(extack, "control channel creation failed");
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
		q->subqueues[ue].qsz_next = now;
		q->subqueues[ue].drop_next = now + DROPCHK_INTERVAL;
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
		kvfree(q->ctldata);
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
		relay_close(ovl->record_chans[ue]);
	kvfree(ovl);
}

static void
janz_done(struct Qdisc *sch)
{
	u32 ue;
	struct mjanz_priv *q = qdisc_priv(sch);
	struct janz_gwq_ovl *ovl;

	qdisc_watchdog_cancel(&q->watchdog);

	if (q->ctlfile) {
		debugfs_remove(q->ctlfile);
		q->ctlfile = NULL;
	}

	if (!q->fragcache_base) {
		if (!q->uenum) {
			/* janz_done after failed janz_init, presumably */
			return;
		}
		/* all bets off… */
		pr_alert("janz_done without fragcache_base memory, refusing to free; leaking resources!\n");
		dump_stack();
		return;
	}

	/*
	 * we need to relay_flush() now but relay_close() later so that
	 * userspace has a chance to actually read the information; for
	 * that, deferred work can be used, but where to put the struct
	 * for that? easy, reuse q->fragcache_base memory, free it last
	 * inside the worker function (this is explicitly permitted) ;)
	 */

	ovl = (void *)q->fragcache_base;
	INIT_DELAYED_WORK(&ovl->dwork, janz_gwq_fn);
	ovl->uenum = q->uenum;
	for (ue = 0; ue < q->uenum; ++ue) {
		ovl->record_chans[ue] = q->subqueues[ue].record_chan;
		relay_flush(q->subqueues[ue].record_chan);
	}

	/* free anything else first */
	kvfree(q->subqueues);
	kvfree(q->ctldata);

	schedule_delayed_work(&ovl->dwork, msecs_to_jiffies(1000));
}

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
	      max(div64_u64(NSEC_PER_SEC, rate), 1ULL), TCA_JANZ_PAD64) ||
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
MODULE_DESCRIPTION("bespoke egress traffic scheduler for the JENS network simulator, multiple UE simulation");

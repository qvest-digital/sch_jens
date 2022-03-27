/* part of sch_jens (fork of sch_fq_codel), Deutsche Telekom LLCTO */
/* Copyright © 2021, 2022 mirabilos <t.glaser@tarent.de> */

/*
 * Fair Queue CoDel discipline
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 *
 *  Copyright (C) 2012,2015 Eric Dumazet <edumazet@google.com>
 */

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
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include "jens_uapi.h"
#include <net/pkt_cls.h>
#include "jens_codel.h"
#include "jens_codel_qdisc.h"
#include "jens_codel_impl.h"

/*	Fair Queue CoDel.
 *
 * Principles :
 * Packets are classified (internal classifier or external) on flows.
 * This is a Stochastic model (as we use a hash, several flows
 *			       might be hashed on same slot)
 * Each flow has a CoDel managed queue.
 * Flows are linked onto two (Round Robin) lists,
 * so that new flows have priority on old ones.
 *
 * For a given flow, packets are not reordered (CoDel uses a FIFO)
 * head drops only.
 * Low memory footprint (64 bytes per flow)
 */

struct fq_codel_flow {
	struct sk_buff	  *head;
	struct sk_buff	  *tail;
	struct list_head  flowchain;
	int		  deficit;
	struct codel_vars cvars;
}; /* please try to keep this structure <= 64 bytes */

struct jens_sched_data {
	struct tcf_proto __rcu *filter_list; /* optional external classifier */
	struct tcf_block *block;
	struct fq_codel_flow *flows;	/* Flows table [flows_cnt] */
	u32		*backlogs;	/* backlog table [flows_cnt] */
	u32		flows_cnt;	/* number of flows */
	u32		quantum;	/* psched_mtu(qdisc_dev(sch)); */
	u32		drop_batch_size;
	u32		memory_limit;
	struct rchan *record_chan;	/* relay to userspace */
	struct jens_params cparams;
	struct codel_stats cstats;
	u32		memory_usage;
	u32		drop_overmemory;
	u32		drop_overlimit;
	u32		new_flow_count;

	struct list_head new_flows;	/* list of new flows */
	struct list_head old_flows;	/* list of old flows */

	spinlock_t	record_lock;	/* for record_chan */
#define QSZ_INTERVAL ((u64)5000000)	/* 5 ms in ns */
	u64		qsz_next;	/* next time to emit queue-size */
	unsigned char	nouseport;	/* do not add port to classify */
};

static struct dentry *jens_debugfs_main;

static struct dentry *jens_debugfs_create(const char *filename,
    struct dentry *parent, umode_t mode, struct rchan_buf *buf,
    int *is_global)
{
	*is_global = 1;
	return (debugfs_create_file(filename, mode, parent, buf,
	    &relay_file_operations));
}

static int jens_debugfs_destroy(struct dentry *dentry)
{
	debugfs_remove(dentry);
	return (0);
}

static int jens_subbuf_init(struct rchan_buf *buf, void *subbuf_,
    void *prev_subbuf, size_t prev_padding)
{
	size_t n;
	struct tc_jens_relay *subbuf = (struct tc_jens_relay *)subbuf_;
	struct tc_jens_relay bufinit = { 0, TC_JENS_RELAY_PADDING };

	for (n = 0; n < TC_JENS_RELAY_NRECORDS; ++n)
		subbuf[n] = bufinit;

	return (1);
}

static /*const*/ struct rchan_callbacks jens_debugfs_relay_hooks = {
	.create_buf_file = jens_debugfs_create,
	.remove_buf_file = jens_debugfs_destroy,
	.subbuf_start = jens_subbuf_init,
};

static void jens_record_write(struct tc_jens_relay *record,
    struct jens_sched_data *q)
{
	unsigned long flags;	/* used by spinlock macros */

	if (!q->record_chan)
		return;
	record->ts = ktime_get_ns();
	spin_lock_irqsave(&q->record_lock, flags);
	__relay_write(q->record_chan, record, sizeof(struct tc_jens_relay));
	spin_unlock_irqrestore(&q->record_lock, flags);
}

static void jens_record_queuesz(struct Qdisc *sch, struct jens_sched_data *q)
{
	struct tc_jens_relay r = {0};

	r.type = TC_JENS_RELAY_QUEUESZ;
	r.d32 = q->memory_usage;
	r.e16 = sch->q.qlen > 0xFFFFU ? 0xFFFFU : sch->q.qlen;
	r.f8 = 0;
	jens_record_write(&r, q);

	q->qsz_next = ktime_get_ns() + QSZ_INTERVAL;
}

static inline void maybe_record_queuesz(struct Qdisc *sch, struct jens_sched_data *q)
{
	if (ktime_get_ns() < q->qsz_next)
		return;

	jens_record_queuesz(sch, q);
}

static void jens_record_packet(struct sk_buff *skb, struct Qdisc *sch,
    struct jens_sched_data *q, codel_time_t ldelay, __u8 flags)
{
	__u8 ecn = jens_get_ecn(skb) & INET_ECN_MASK;
	struct tc_jens_relay r = {0};
	struct jens_skb_cb *cb = get_jens_cb(skb);

	r.type = TC_JENS_RELAY_SOJOURN;
	r.d32 = ldelay;
	r.e16 = cb->chance;
	r.f8 = cb->record_flag | flags | (ecn << 3);
	jens_record_write(&r, q);

	/* put out a queue-size record if it’s time */
	if (r.ts >= q->qsz_next)
		jens_record_queuesz(sch, q);
}

static unsigned int jens_hash(const struct jens_sched_data *q,
				  struct sk_buff *skb)
{
	struct flow_keys keys;
	__u32 hash;

	skb_flow_dissect_flow_keys(skb, &keys,
	    FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL);
	if (q->nouseport)
		memset(&keys.ports, 0, sizeof(keys.ports));
	hash = flow_hash_from_keys(&keys);

	return reciprocal_scale(hash, q->flows_cnt);
}

static unsigned int fq_codel_classify(struct sk_buff *skb, struct Qdisc *sch,
				      int *qerr)
{
	struct jens_sched_data *q = qdisc_priv(sch);
	struct tcf_proto *filter;
	struct tcf_result res;
	int result;

	if (TC_H_MAJ(skb->priority) == sch->handle &&
	    TC_H_MIN(skb->priority) > 0 &&
	    TC_H_MIN(skb->priority) <= q->flows_cnt)
		return TC_H_MIN(skb->priority);

	filter = rcu_dereference_bh(q->filter_list);
	if (!filter)
		return jens_hash(q, skb) + 1;

	*qerr = NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0)
	result = tcf_classify(skb, filter, &res, false);
#else
	result = tcf_classify(skb, NULL, filter, &res, false);
#endif
	if (result >= 0) {
#ifdef CONFIG_NET_CLS_ACT
		switch (result) {
		case TC_ACT_STOLEN:
		case TC_ACT_QUEUED:
		case TC_ACT_TRAP:
			*qerr = NET_XMIT_SUCCESS | __NET_XMIT_STOLEN;
			/* fall through */
		case TC_ACT_SHOT:
			return 0;
		}
#endif
		if (TC_H_MIN(res.classid) <= q->flows_cnt)
			return TC_H_MIN(res.classid);
	}
	return 0;
}

/* helper functions : might be changed when/if skb use a standard list_head */

/* remove one skb from head of slot queue */
static inline struct sk_buff *dequeue_head(struct fq_codel_flow *flow)
{
	struct sk_buff *skb = flow->head;

	flow->head = skb->next;
	skb->next = NULL;
	return skb;
}

/* add skb to flow queue (tail add) */
static inline void flow_queue_add(struct fq_codel_flow *flow,
				  struct sk_buff *skb)
{
	if (flow->head == NULL)
		flow->head = skb;
	else
		flow->tail->next = skb;
	flow->tail = skb;
	skb->next = NULL;
}

static unsigned int fq_codel_drop(struct Qdisc *sch, unsigned int max_packets,
				  struct sk_buff **to_free)
{
	struct jens_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;
	unsigned int maxbacklog = 0, idx = 0, i, len;
	struct fq_codel_flow *flow;
	unsigned int threshold;
	unsigned int mem = 0;

	/* Queue is full! Find the fat flow and drop packet(s) from it.
	 * This might sound expensive, but with 1024 flows, we scan
	 * 4KB of memory, and we dont need to handle a complex tree
	 * in fast path (packet queue/enqueue) with many cache misses.
	 * In stress mode, we'll try to drop 64 packets from the flow,
	 * amortizing this linear lookup to one cache line per drop.
	 */
	for (i = 0; i < q->flows_cnt; i++) {
		if (q->backlogs[i] > maxbacklog) {
			maxbacklog = q->backlogs[i];
			idx = i;
		}
	}

	/* Our goal is to drop half of this fat flow backlog */
	threshold = maxbacklog >> 1;

	flow = &q->flows[idx];
	len = 0;
	i = 0;
	do {
		skb = dequeue_head(flow);
		len += qdisc_pkt_len(skb);
		mem += get_jens_cb(skb)->mem_usage;
		__qdisc_drop(skb, to_free);
	} while (++i < max_packets && len < threshold);

	/* Tell codel to increase its signal strength also */
	flow->cvars.count += i;
	q->backlogs[idx] -= len;
	q->memory_usage -= mem;
	sch->qstats.drops += i;
	sch->qstats.backlog -= len;
	sch->q.qlen -= i;
	return idx;
}

static int fq_codel_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			    struct sk_buff **to_free)
{
	struct jens_sched_data *q = qdisc_priv(sch);
	unsigned int idx, prev_backlog, prev_qlen;
	struct fq_codel_flow *flow;
	int ret;
	unsigned int pkt_len;
	bool memory_limited;

	idx = fq_codel_classify(skb, sch, &ret);
	if (idx == 0) {
		if (ret & __NET_XMIT_BYPASS)
			qdisc_qstats_drop(sch);
		__qdisc_drop(skb, to_free);
		maybe_record_queuesz(sch, q);
		return ret;
	}
	idx--;

	jens_set_enqueue_data(skb);
	flow = &q->flows[idx];
	flow_queue_add(flow, skb);
	q->backlogs[idx] += qdisc_pkt_len(skb);
	qdisc_qstats_backlog_inc(sch, skb);

	if (list_empty(&flow->flowchain)) {
		list_add_tail(&flow->flowchain, &q->new_flows);
		q->new_flow_count++;
		flow->deficit = q->quantum;
	}
	get_jens_cb(skb)->mem_usage = skb->truesize;
	q->memory_usage += /*get_jens_cb(skb)->mem_usage*/ skb->truesize;
	memory_limited = q->memory_usage > q->memory_limit;
	if (++sch->q.qlen <= sch->limit && !memory_limited) {
		maybe_record_queuesz(sch, q);
		return NET_XMIT_SUCCESS;
	}

	prev_backlog = sch->qstats.backlog;
	prev_qlen = sch->q.qlen;

	/* save this packet length as it might be dropped by fq_codel_drop() */
	pkt_len = qdisc_pkt_len(skb);
	/* fq_codel_drop() is quite expensive, as it performs a linear search
	 * in q->backlogs[] to find a fat flow.
	 * So instead of dropping a single packet, drop half of its backlog
	 * with a 64 packets limit to not add a too big cpu spike here.
	 */
	ret = fq_codel_drop(sch, q->drop_batch_size, to_free);

	prev_qlen -= sch->q.qlen;
	prev_backlog -= sch->qstats.backlog;
	q->drop_overlimit += prev_qlen;
	if (memory_limited)
		q->drop_overmemory += prev_qlen;

	/* As we dropped packet(s), better let upper stack know this.
	 * If we dropped a packet for this flow, return NET_XMIT_CN,
	 * but in this case, our parents wont increase their backlogs.
	 */
	if (ret == idx) {
		qdisc_tree_reduce_backlog(sch, prev_qlen - 1,
					  prev_backlog - pkt_len);
		maybe_record_queuesz(sch, q);
		return NET_XMIT_CN;
	}
	qdisc_tree_reduce_backlog(sch, prev_qlen, prev_backlog);
	maybe_record_queuesz(sch, q);
	return NET_XMIT_SUCCESS;
}

/* This is the specific function called from jens_dequeue_codel()
 * to dequeue a packet from queue. Note: backlog is handled in
 * codel, we dont need to reduce it here.
 */
static struct sk_buff *dequeue_func(struct codel_vars *vars, void *ctx)
{
	struct Qdisc *sch = ctx;
	struct jens_sched_data *q = qdisc_priv(sch);
	struct fq_codel_flow *flow;
	struct sk_buff *skb = NULL;

	flow = container_of(vars, struct fq_codel_flow, cvars);
	if (flow->head) {
		skb = dequeue_head(flow);
		q->backlogs[flow - q->flows] -= qdisc_pkt_len(skb);
		q->memory_usage -= get_jens_cb(skb)->mem_usage;
		sch->q.qlen--;
		sch->qstats.backlog -= qdisc_pkt_len(skb);
	}
	return skb;
}

static void drop_func(struct sk_buff *skb, struct codel_vars *vars, void *ctx)
{
	struct Qdisc *sch = ctx;

	if (skb)
		jens_record_packet(skb, sch, qdisc_priv(sch), vars->ldelay,
		    TC_JENS_RELAY_SOJOURN_DROP);
	kfree_skb(skb);
	qdisc_qstats_drop(sch);
}

static struct sk_buff *jens_dequeue_fq_int(struct Qdisc *sch,
    codel_time_t *sojournp)
{
	struct jens_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;
	struct fq_codel_flow *flow;
	struct list_head *head;

begin:
	head = &q->new_flows;
	if (list_empty(head)) {
		head = &q->old_flows;
		if (list_empty(head))
			return NULL;
	}
	flow = list_first_entry(head, struct fq_codel_flow, flowchain);

	if (flow->deficit <= 0) {
		flow->deficit += q->quantum;
		list_move_tail(&flow->flowchain, &q->old_flows);
		goto begin;
	}

	skb = jens_dequeue_codel(sch, &sch->qstats.backlog, &q->cparams,
			    &flow->cvars, &q->cstats, qdisc_pkt_len,
			    codel_get_enqueue_time, drop_func, dequeue_func);

	if (!skb) {
		/* force a pass through old_flows to prevent starvation */
		if ((head == &q->new_flows) && !list_empty(&q->old_flows))
			list_move_tail(&flow->flowchain, &q->old_flows);
		else
			list_del_init(&flow->flowchain);
		goto begin;
	}
	*sojournp = flow->cvars.ldelay;
	qdisc_bstats_update(sch, skb);
	flow->deficit -= qdisc_pkt_len(skb);
	/* We cant call qdisc_tree_reduce_backlog() if our qlen is 0,
	 * or HTB crashes. Defer it for next round.
	 */
	if (q->cstats.drop_count && sch->q.qlen) {
		qdisc_tree_reduce_backlog(sch, q->cstats.drop_count,
					  q->cstats.drop_len);
		q->cstats.drop_count = 0;
		q->cstats.drop_len = 0;
	}
	return skb;
}

static struct sk_buff *jens_dequeue_fq(struct Qdisc *sch)
{
	codel_time_t ldelay = (codel_time_t)-1;

	struct sk_buff *skb = jens_dequeue_fq_int(sch, &ldelay);

	if (skb)
		jens_record_packet(skb, sch, qdisc_priv(sch), ldelay, 0);
	return (skb);
}

static void fq_codel_flow_purge(struct fq_codel_flow *flow)
{
	rtnl_kfree_skbs(flow->head, flow->tail);
	flow->head = NULL;
}

static void fq_codel_reset(struct Qdisc *sch)
{
	struct jens_sched_data *q = qdisc_priv(sch);
	int i;

	INIT_LIST_HEAD(&q->new_flows);
	INIT_LIST_HEAD(&q->old_flows);
	for (i = 0; i < q->flows_cnt; i++) {
		struct fq_codel_flow *flow = q->flows + i;

		fq_codel_flow_purge(flow);
		INIT_LIST_HEAD(&flow->flowchain);
		codel_vars_init(&flow->cvars);
	}
	memset(q->backlogs, 0, q->flows_cnt * sizeof(u32));
	sch->q.qlen = 0;
	sch->qstats.backlog = 0;
	q->memory_usage = 0;
}

static const struct nla_policy fq_codel_policy[TCA_JENS_MAX + 1] = {
	[TCA_JENS_TARGET]	= { .type = NLA_U32 },
	[TCA_JENS_LIMIT]	= { .type = NLA_U32 },
	[TCA_JENS_INTERVAL]	= { .type = NLA_U32 },
	[TCA_JENS_MARKFREE]	= { .type = NLA_U32 },
	[TCA_JENS_MARKFULL]	= { .type = NLA_U32 },
	[TCA_JENS_FLOWS]	= { .type = NLA_U32 },
	[TCA_JENS_QUANTUM]	= { .type = NLA_U32 },
	[TCA_JENS_DROP_BATCH_SIZE] = { .type = NLA_U32 },
	[TCA_JENS_MEMORY_LIMIT] = { .type = NLA_U32 },
	[TCA_JENS_SUBBUFS]	= { .type = NLA_U32 },
	[TCA_JENS_NOUSEPORT]	= { .type = NLA_FLAG },
};

static int fq_codel_change(struct Qdisc *sch, struct nlattr *opt,
			   struct netlink_ext_ack *extack)
{
	struct jens_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_JENS_MAX + 1];
	u32 quantum = 0;
	int err;

	if (!opt)
		return -EINVAL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
	err = nla_parse_nested(tb, TCA_JENS_MAX, opt, fq_codel_policy,
			       NULL);
#else
	err = nla_parse_nested_deprecated(tb, TCA_JENS_MAX, opt,
					  fq_codel_policy, NULL);
#endif
	if (err < 0)
		return err;

	if (tb[TCA_JENS_SUBBUFS]) {
		/* only at load time */
		if (q->flows)
			return (-EINVAL);
		q->cparams.subbufs = nla_get_u32(tb[TCA_JENS_SUBBUFS]);
		if (q->cparams.subbufs == 1)
			/* use suitable default value */
			q->cparams.subbufs = 1024;
	}

	if (tb[TCA_JENS_FLOWS]) {
		if (q->flows)
			return -EINVAL;
		q->flows_cnt = nla_get_u32(tb[TCA_JENS_FLOWS]);
		if (!q->flows_cnt ||
		    q->flows_cnt > 65536)
			return -EINVAL;
	}
	if (tb[TCA_JENS_QUANTUM]) {
		quantum = max(256U, nla_get_u32(tb[TCA_JENS_QUANTUM]));
		if (quantum > JENS_QUANTUM_MAX) {
			NL_SET_ERR_MSG(extack, "Invalid quantum");
			return -EINVAL;
		}
	}
	sch_tree_lock(sch);

	if (tb[TCA_JENS_TARGET]) {
		u64 target = nla_get_u32(tb[TCA_JENS_TARGET]);

		q->cparams.target = (target * NSEC_PER_USEC) >> CODEL_SHIFT;
	}

	if (tb[TCA_JENS_MARKFREE]) {
		u64 val = nla_get_u32(tb[TCA_JENS_MARKFREE]);

		q->cparams.markfree = (val * NSEC_PER_USEC) >> CODEL_SHIFT;
	}
	if (tb[TCA_JENS_MARKFULL]) {
		u64 val = nla_get_u32(tb[TCA_JENS_MARKFULL]);

		q->cparams.markfull = (val * NSEC_PER_USEC) >> CODEL_SHIFT;
	}

	if (tb[TCA_JENS_INTERVAL]) {
		u64 interval = nla_get_u32(tb[TCA_JENS_INTERVAL]);

		q->cparams.interval = (interval * NSEC_PER_USEC) >> CODEL_SHIFT;
	}

	if (tb[TCA_JENS_LIMIT])
		sch->limit = nla_get_u32(tb[TCA_JENS_LIMIT]);

	if (quantum)
		q->quantum = quantum;

	if (tb[TCA_JENS_DROP_BATCH_SIZE])
		q->drop_batch_size = max(1U, nla_get_u32(tb[TCA_JENS_DROP_BATCH_SIZE]));

	if (tb[TCA_JENS_MEMORY_LIMIT])
		q->memory_limit = min(1U << 31, nla_get_u32(tb[TCA_JENS_MEMORY_LIMIT]));

	q->nouseport = nla_get_flag(tb[TCA_JENS_NOUSEPORT]);

	while (sch->q.qlen > sch->limit ||
	       q->memory_usage > q->memory_limit) {
		codel_time_t dummy_sojourn;
		struct sk_buff *skb = jens_dequeue_fq_int(sch, &dummy_sojourn);

		if (skb)
			jens_record_packet(skb, sch, q, (codel_time_t)-1,
			    TC_JENS_RELAY_SOJOURN_DROP);
		q->cstats.drop_len += qdisc_pkt_len(skb);
		rtnl_kfree_skbs(skb, skb);
		q->cstats.drop_count++;
	}
	qdisc_tree_reduce_backlog(sch, q->cstats.drop_count, q->cstats.drop_len);
	q->cstats.drop_count = 0;
	q->cstats.drop_len = 0;

	sch_tree_unlock(sch);
	return 0;
}

static void fq_codel_destroy(struct Qdisc *sch)
{
	struct jens_sched_data *q = qdisc_priv(sch);

	if (q->record_chan)
		relay_close(q->record_chan);
	tcf_block_put(q->block);
	kvfree(q->backlogs);
	kvfree(q->flows);
}

static int fq_codel_init(struct Qdisc *sch, struct nlattr *opt,
			 struct netlink_ext_ack *extack)
{
	struct jens_sched_data *q = qdisc_priv(sch);
	int i;
	int err;

	sch->limit = 10*1024;
	q->flows_cnt = 1024;
	q->memory_limit = 32 << 20; /* 32 MBytes */
	q->drop_batch_size = 64;
	q->quantum = psched_mtu(qdisc_dev(sch));
	INIT_LIST_HEAD(&q->new_flows);
	INIT_LIST_HEAD(&q->old_flows);
	jens_params_init(&q->cparams);
	codel_stats_init(&q->cstats);
	q->cparams.mtu = psched_mtu(qdisc_dev(sch));
	q->record_chan = NULL;
	q->nouseport = 0;
	spin_lock_init(&q->record_lock);

	if (opt) {
		err = fq_codel_change(sch, opt, extack);
		if (err)
			goto init_failure;
	}

	if (!jens_debugfs_main)
		q->cparams.subbufs = 0;
	if (q->cparams.subbufs) {
		char name[6];

		snprintf(name, sizeof(name), "%04X:", sch->handle >> 16);
		q->record_chan = relay_open(name, jens_debugfs_main,
		    TC_JENS_RELAY_SUBBUFSZ, q->cparams.subbufs,
		    &jens_debugfs_relay_hooks, sch);
		if (!q->record_chan) {
			printk(KERN_DEBUG "sch_jens: relay channel creation failed\n");
			err = -ENOENT;
			goto init_failure;
		}
	}

	err = tcf_block_get(&q->block, &q->filter_list, sch, extack);
	if (err)
		goto init_failure;

	if (!q->flows) {
		q->flows = kvcalloc(q->flows_cnt,
				    sizeof(struct fq_codel_flow),
				    GFP_KERNEL);
		if (!q->flows) {
			err = -ENOMEM;
			goto init_failure;
		}
		q->backlogs = kvcalloc(q->flows_cnt, sizeof(u32), GFP_KERNEL);
		if (!q->backlogs) {
			err = -ENOMEM;
			goto alloc_failure;
		}
		for (i = 0; i < q->flows_cnt; i++) {
			struct fq_codel_flow *flow = q->flows + i;

			INIT_LIST_HEAD(&flow->flowchain);
			codel_vars_init(&flow->cvars);
		}
	}
	if (sch->limit >= 1)
		sch->flags |= TCQ_F_CAN_BYPASS;
	else
		sch->flags &= ~TCQ_F_CAN_BYPASS;
	q->qsz_next = q->cparams.subbufs ? ktime_get_ns() + QSZ_INTERVAL :
	    /* disable since we don’t report anyway */ (u64)-1;
	return 0;

alloc_failure:
	kvfree(q->flows);
	q->flows = NULL;
init_failure:
	if (q->record_chan)
		relay_close(q->record_chan);
	q->flows_cnt = 0;
	return err;
}

static int fq_codel_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct jens_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
	opts = nla_nest_start(skb, TCA_OPTIONS);
#else
	opts = nla_nest_start_noflag(skb, TCA_OPTIONS);
#endif
	if (opts == NULL)
		goto nla_put_failure;

	if (q->nouseport &&
	    nla_put_flag(skb, TCA_JENS_NOUSEPORT))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_JENS_TARGET,
			codel_time_to_us(q->cparams.target)) ||
	    nla_put_u32(skb, TCA_JENS_LIMIT,
			sch->limit) ||
	    nla_put_u32(skb, TCA_JENS_INTERVAL,
			codel_time_to_us(q->cparams.interval)) ||
	    nla_put_u32(skb, TCA_JENS_MARKFREE,
			codel_time_to_us(q->cparams.markfree)) ||
	    nla_put_u32(skb, TCA_JENS_MARKFULL,
			codel_time_to_us(q->cparams.markfull)) ||
	    nla_put_u32(skb, TCA_JENS_QUANTUM,
			q->quantum) ||
	    nla_put_u32(skb, TCA_JENS_DROP_BATCH_SIZE,
			q->drop_batch_size) ||
	    nla_put_u32(skb, TCA_JENS_SUBBUFS,
			q->cparams.subbufs) ||
	    nla_put_u32(skb, TCA_JENS_MEMORY_LIMIT,
			q->memory_limit) ||
	    nla_put_u32(skb, TCA_JENS_FLOWS,
			q->flows_cnt))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);

nla_put_failure:
	return -1;
}

static int fq_codel_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct jens_sched_data *q = qdisc_priv(sch);
	struct tc_jens_xstats st = {
		.type				= TCA_JENS_XSTATS_QDISC,
	};
	struct list_head *pos;

	st.qdisc_stats.maxpacket = q->cstats.maxpacket;
	st.qdisc_stats.drop_overlimit = q->drop_overlimit;
	st.qdisc_stats.ecn_mark = q->cstats.ecn_mark;
	st.qdisc_stats.new_flow_count = q->new_flow_count;
	st.qdisc_stats.ce_mark = q->cstats.ce_mark;
	st.qdisc_stats.memory_usage  = q->memory_usage;
	st.qdisc_stats.drop_overmemory = q->drop_overmemory;

	sch_tree_lock(sch);
	list_for_each(pos, &q->new_flows)
		st.qdisc_stats.new_flows_len++;

	list_for_each(pos, &q->old_flows)
		st.qdisc_stats.old_flows_len++;
	sch_tree_unlock(sch);

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static struct Qdisc *fq_codel_leaf(struct Qdisc *sch, unsigned long arg)
{
	return NULL;
}

static unsigned long fq_codel_find(struct Qdisc *sch, u32 classid)
{
	return 0;
}

static unsigned long fq_codel_bind(struct Qdisc *sch, unsigned long parent,
			      u32 classid)
{
	return 0;
}

static void fq_codel_unbind(struct Qdisc *q, unsigned long cl)
{
}

static struct tcf_block *fq_codel_tcf_block(struct Qdisc *sch, unsigned long cl,
					    struct netlink_ext_ack *extack)
{
	struct jens_sched_data *q = qdisc_priv(sch);

	if (cl)
		return NULL;
	return q->block;
}

static int fq_codel_dump_class(struct Qdisc *sch, unsigned long cl,
			  struct sk_buff *skb, struct tcmsg *tcm)
{
	tcm->tcm_handle |= TC_H_MIN(cl);
	return 0;
}

static int fq_codel_dump_class_stats(struct Qdisc *sch, unsigned long cl,
				     struct gnet_dump *d)
{
	struct jens_sched_data *q = qdisc_priv(sch);
	u32 idx = cl - 1;
	struct gnet_stats_queue qs = { 0 };
	struct tc_jens_xstats xstats;

	if (idx < q->flows_cnt) {
		const struct fq_codel_flow *flow = &q->flows[idx];
		const struct sk_buff *skb;

		memset(&xstats, 0, sizeof(xstats));
		xstats.type = TCA_JENS_XSTATS_CLASS;
		xstats.class_stats.deficit = flow->deficit;
		xstats.class_stats.ldelay =
			codel_time_to_us(flow->cvars.ldelay);
		xstats.class_stats.count = flow->cvars.count;
		xstats.class_stats.lastcount = flow->cvars.lastcount;
		xstats.class_stats.dropping = flow->cvars.dropping;
		if (flow->cvars.dropping) {
			codel_tdiff_t delta = flow->cvars.drop_next -
					      codel_get_time();

			xstats.class_stats.drop_next = (delta >= 0) ?
				codel_time_to_us(delta) :
				-codel_time_to_us(-delta);
		}
		if (flow->head) {
			sch_tree_lock(sch);
			skb = flow->head;
			while (skb) {
				qs.qlen++;
				skb = skb->next;
			}
			sch_tree_unlock(sch);
		}
		qs.backlog = q->backlogs[idx];
		qs.drops = 0;
	}
	if (gnet_stats_copy_queue(d, NULL, &qs, qs.qlen) < 0)
		return -1;
	if (idx < q->flows_cnt)
		return gnet_stats_copy_app(d, &xstats, sizeof(xstats));
	return 0;
}

static void fq_codel_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
	struct jens_sched_data *q = qdisc_priv(sch);
	unsigned int i;

	if (arg->stop)
		return;

	for (i = 0; i < q->flows_cnt; i++) {
		if (list_empty(&q->flows[i].flowchain) ||
		    arg->count < arg->skip) {
			arg->count++;
			continue;
		}
		if (arg->fn(sch, i + 1, arg) < 0) {
			arg->stop = 1;
			break;
		}
		arg->count++;
	}
}

static const struct Qdisc_class_ops fq_codel_class_ops = {
	.leaf		=	fq_codel_leaf,
	.find		=	fq_codel_find,
	.tcf_block	=	fq_codel_tcf_block,
	.bind_tcf	=	fq_codel_bind,
	.unbind_tcf	=	fq_codel_unbind,
	.dump		=	fq_codel_dump_class,
	.dump_stats	=	fq_codel_dump_class_stats,
	.walk		=	fq_codel_walk,
};

static struct Qdisc_ops fq_codel_qdisc_ops __read_mostly = {
	.cl_ops		=	&fq_codel_class_ops,
	.id		=	"jens",
	.priv_size	=	sizeof(struct jens_sched_data),
	.enqueue	=	fq_codel_enqueue,
	.dequeue	=	jens_dequeue_fq,
	.peek		=	qdisc_peek_dequeued,
	.init		=	fq_codel_init,
	.reset		=	fq_codel_reset,
	.destroy	=	fq_codel_destroy,
	.change		=	fq_codel_change,
	.dump		=	fq_codel_dump,
	.dump_stats	=	fq_codel_dump_stats,
	.owner		=	THIS_MODULE,
};

static int __init fq_codel_module_init(void)
{
	int rv;

	if (!(jens_debugfs_main = debugfs_create_dir("sch_jens", NULL)))
		rv = -ENOSYS;
	else
		rv = PTR_ERR_OR_ZERO(jens_debugfs_main);
	if (rv == -ENODEV) {
		jens_debugfs_main = NULL;
		printk(KERN_WARNING "sch_jens: debugfs not available, disabling\n");
	} else if (rv) {
		jens_debugfs_main = NULL;
		printk(KERN_WARNING "sch_jens: debugfs initialisation error\n");
		goto e0;
	}

	rv = register_qdisc(&fq_codel_qdisc_ops);

	if (rv)
		debugfs_remove(jens_debugfs_main);

 e0:
	return (rv);
}

static void __exit fq_codel_module_exit(void)
{
	unregister_qdisc(&fq_codel_qdisc_ops);
	debugfs_remove(jens_debugfs_main);
}

module_init(fq_codel_module_init)
module_exit(fq_codel_module_exit)
MODULE_AUTHOR("Deutsche Telekom LLCTO");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("packet scheduler for JENS");

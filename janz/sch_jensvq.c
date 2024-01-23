/*
 * JENS virtual queue-based marking real queue-based delimiting multi-UE qdisc
 *
 * Copyright © 2022, 2023 mirabilos <t.glaser@tarent.de>
 * Copyright © 2024 mirabilos <t.glaser@qvest-digital.com>
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

#include "mbsdcc.h"
#include "janz_uapi.h"
#include "gru32b.h"

#define nsmul(val, fac) ((u64)((u64)(val) * (u64)(fac)))

#define xinline inline __attribute__((__always_inline__))

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
 mbCTA(srcip, mbccFSZ(struct jensvq_relay, srcip) == 16U);
 mbCTA(dstip, mbccFSZ(struct jensvq_relay, dstip) == 16U);
 mbCTA(sd_r, offsetof(struct jensvq_relay, dstip) == (offsetof(struct jensvq_relay, srcip) + 16U));
 mbCTA(sd_f, offsetof(struct janz_fragcomp, dip) == (offsetof(struct janz_fragcomp, sip) + 16U));
mbCTA_END(janz_fragcache_check);

/* workaround to relay_close late using the global workqueue */
struct janz_gwq_ovl {
	struct delayed_work dwork;
	struct rchan *record_chan;
};

/* per-packet extra data overflow buffer */
/* struct janz_cb *cb = get_cb(skb, q); */
struct janz_cb {
	struct in6_addr srcip;							//@=0
	struct in6_addr dstip;							//@=16
	struct janz_cb *next;	/* freelist chaining */				//@=32
	u64 ts_arrive;		/* arrival time of packet, for owd */		//@=40
	u64 ts_enq;		/* (virtual) enqueue timestamp, +xlatency */	//@=48
	u16 sport;								//@=56
	u16 dport;								//@=58
	u8 nexthdr;								//@=60
	u8 ipver:2;								//@=61
	u8 rexnum:3;
	u8 rextot:3;
	u8 mark:1;								//@=62
	u8 ecnval:1;
	u8 ecnenq:2;
	u8 ecndeq:2;
	u8 drop:1;
	u8 bypass:1;
	u8 uenum:3;								//@=63
};

/* per-packet extra data, in-skb buffer */
/* struct janz_skb *cx = get_cx(skb); */
struct janz_skb {
	/* limited to QDISC_CB_PRIV_LEN (20) bytes! */
	u64 vqdelay;
	u64 rqdelay;
	unsigned short janz_cb_num;
	u8 tosbyte;
} __attribute__((__packed__));

/* an SKB (packet) queue */
struct janz_skbfifo {
	struct sk_buff *first;
	struct sk_buff *last;
};

/* per-UE data */
struct jensvq_perue {
	struct janz_skbfifo q;		/* FIFO */					//@16 :16
#define DROPCHK_INTERVAL nsmul(200, NSEC_PER_MSEC)
	u64 drop_next;			/* next time to check drops */			//@16
	u64 notbefore;			/* next time to send at earliest */		//   +8
	u32 pktlensum;			/* all packets in q → size */			//@16
	u16 pktnum;			/* all packets in q → count */			//   +4
	unsigned int crediting:1;	/* backdating allowed? */			//   +8
};

/* per-qdisc data */
/* struct jensvq_qd *q = qdisc_priv(sch); */
struct jensvq_qd {
	struct jensvq_perue ue[JENSVQ_NUE];						//@16
	struct {
		struct jensvq_ldue {
			u64 vrate;	/* packet marking tgt bandwidth */		//@16
			u64 rrate;	/* traffic shaping tgt bandwidth */		//   +8
		} ue[JENSVQ_NUE];
	} latchdata[2];									//@16
	seqcount_latch_t latch;		/* for latchdata */				//@16:4 (?)
	raw_spinlock_t record_lock;	/* for record_chan */				// +4:4 (?)
	struct rchan *record_chan;	/* relay to userspace */			//@8
	struct janz_fragcache *fragcache_base;						//@8 (?@16)
	struct janz_fragcache *fragcache_free;						//@8
	struct janz_fragcache *fragcache_used;						//@8
	struct janz_fragcache *fragcache_last;	/* last used element */			//@8
	struct janz_cb *cb_base;	/* num = sch->limit ≤ 32767 */			//@8 (?@16)
	struct janz_cb *cb_free;							//@8
	struct janz_skbfifo byp;	/* bypass queue FIFO */				//@8 (?@16)
	u64 markfree;			/* marking lower limit */			//@8 (?@16)
	u64 markfull;			/* marking upper limit */			//@8
	u64 xlatency;			/* extralatency */				//@8 (?@16)
	struct dentry *ctlfile;		/* bandwidth setting i/f */			//@8
	u64 fragcache_aged;								//@8 (?@16)
	u32 fragcache_num;		/* nelts(fragcache_base) */			//@8
	u32 nsubbufs;			/* for record_chan */				//  +4
	u32 byplensum;									//@8 (?@16)
	u16 bypnum;									//  +4
	u8 uecur;									//  +6
	struct qdisc_watchdog watchdog;	/* to schedule when traffic shaping */		//?@8
};

/* compile-time assertions */
mbCTA_BEG(jensvq_structs_check);
 mbCTA(cb_s, sizeof(struct janz_cb) == 64U);
 mbCTA(cx_s, sizeof(struct janz_skb) == 19U);
 mbCTA(cx_o1, offsetof(struct janz_skb, rqdelay) == 8U);
 mbCTA(cx_o2, offsetof(struct janz_skb, janz_cb_num) == 16U);
 mbCTA(cx_o3, offsetof(struct janz_skb, tosbyte) == 18U);
mbCTA_END(jensvq_structs_check);

static xinline u64 us_to_ns(u32 us);
static xinline u64 ns_to_us(u64 ns);

static xinline struct janz_cb *get_cb(const struct sk_buff *skb, struct jensvq_qd *q);
static xinline struct janz_skb *get_cx(const struct sk_buff *skb);
static xinline struct jensvq_ldue jensvq_readlatch(struct jensvq_qd *q, int ue);

static xinline void janz_reset(struct Qdisc *sch, bool initial);
static xinline int janz_chg(struct Qdisc *, struct nlattr *, struct netlink_ext_ack *, bool);

static int __init janz_modinit(void);
static void __exit janz_modexit(void);
static int janz_enq(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free);
static struct sk_buff *janz_deq(struct Qdisc *sch);
static struct sk_buff *janz_peek(struct Qdisc *sch);
static int janz_init(struct Qdisc *sch, struct nlattr *opt, struct netlink_ext_ack *extack);
static void janz_reset_noinline(struct Qdisc *sch);
static void janz_done(struct Qdisc *sch);
static int janz_chg_noinline(struct Qdisc *sch, struct nlattr *opt, struct netlink_ext_ack *extack);
static int janz_dump(struct Qdisc *sch, struct sk_buff *skb);

static struct dentry *janz_debugfs_create(const char *filename, struct dentry *parent,
    umode_t mode, struct rchan_buf *buf, int *is_global);
static int janz_debugfs_destroy(struct dentry *dentry);
static int janz_subbuf_init(struct rchan_buf *buf, void *subbuf,
    void *prev_subbuf, size_t prev_padding);
static ssize_t janz_ctlfile_write(struct file *filp, const char __user *buf,
    size_t count, loff_t *posp);
static void janz_gwq_fn(struct work_struct *work);

module_init(janz_modinit);
module_exit(janz_modexit);
MODULE_AUTHOR("Deutsche Telekom LLCTO");
MODULE_LICENSE("GPL");
#define janzmoddesc_bs "bespoke multi-UE egress traffic scheduler for the JENS network simulator"
#ifdef VQ_USE_FOR_DROPS
#define janzmoddesc_qd ", drops from virtual queue"
#else
#define janzmoddesc_qd ", drops from real queue"
#endif
MODULE_DESCRIPTION(janzmoddesc_bs janzmoddesc_qd);

static struct Qdisc_ops janz_ops __read_mostly = {
	.id		= "jensvq",
	.priv_size	= sizeof(struct jensvq_qd),
	.enqueue	= janz_enq,
	.dequeue	= janz_deq,
	.peek		= janz_peek,
	.init		= janz_init,
	.reset		= janz_reset_noinline,
	.destroy	= janz_done,
	.change		= janz_chg_noinline,
	.dump		= janz_dump,
	.owner		= THIS_MODULE
};

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

static const struct nla_policy janz_nla_policy[TCA_JENSVQ_MAX + 1] = {
	[TCA_JENSVQ_LIMIT]	= { .type = NLA_U32 },
	[TCA_JENSVQ_MARKFREE]	= { .type = NLA_U32 },
	[TCA_JENSVQ_MARKFULL]	= { .type = NLA_U32 },
	[TCA_JENSVQ_SUBBUFS]	= { .type = NLA_U32 },
	[TCA_JENSVQ_FRAGCACHE]	= { .type = NLA_U32 },
	[TCA_JENSVQ_XLATENCY]	= { .type = NLA_U32 },
};

static xinline u64
us_to_ns(u32 us)
{
	return (nsmul(us, NSEC_PER_USEC));
}

static xinline u64
ns_to_us(u64 ns)
{
	return (div_u64(ns, NSEC_PER_USEC));
}

static xinline struct janz_cb *
get_cb(const struct sk_buff *skb, struct jensvq_qd *q)
{
	return (&(q->cb_base[get_cx(skb)->janz_cb_num]));
}

static xinline struct janz_skb *
get_cx(const struct sk_buff *skb)
{
	qdisc_cb_private_validate(skb, sizeof(struct janz_skb));
	return ((struct janz_skb *)qdisc_skb_cb(skb)->data);
}

static xinline struct jensvq_ldue
jensvq_readlatch(struct jensvq_qd *q, int ue)
{
	struct jensvq_ldue res;
	unsigned int seq;

	do {
		seq = raw_read_seqcount_latch(&q->latch);
		res.vrate = q->latchdata[seq & 1].ue[ue].vrate;
		res.rrate = q->latchdata[seq & 1].ue[ue].rrate;
	} while (read_seqcount_latch_retry(&q->latch, seq));

	return (res);
}

static void
janz_reset_noinline(struct Qdisc *sch)
{
	janz_reset(sch, false);
}

static int
janz_chg_noinline(struct Qdisc *sch, struct nlattr *opt, struct netlink_ext_ack *extack)
{
	return (janz_chg(sch, opt, extack, false));
}

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
		pr_err("could not initialise debugfs\n");
		return (rv);
	}

	rv = register_qdisc(&janz_ops);
	if (rv) {
		debugfs_remove(janz_debugfs_main);
		return (rv);
	}

	return (0);
}

static void __exit
janz_modexit(void)
{
	unregister_qdisc(&janz_ops);
	debugfs_remove(janz_debugfs_main);
}

static int
janz_init(struct Qdisc *sch, struct nlattr *opt, struct netlink_ext_ack *extack)
{
	struct jensvq_qd *q = qdisc_priv(sch);
	int rv;
	unsigned int i;
	u64 t;
	char name[12];

	/* lock and watchdog initialisation */
	seqcount_latch_init(&q->latch);
	raw_spin_lock_init(&q->record_lock);
	qdisc_watchdog_init_clockid(&q->watchdog, sch, CLOCK_MONOTONIC);
	/* default configuration values */
	sch->limit = 10240;
	q->markfree = nsmul(4, NSEC_PER_MSEC);
	q->markfull = nsmul(14, NSEC_PER_MSEC);
	q->xlatency = 0;
	q->fragcache_num = 1024U;
	q->nsubbufs = 2048U;
	/* qdisc state */
	sch->q.qlen = 0;
	q->record_chan = NULL;
	q->fragcache_base = NULL;
	q->cb_base = NULL;
	q->ctlfile = NULL;
	q->uecur = 0;

	if ((rv = janz_chg(sch, opt, extack, true)))
		goto init_fail;
	janz_reset(sch, true);

	if (!(q->fragcache_base = kvcalloc(q->fragcache_num,
	    sizeof(struct janz_fragcache), GFP_KERNEL))) {
		NL_SET_ERR_MSG_MOD(extack, "not enough memory for fragcache");
		rv = -ENOMEM;
		goto init_fail;
	}
	q->fragcache_used = NULL;
	q->fragcache_last = NULL;
	q->fragcache_free = &(q->fragcache_base[0]);
	for (i = 1; i < q->fragcache_num; ++i)
		q->fragcache_base[i - 1].next = &(q->fragcache_base[i]);
	q->fragcache_base[q->fragcache_num - 1].next = NULL;
	q->fragcache_aged = 0;

	if (!(q->cb_base = kvcalloc(sch->limit,
	    sizeof(struct janz_cb), GFP_KERNEL))) {
		NL_SET_ERR_MSG_MOD(extack, "not enough memory for per-packet data");
		rv = -ENOMEM;
		goto init_fail;
	}
	q->cb_free = &(q->cb_base[0]);
	for (i = 1; i < sch->limit; ++i)
		q->cb_base[i - 1].next = &(q->cb_base[i]);

	snprintf(name, sizeof(name), "%04X:v2-",
	    (unsigned int)(sch->handle >> 16));
	if (!(q->record_chan = relay_open(name, janz_debugfs_main,
	    TC_JENSVQ_RELAY_SUBBUFSZ, q->nsubbufs,
	    &janz_debugfs_relay_hooks, sch))) {
		NL_SET_ERR_MSG_MOD(extack, "relay channel creation failed");
		rv = -ENOENT;
		goto init_fail;
	}
	snprintf(name, sizeof(name), "%04X:v2-c",
	    (unsigned int)(sch->handle >> 16));
	q->ctlfile = debugfs_create_file(name, 0200, janz_debugfs_main,
	    q, &janz_ctlfile_fops);
	if (IS_ERR_OR_NULL(q->ctlfile)) {
		rv = q->ctlfile ? PTR_ERR(q->ctlfile) : -ENOENT;
		q->ctlfile = NULL;
		NL_SET_ERR_MSG_MOD(extack, "control channel creation failed");
		goto init_fail;
	}
	d_inode(q->ctlfile)->i_size = sizeof(struct jensvq_ctlfile_pkt);

	t = ktime_get_ns() + DROPCHK_INTERVAL;
	for (i = 0; i < JENSVQ_NUE; ++i)
		q->ue[i].drop_next = t;

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
	if (q->cb_base) {
		kvfree(q->cb_base);
		q->cb_base = NULL;
	}
	if (q->fragcache_base) {
		kvfree(q->fragcache_base);
		q->fragcache_base = NULL;
	}
	return (rv);
}

/* when live, janz_reset is called first to free the packets */
static void
janz_done(struct Qdisc *sch)
{
	struct jensvq_qd *q = qdisc_priv(sch);
	struct janz_gwq_ovl *ovl;

	qdisc_watchdog_cancel(&q->watchdog);

	if (q->ctlfile) {
		debugfs_remove(q->ctlfile);
		q->ctlfile = NULL;
	}
	if (q->record_chan && q->fragcache_base) {
		/* use fragcache memory for delayed work queue */
		ovl = (void *)q->fragcache_base;
		q->fragcache_base = NULL;
		ovl->record_chan = q->record_chan;
		q->record_chan = NULL;
		INIT_DELAYED_WORK(&ovl->dwork, janz_gwq_fn);
		relay_flush(ovl->record_chan);
		schedule_delayed_work(&ovl->dwork, msecs_to_jiffies(800));
	}
	if (q->record_chan) {
		pr_alert("could not flush report channel\n");
		relay_close(q->record_chan);
		q->record_chan = NULL;
	}
	if (q->cb_base) {
		kvfree(q->cb_base);
		q->cb_base = NULL;
	}
	if (q->fragcache_base) {
		kvfree(q->fragcache_base);
		q->fragcache_base = NULL;
	}
}

static void
janz_gwq_fn(struct work_struct *work)
{
	struct janz_gwq_ovl *ovl = container_of(to_delayed_work(work),
	    struct janz_gwq_ovl, dwork);

	relay_close(ovl->record_chan);
	kvfree(ovl);
}

static xinline void
janz_reset(struct Qdisc *sch, bool initial)
{
	struct jensvq_qd *q = qdisc_priv(sch);
	unsigned int i;

	ASSERT_RTNL();
	if (sch->q.qlen && !initial) {
		for (i = 0; i < JENSVQ_NUE; ++i)
			rtnl_kfree_skbs(q->ue[i].q.first, q->ue[i].q.last);
		rtnl_kfree_skbs(q->byp.first, q->byp.last);
	}
	sch->q.qlen = 0;
	for (i = 0; i < JENSVQ_NUE; ++i) {
		q->ue[i].q.first = NULL;
		q->ue[i].q.last = NULL;
		q->ue[i].notbefore = 0;
		q->ue[i].pktlensum = 0;
		q->ue[i].pktnum = 0;
		q->ue[i].crediting = 0;
		/* 10 Mbit/s */
		q->latchdata[0].ue[i].vrate = 800;
		q->latchdata[0].ue[i].rrate = 800;
		q->latchdata[1].ue[i].vrate = 800;
		q->latchdata[1].ue[i].rrate = 800;
	}
	q->byp.first = NULL;
	q->byp.last = NULL;
	q->byplensum = 0;
	q->bypnum = 0;
	sch->qstats.backlog = 0;
	sch->qstats.overlimits = 0;
	if (q->record_chan && !initial)
		relay_flush(q->record_chan);
}

static xinline int
janz_chg(struct Qdisc *sch, struct nlattr *opt,
    struct netlink_ext_ack *extack, bool initial)
{
	struct jensvq_qd *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_JENSVQ_MAX + 1];
	int rv;
	u32 newlimit = 0;
	u32 newsubbufs = 0;
	u32 newfragnum = 0;
	u64 newxlatency = 0;

	if (!opt)
		return (-EINVAL);

	if ((rv = nla_parse_nested_deprecated(tb, TCA_JENSVQ_MAX, opt,
	    janz_nla_policy, extack)) < 0)
		return (rv);

	/* anything that can throw first */

	if (!initial) {
		/* permit no-change calls for c/p from tc output */
		if (tb[TCA_JENSVQ_LIMIT] &&
		    nla_get_u32(tb[TCA_JENSVQ_LIMIT]) != sch->limit)
			goto notatinit;
		if (tb[TCA_JENSVQ_SUBBUFS] &&
		    nla_get_u32(tb[TCA_JENSVQ_SUBBUFS]) != q->nsubbufs)
			goto notatinit;
		if (tb[TCA_JENSVQ_FRAGCACHE] &&
		    nla_get_u32(tb[TCA_JENSVQ_FRAGCACHE]) != q->fragcache_num)
			goto notatinit;
	}

	if (tb[TCA_JENSVQ_LIMIT]) {
		newlimit = nla_get_u32(tb[TCA_JENSVQ_LIMIT]);
		if (newlimit < 8U) {
			NL_SET_ERR_MSG_MOD(extack, "limit too small (minimum 8)");
			return (-EINVAL);
		}
		if (newlimit > 32767U) {
			NL_SET_ERR_MSG_MOD(extack, "limit too large (maximum 32767)");
			return (-EINVAL);
		}
	}

	if (tb[TCA_JENSVQ_SUBBUFS]) {
		newsubbufs = nla_get_u32(tb[TCA_JENSVQ_SUBBUFS]);
		if (newsubbufs < 4U) {
			NL_SET_ERR_MSG_MOD(extack, "subbufs too small (minimum 4)");
			return (-EINVAL);
		}
		if (newsubbufs > 0x000FFFFFU) {
			NL_SET_ERR_MSG_MOD(extack, "subbufs too large (maximum 1Mi-1)");
			return (-EINVAL);
		}
	}

	if (tb[TCA_JENSVQ_FRAGCACHE]) {
		newfragnum = nla_get_u32(tb[TCA_JENSVQ_FRAGCACHE]);
		if (newfragnum < 16U) {
			NL_SET_ERR_MSG_MOD(extack, "fragcache too small (minimum 16)");
			return (-EINVAL);
		}
		if (newfragnum > 0x00FFFFFFU) {
			NL_SET_ERR_MSG_MOD(extack, "fragcache too large (maximum 16Mi-1)");
			return (-EINVAL);
		}
	}

	if (tb[TCA_JENSVQ_XLATENCY]) {
		newxlatency = us_to_ns(nla_get_u32(tb[TCA_JENSVQ_XLATENCY]));
		if (newxlatency > nsmul(2, NSEC_PER_SEC)) {
			NL_SET_ERR_MSG_MOD(extack, "extralatency too large (maximum 2s)");
			return (-EINVAL);
		}
	}

	/* now actual configuring */
	sch_tree_lock(sch);
	/* no memory allocation, returns, etc. now */

	if (tb[TCA_JENSVQ_LIMIT])
		sch->limit = newlimit;

	if (tb[TCA_JENSVQ_MARKFREE])
		q->markfree = us_to_ns(nla_get_u32(tb[TCA_JANZ_MARKFREE]));

	if (tb[TCA_JENSVQ_MARKFULL])
		q->markfull = us_to_ns(nla_get_u32(tb[TCA_JANZ_MARKFULL]));

	if (tb[TCA_JENSVQ_SUBBUFS])
		q->nsubbufs = newsubbufs;

	if (tb[TCA_JENSVQ_FRAGCACHE])
		q->fragcache_num = newfragnum;

	if (tb[TCA_JENSVQ_XLATENCY])
		q->xlatency = newxlatency;

	sch_tree_unlock(sch);
	return (0);

 notatinit:
	NL_SET_ERR_MSG_MOD(extack, "limit, subbufs and fragcache can only be set at initialisation time");
	return (-EINVAL);
}

static int
janz_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct jensvq_qd *q = qdisc_priv(sch);
	struct nlattr *opts;

	opts = nla_nest_start(skb, TCA_OPTIONS);
	if (opts == NULL)
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_JENSVQ_MARKFREE, ns_to_us(q->markfree)) ||
	    nla_put_u32(skb, TCA_JENSVQ_MARKFULL, ns_to_us(q->markfull)) ||
	    nla_put_u32(skb, TCA_JENSVQ_SUBBUFS, q->nsubbufs) ||
	    nla_put_u32(skb, TCA_JENSVQ_FRAGCACHE, q->fragcache_num) ||
	    nla_put_u32(skb, TCA_JENSVQ_XLATENCY, ns_to_us(q->xlatency)) ||
	    nla_put_u32(skb, TCA_JENSVQ_LIMIT, sch->limit))
		goto nla_put_failure;

	return (nla_nest_end(skb, opts));

 nla_put_failure:
	return (-1);
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
janz_subbuf_init(struct rchan_buf *buf, void *subbuf,
    void *prev_subbuf, size_t prev_padding)
{
	memset(subbuf, '\0', TC_JENSVQ_RELAY_SUBBUFSZ);
	return (1);
}

static struct sk_buff *
janz_peek(struct Qdisc *sch)
{
	struct jensvq_qd *q = qdisc_priv(sch);
	u64 then;
	unsigned int i;

	pr_warn(".peek called; this is not supported!\n");
	dump_stack();
	/* delay traffic noticeably, so the user knows to look */
	then = ktime_get_ns() + NSEC_PER_SEC;
	for (i = 0; i < JENSVQ_NUE; ++i) {
		if (q->ue[i].notbefore < then)
			q->ue[i].notbefore = then;
		q->ue[i].crediting = 0;
	}
	/* hard reply no packet to now send */
	return (NULL);
}

static ssize_t
janz_ctlfile_write(struct file *filp, const char __user *buf,
    size_t count, loff_t *posp)
{
	u64 r;
	unsigned int i, j;
	struct jensvq_qd *q = filp->private_data;
	struct jensvq_ctlfile_pkt data;

	if (count != sizeof(data))
		return (-EINVAL);
	if (copy_from_user(&data, buf, sizeof(data)))
		return (-EFAULT);

	/* transform data to expected internal format first */
	for (i = 0; i < JENSVQ_NUE; ++i) {
		if (!data.ue[i].rq_bps) {
			/* handover signalling */
			if (data.ue[i].vq_bps > nsmul(3600, NSEC_PER_SEC))
				return (-EBADSLT);
			data.ue[i].vq_bps += ktime_get_ns();
		} else {
			/* convert to ns/byte */
			r = div64_u64(8ULL * NSEC_PER_SEC,
			    data.ue[i].vq_bps);
			if (r < 1U)
				r = 1U;
			data.ue[i].vq_bps = r;
			r = div64_u64(8ULL * NSEC_PER_SEC,
			    data.ue[i].rq_bps);
			if (r < 1U)
				r = 1U;
			data.ue[i].rq_bps = r;
		}
	}

	/* now infill */
	for (j = 0; j <= 1; ++j) {
		raw_write_seqcount_latch(&q->latch);
		for (i = 0; i < JENSVQ_NUE; ++i) {
			q->latchdata[j].ue[i].vrate = data.ue[i].vq_bps;
			q->latchdata[j].ue[i].rrate = data.ue[i].rq_bps;
		}
	}

	return (sizeof(data));
}

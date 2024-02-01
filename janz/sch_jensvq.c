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
#undef JANZ_DEV_DEBUG

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

#ifdef JANZ_DEV_DEBUG
#define JANZDBG 1
#else
#define JANZDBG 0
#endif
#define JTFMT "%lu.%06u"
#define jtfmt(x) (unsigned long)((u64)(x) / 1000000000UL), \
		 (unsigned int)(((u64)(x) % 1000000000UL) / 1000U)

#if 0
#define checked_dec(var) do {						\
	--(var);							\
} while (/* CONSTCOND */ 0)
#else
#define checked_dec(var) do {						\
	if (unlikely(!(var))) {						\
		pr_err("trying to decrease %s from 0 in %s:%d\n",	\
		    mbccS(var), __FILE__, __LINE__);			\
		dump_stack();						\
		break;							\
	}								\
	--(var);							\
} while (/* CONSTCOND */ 0)
#endif

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
/* struct janz_cb *cb = get_cb(cx, q); */
struct janz_cb {
	struct in6_addr srcip;							//@=0
	struct in6_addr dstip;							//@=16
	struct janz_cb *next;	/* freelist chaining */				//@=32
	u64 ts_enq;		/* enqueue time of packet, for owd */		//@=40
	u64 ts_arrive;		/* (virtual) arrival timestamp, +xlatency */	//@=48
				/* if rextot: ts of next xmit attempt */
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
	struct janz_skbfifo rexmits;	/* retransmission loop */			//@16 :16
#define DROPCHK_INTERVAL nsmul(200, NSEC_PER_MSEC)
	u64 drop_next;			/* next time to check drops */			//@16
	u64 rq_notbefore;		/* next time to send at earliest */		//   +8
	u64 vq_notbefore;		/* virtual queue tracking */			//@16
	u32 pktlensum;			/* all packets in q+rexmits → size */		//   +8
	u16 pktnum;			/* all packets in q+rexmits → count */		//   +12
	u8 crediting:1;			/* backdating allowed? */			//   +14
};

/* per-qdisc data */
/* struct jensvq_qd *q = qdisc_priv(sch); */
struct jensvq_qd {
	struct jensvq_perue ue[JENSVQ_NUE];						//@16
	struct {
		struct jensvq_ldue {
			u64 vrate;	/* packet marking tgt bandwidth */		//@16
			u64 rrate;	/* traffic shaping tgt bandwidth */		//   +8
			u64 hover;	/* handover timestamp */			//   +16
			u64 _pad;							//   +24
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
#ifdef JANZ_DEV_DEBUG
	u8 dbg_mnext:1;									//  +7:⅛
#endif
	struct qdisc_watchdog watchdog;	/* to schedule when traffic shaping */		//?@8
};

/* compile-time assertions */
mbCTA_BEG(jensvq_structs_check);
 mbCTA(pue, sizeof(struct jensvq_perue) <= 64U);
 mbCTA(cb_s, sizeof(struct janz_cb) == 64U);
 mbCTA(cx_s, sizeof(struct janz_skb) == 19U);
 mbCTA(cx_o1, offsetof(struct janz_skb, rqdelay) == 8U);
 mbCTA(cx_o2, offsetof(struct janz_skb, janz_cb_num) == 16U);
 mbCTA(cx_o3, offsetof(struct janz_skb, tosbyte) == 18U);
 mbCTA(cb_sd, offsetof(struct janz_cb, dstip) == (offsetof(struct janz_cb, srcip) + 16U));
mbCTA_END(jensvq_structs_check);

static xinline u64 us_to_ns(u32 us) __attribute_const__;
static xinline u64 ns_to_us(u64 ns) __attribute_const__;

static xinline u64 bps_to_nspby(u64 bps) __attribute_const__;
static xinline u64 nspby_to_bps(u64 rate) __attribute_const__;

static xinline u32 vpktlen(u32 rpktlen) __attribute_const__;

static xinline struct janz_cb *get_cb(const struct janz_skb *cx, struct jensvq_qd *q) __pure;
static xinline struct janz_skb *get_cx(const struct sk_buff *skb) __pure;
static xinline struct jensvq_ldue jensvq_readlatch(struct jensvq_qd *q, int ue);

static xinline void janz_reset(struct Qdisc *sch, bool initial);
static xinline int janz_chg(struct Qdisc *, struct nlattr *, struct netlink_ext_ack *, bool);
static xinline int janz_enq(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free);
static xinline struct sk_buff *janz_deq(struct Qdisc *sch);

static int __init janz_modinit(void);
static void __exit janz_modexit(void);
static int janz_enq_noinline(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free);
static struct sk_buff *janz_deq_noinline(struct Qdisc *sch);
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
static xinline void janz_record_write(struct jensvq_relay *record, struct jensvq_qd *q);
static ssize_t janz_ctlfile_write(struct file *filp, const char __user *buf,
    size_t count, loff_t *posp);
static void janz_gwq_fn(struct work_struct *work);

static xinline bool janz_analyse(struct Qdisc *sch, struct jensvq_qd *q,
    struct sk_buff *skb, struct janz_skb *cx, struct janz_cb *cb, u64 now);
static xinline void janz_fragcache_maint(struct jensvq_qd *q, u64 now);

static xinline void janz_record_handover(struct Qdisc *sch, struct jensvq_qd *q,
    u64 now, u64 notbefore, unsigned int ue);
static xinline void janz_record_packet(struct Qdisc *sch, struct jensvq_qd *q,
    struct sk_buff *skb, struct janz_skb *cx, struct janz_cb *cb, u64 now,
    u64 vbw, u64 rbw, int what /* 1=normal 2=drop 3=bypass */);
static xinline void janz_record_enqdrop(struct Qdisc *sch, struct jensvq_qd *q,
    struct sk_buff *skb, u64 now, unsigned int ue);

static xinline void janz_drop1(struct Qdisc *sch, struct jensvq_qd *q,
    u64 now, const char *why, unsigned int ue);

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
	.enqueue	= janz_enq_noinline,
	.dequeue	= janz_deq_noinline,
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

static xinline u64
bps_to_nspby(u64 bps)
{
	return (max(div64_u64(8ULL * NSEC_PER_SEC, bps), 1ULL));
}

static xinline u64
nspby_to_bps(u64 rate)
{
	return (max(div64_u64(8ULL * NSEC_PER_SEC, rate), 1ULL));
}

/* to limit for accounting to prevent overflows */
static xinline u32
vpktlen(u32 rpktlen)
{
	return (rpktlen > 131071U ? 131071U : rpktlen);
}

static xinline struct janz_cb *
get_cb(const struct janz_skb *cx, struct jensvq_qd *q)
{
	return (&(q->cb_base[cx->janz_cb_num]));
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
		res.hover = q->latchdata[seq & 1].ue[ue].hover;
		// don’t bother with _pad
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

static xinline void
janz_record_handover(struct Qdisc *sch, struct jensvq_qd *q,
    u64 now, u64 notbefore, unsigned int ue)
{
	struct jensvq_relay r = {0};

	r.vts = now;
	r.flags = JENS_FMK(JENSVQ_Ftype, 2);
	r.upkts = q->ue[ue].pktnum;
	r.ubytes = q->ue[ue].pktlensum;
	r.vbw = notbefore;
	janz_record_write(&r, q);
}

static int
janz_init(struct Qdisc *sch, struct nlattr *opt, struct netlink_ext_ack *extack)
{
	struct jensvq_qd *q = qdisc_priv(sch);
	int rv;
	unsigned int i;
	u64 now;
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

	now = ktime_get_ns();
	for (i = 0; i < JENSVQ_NUE; ++i) {
		q->ue[i].drop_next = now + DROPCHK_INTERVAL;
		/* report 0ns handover signals initialisation + time delta */
		janz_record_handover(sch, q, now, now, i);
	}
	sch->flags &= ~TCQ_F_CAN_BYPASS;
	pr_info(JTFMT "|janz_init GREP success\n", jtfmt(now));
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
		for (i = 0; i < JENSVQ_NUE; ++i) {
			rtnl_kfree_skbs(q->ue[i].q.first, q->ue[i].q.last);
			rtnl_kfree_skbs(q->ue[i].rexmits.first, q->ue[i].rexmits.last);
		}
		rtnl_kfree_skbs(q->byp.first, q->byp.last);
	}
	sch->q.qlen = 0;
	for (i = 0; i < JENSVQ_NUE; ++i) {
		q->ue[i].q.first = NULL;
		q->ue[i].q.last = NULL;
		q->ue[i].rexmits.first = NULL;
		q->ue[i].rexmits.last = NULL;
		q->ue[i].rq_notbefore = 0;
		q->ue[i].vq_notbefore = 0;
		q->ue[i].pktlensum = 0;
		q->ue[i].pktnum = 0;
		q->ue[i].crediting = 0;
		/* 10 Mbit/s */
		q->latchdata[0].ue[i].vrate = 80000;
		q->latchdata[0].ue[i].rrate = 80000;
		q->latchdata[0].ue[i].hover = 0;
		q->latchdata[1].ue[i].vrate = 800;
		q->latchdata[1].ue[i].rrate = 800;
		q->latchdata[1].ue[i].hover = 0;
		// don’t bother with _pad
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
	u64 newmarkfree = 0;
	u64 newmarkfull = 0;

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

	if (tb[TCA_JENSVQ_MARKFREE] && tb[TCA_JENSVQ_MARKFULL]) {
		newmarkfree = us_to_ns(nla_get_u32(tb[TCA_JANZ_MARKFREE]));
		newmarkfull = us_to_ns(nla_get_u32(tb[TCA_JANZ_MARKFULL]));
		if (!(newmarkfull > newmarkfree)) {
			NL_SET_ERR_MSG_MOD(extack, "markfull must be > markfree");
			return (-EINVAL);
		}
		if ((newmarkfull - newmarkfree) > 0xFFFFFFFFULL) {
			NL_SET_ERR_MSG_MOD(extack, "markfree‥markfull too large");
			return (-EINVAL);
		}
	} else if (tb[TCA_JENSVQ_MARKFREE] || tb[TCA_JENSVQ_MARKFULL]) {
		NL_SET_ERR_MSG_MOD(extack, "give both markfree and markfull or none of them");
		return (-EINVAL);
	}

	/* now actual configuring */
	sch_tree_lock(sch);
	/* no memory allocation, returns, etc. now */

	if (tb[TCA_JENSVQ_LIMIT])
		sch->limit = newlimit;

	if (tb[TCA_JENSVQ_MARKFREE])
		q->markfree = newmarkfree;

	if (tb[TCA_JENSVQ_MARKFULL])
		q->markfull = newmarkfull;

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

static xinline void
janz_record_write(struct jensvq_relay *record, struct jensvq_qd *q)
{
	unsigned long flags;	/* used by spinlock macros */

	record->hts = ktime_get_real_ns();
	raw_spin_lock_irqsave(&q->record_lock, flags);
	__relay_write(q->record_chan, record, sizeof(struct jensvq_relay));
	raw_spin_unlock_irqrestore(&q->record_lock, flags);
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
		if (q->ue[i].rq_notbefore < then)
			q->ue[i].rq_notbefore = then;
		q->ue[i].crediting = 0;
	}
	/* hard reply no packet to now send */
	return (NULL);
}

static ssize_t
janz_ctlfile_write(struct file *filp, const char __user *buf,
    size_t count, loff_t *posp)
{
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
			data.ue[i].vq_bps = bps_to_nspby(data.ue[i].vq_bps);
			data.ue[i].rq_bps = bps_to_nspby(data.ue[i].rq_bps);
		}
	}

	/* now infill */
	for (j = 0; j <= 1; ++j) {
		raw_write_seqcount_latch(&q->latch);
		for (i = 0; i < JENSVQ_NUE; ++i) {
			q->latchdata[j].ue[i].vrate = data.ue[i].vq_bps;
			q->latchdata[j].ue[i].rrate = data.ue[i].rq_bps;
			if (!data.ue[i].rq_bps &&
			    (data.ue[i].vq_bps > q->latchdata[j].ue[i].hover))
				q->latchdata[j].ue[i].hover = data.ue[i].vq_bps;
		}
	}

	return (sizeof(data));
}

static int
janz_enq_noinline(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free)
{
	int rv;
	u64 now;

	if (JANZDBG) {
		now = ktime_get_ns();
		pr_info(JTFMT "|janz_enq entering\n", jtfmt(now));
	}
	rv = janz_enq(skb, sch, to_free);
	if (JANZDBG)
		pr_info(JTFMT "|janz_enq leaving, %s\n", jtfmt(now),
		    rv == NET_XMIT_SUCCESS ? "ok" :
		    rv == NET_XMIT_CN ? "drop-other" :
		    rv == NET_XMIT_DROP ? "drop-this" : "unknown error");

	return (rv);
}

static xinline int
janz_enq(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free)
{
	struct jensvq_qd *q = qdisc_priv(sch);
	struct janz_skb *cx = get_cx(skb);
	struct janz_cb *cb;
	u64 now;
	unsigned int ue, rpktlen;
	int rv = NET_XMIT_SUCCESS;

	now = ktime_get_ns();
	ue = (u32)skb->mark < JENSVQ_NUE ? (u32)skb->mark : 0U;

	if (WARN(skb->next != NULL, "janz_enq passed multiple packets?!"))
		skb->next = NULL;
	if ((rpktlen = qdisc_pkt_len(skb)) > 65535U)
		pr_warn("overweight packet (%u) received\n", rpktlen);

	/* ensure we have space in the queue */
	if (unlikely(sch->q.qlen >= sch->limit)) {
		u32 prev_backlog = sch->qstats.backlog;
		const char *why;

		if (unlikely(sch->q.qlen > sch->limit)) {
			net_warn_ratelimited("qdisc over limit");
			why = "overlimit";
			goto dont_enq;
		}
		if (unlikely(!q->ue[ue].q.first)) {
			net_warn_ratelimited("UE#%u starving", ue);
			why = "starving";
 dont_enq:
			janz_record_enqdrop(sch, q, skb, now, ue);
			if (JANZDBG)
				pr_info(JTFMT "|dropping skb %08lX from UE #%u for %s\n",
				    jtfmt(now), (unsigned long)skb, ue, why);
			return (qdisc_drop(skb, sch, to_free));
		}
		janz_drop1(sch, q, now, "full queue", ue);
		qdisc_qstats_overlimit(sch);
		qdisc_tree_reduce_backlog(sch, 0,
		    prev_backlog - sch->qstats.backlog);
		rv = NET_XMIT_CN;
	}
	/* we now know at least one cb element is free */
	cb = q->cb_free;
	q->cb_free = cb->next;
	/* initialise cb/cx struct */
	memset(cx, '\0', sizeof(struct janz_skb));
	cx->janz_cb_num = (size_t)(cb - q->cb_base);
	memset(cb, '\0', sizeof(struct janz_cb));
	cb->next = NULL;
	cb->ts_enq = now;

	skb_orphan(skb);
	if (janz_analyse(sch, q, skb, cx, cb, now)) {
		cb->ts_arrive = now;
		cb->bypass = 1;

		if (!q->byp.first) {
			q->byp.first = skb;
			q->byp.last = skb;
		} else {
			q->byp.last->next = skb;
			q->byp.last = skb;
		}
		q->byplensum += vpktlen(rpktlen);
		++q->bypnum;
		++sch->q.qlen;
		qdisc_qstats_backlog_inc(sch, skb);
		return (rv);
	}

	cb->ts_arrive = now + q->xlatency;
	cb->uenum = ue;

	if (!q->ue[ue].q.first) {
		q->ue[ue].q.first = skb;
		q->ue[ue].q.last = skb;
	} else {
		q->ue[ue].q.last->next = skb;
		q->ue[ue].q.last = skb;
	}
	q->ue[ue].pktlensum += vpktlen(rpktlen);
	++q->ue[ue].pktnum;
	++sch->q.qlen;
	qdisc_qstats_backlog_inc(sch, skb);
	return (rv);
}

#ifdef JANZ_IP_DECODER_DEBUG
static const char * const ipver_decode[4] = {
	"not IP",
	"IPv6",
	"IPv4",
	"invalid"
};
#undef JANZ_IP_DECODER_DEBUG
#define JANZ_IP_DECODER_DEBUG(fmt,...)	printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#else
#define JANZ_IP_DECODER_DEBUG(fmt,...)	do { /* nothing */ } while (0)
#endif

static xinline bool
janz_analyse(struct Qdisc *sch, struct jensvq_qd *q,
    struct sk_buff *skb, struct janz_skb *cx, struct janz_cb *cb, u64 now)
{
	unsigned char *hdrp;
	unsigned char *endoflineardata = skb->data + skb_headlen(skb);
	/* normally: the nexthdr for IPv6’s no payload marker */
	u8 noportinfo = 59;
	int fragoff = -1;
	struct janz_fragcomp fc;
	struct ipv6hdr *ih6 = NULL;
	struct iphdr *ih4 = NULL;
	struct janz_fragcache *fe;

	/* addresses */
	switch (skb->protocol) {
	case htons(ETH_P_IP):
		ih4 = ip_hdr(skb);
		hdrp = (void *)ih4;
		if ((hdrp + sizeof(struct iphdr)) > endoflineardata) {
			JANZ_IP_DECODER_DEBUG("IPv4 too short\n");
			goto no_ports;
		}
		JANZ_IP_DECODER_DEBUG("IPv4 %08X->%08X proto %u frag %d\n",
		    htonl(ih4->saddr), htonl(ih4->daddr), ih4->protocol, ip_is_fragment(ih4) ? 1 : 0);
		cx->tosbyte = ih4->tos;
		ipv6_addr_set_v4mapped(ih4->saddr, &cb->srcip);
		ipv6_addr_set_v4mapped(ih4->daddr, &cb->dstip);
		cb->ecnenq = cx->tosbyte & INET_ECN_MASK;
		cb->ecndeq = cb->ecnenq /* at first */;
		cb->ecnval = 1;
		cb->ipver = 2;
		cb->nexthdr = ih4->protocol;
		hdrp += ih4->ihl * 4;
		/* Legacy IP fragmentation */
		if (ip_is_fragment(ih4)) {
			/* use nexthdr from IPv6 frag header as indicator */
			noportinfo = 44;
			/* fragment information */
			memcpy(&fc.sip, &cb->srcip, 32);
			fc.idp = ((u32)ih4->protocol << 24) | ((u32)ih4->id & 0xFFFFU);
			fc.v = cb->ipver;
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
			goto no_ports;
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
		cx->tosbyte = ipv6_get_dsfield(ih6);
		memcpy(&cb->srcip, ih6->saddr.s6_addr, 16);
		memcpy(&cb->dstip, ih6->daddr.s6_addr, 16);
		cb->ecnenq = cx->tosbyte & INET_ECN_MASK;
		cb->ecndeq = cb->ecnenq /* at first */;
		cb->ecnval = 1;
		cb->ipver = 1;
		cb->nexthdr = ih6->nexthdr;
		hdrp += 40;
		break;
	/* ARP/RARP bypass */
	case htons(ETH_P_ARP):
		JANZ_IP_DECODER_DEBUG("ARP packet\n");
		return (true);
	case htons(ETH_P_RARP):
		JANZ_IP_DECODER_DEBUG("RARP packet\n");
		return (true);
	/* others of possible interest */
	case htons(ETH_P_PPP_DISC):
		JANZ_IP_DECODER_DEBUG("PPPoE discovery packet\n");
		return (false);
	case htons(ETH_P_LOOP):
	case htons(ETH_P_LOOPBACK):
		JANZ_IP_DECODER_DEBUG("ethernet loopback packet\n");
		return (false);
	default:
		JANZ_IP_DECODER_DEBUG("unknown proto htons(0x%04X)\n", (unsigned)ntohs(skb->protocol));
		return (false);
	}
	/* we end here only if the packet is IPv4 or IPv6 */

 try_nexthdr:
	switch (cb->nexthdr) {
	case 1:		/* ICMP */
		if (cb->ipver != 2) {
			JANZ_IP_DECODER_DEBUG("%s in %s packet\n",
			    "ICMP", ipver_decode[cb->ipver]);
			goto no_ports;
		}
		if ((hdrp + 4) > endoflineardata) {
			JANZ_IP_DECODER_DEBUG("%u too short\n", cb->nexthdr);
			goto no_ports;
		}
		switch (/* Type */ hdrp[0]) {
		case 3: /* Destination Unreachable */
		case 5: /* Redirect */
		case 9: /* Router Advertisement */
		case 10: /* Router Solicitation */
		case 11: /* Time Exceeded */
		case 12: /* Parameter Problem: Bad IP header */
		case 13: /* Timestamp (like NTP) */
		case 14: /* Timestamp Reply */
			/*XXX here could validate legacy ICMP checksum */
			/* into the bypass */
			return (true);
		default:
			return (false);
		}
	case 6:		/* TCP */
	case 17:	/* UDP */
		/* both begin with src and dst ports in this order */
		if ((hdrp + 4) > endoflineardata) {
			JANZ_IP_DECODER_DEBUG("%u too short\n", cb->nexthdr);
			goto no_ports;
		}
		cb->sport = ((unsigned int)hdrp[0] << 8) | hdrp[1];
		cb->dport = ((unsigned int)hdrp[2] << 8) | hdrp[3];
		break;
	case 58:	/* ICMPv6 */
		if (cb->ipver != 1) {
			JANZ_IP_DECODER_DEBUG("%s in %s packet\n",
			    "ICMPv6", ipver_decode[cb->ipver]);
			goto no_ports;
		}
		if ((hdrp + 4) > endoflineardata) {
			JANZ_IP_DECODER_DEBUG("%u too short\n", cb->nexthdr);
			goto no_ports;
		}
		switch (/* Type */ hdrp[0]) {
		case 1: /* Destination unreachable */
		case 2: /* Packet too big */
		case 3: /* Time exceeded */
		case 4: /* Parameter problem */
		case 133: /* ND Router Solicitation */
		case 134: /* ND Router Advertisement */
		case 135: /* ND Neighbour Solicitation */
		case 136: /* ND Neighbour Advertisement */
		case 137: /* ND Redirect */
		case 141: /* IND Solicitation (like RARP) */
		case 142: /* IND Advertisement */
		case 144: /* Mobile Prefix Solicitation */
		case 145: /* Mobile Prefix Advertisement */
		case 146: /* SeND Certification Path Solicitation */
		case 147: /* SeND Certification Path Advertisement */
			/*XXX here could validate ICMPv6 checksum */
			/* into the bypass */
			return (true);
		default:
			return (false);
		}
	case 0:		/* IPv6 hop-by-hop options */
	case 43:	/* IPv6 routing */
	case 60:	/* IPv6 destination options */
		if (cb->ipver != 1) {
			JANZ_IP_DECODER_DEBUG("%s in %s packet\n",
			    "IPv6 options", ipver_decode[cb->ipver]);
			goto no_ports;
		}
		if ((hdrp + 4) > endoflineardata) {
			JANZ_IP_DECODER_DEBUG("%u too short\n", cb->nexthdr);
			goto no_ports;
		}
		cb->nexthdr = hdrp[0];
		hdrp += ((unsigned int)hdrp[1] + 1U) * 8U;
		goto try_nexthdr;
	case 44:	/* IPv6 fragment */
		if (cb->ipver != 1) {
			JANZ_IP_DECODER_DEBUG("%s in %s packet\n",
			    "IPv6 fragment header", ipver_decode[cb->ipver]);
			goto no_ports;
		}
		if ((hdrp + 8) > endoflineardata) {
			JANZ_IP_DECODER_DEBUG("%u too short\n", cb->nexthdr);
			goto no_ports;
		}
		if (fragoff != -1) {
			JANZ_IP_DECODER_DEBUG("two fragment headers\n");
			goto no_ports;
		}
		memcpy(&fc.sip, &cb->srcip, 32);
		memcpy(&fc.idp, hdrp + 4, 4);
		fc.v = cb->ipver;
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
		fe->ts = cb->ts_enq;
		fe->sport = cb->sport;
		fe->dport = cb->dport;
		fe->next = q->fragcache_used;
		if (unlikely(!fe->next)) {
			q->fragcache_last = fe;
			q->fragcache_aged = fe->ts;
		}
		q->fragcache_used = fe;
	}
	return (false);

 higher_fragment:
	fe = q->fragcache_used;
	while (fe) {
		if (!memcmp(&fc, &(fe->c), sizeof(struct janz_fragcomp))) {
			cb->nexthdr = fe->nexthdr;
			cb->sport = fe->sport;
			cb->dport = fe->dport;
			return (false);
		}
		fe = fe->next;
	}

 no_ports:
	/* we end here if the packet buffer does not contain enough info */
	cb->nexthdr = noportinfo;
	return (false);
}

static xinline void
janz_fragcache_maint(struct jensvq_qd *q, u64 now)
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
		while (lastnew->next && old <= lastnew->next->ts)
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

static xinline void
janz_record_packet(struct Qdisc *sch, struct jensvq_qd *q,
    struct sk_buff *skb, struct janz_skb *cx, struct janz_cb *cb, u64 now,
    u64 vbw, u64 rbw, int what)
{
	struct jensvq_relay r = {0};

	switch (what) {
	case 1: /* normal */
		r.upkts = q->ue[cb->uenum].pktnum;
		r.ubytes = q->ue[cb->uenum].pktlensum;
		r.vbw = nspby_to_bps(vbw);
		r.rbw = nspby_to_bps(rbw);
		r.vqdelay = cx->vqdelay;
		r.rqdelay = cx->rqdelay;
		break;
	case 2: /* drop */
		r.upkts = q->ue[cb->uenum].pktnum;
		r.ubytes = q->ue[cb->uenum].pktlensum;
		break;
	case 3: /* bypass */
		r.upkts = q->bypnum;
		r.ubytes = q->byplensum;
		break;
	default:
		BUILD_BUG_ON_MSG(1, "what?");
	}

	r.vts = now;
	memcpy(&r.srcip, &cb->srcip, 32);
	r.flags = JENS_FMK(JENSVQ_Ftype, 1) |
	    JENS_FMK(JENSVQ_Frexnum, cb->rexnum) |
	    JENS_FMK(JENSVQ_Frextot, cb->rextot) |
	    JENS_FMK(JENSVQ_Fmark, cb->mark) |
	    JENS_FMK(JENSVQ_Fecnval, cb->ecnval) |
	    JENS_FMK(JENSVQ_Fecnenq, cb->ecnenq) |
	    JENS_FMK(JENSVQ_Fecndeq, cb->ecndeq) |
	    JENS_FMK(JENSVQ_Fipv, cb->ipver) |
	    JENS_FMK(JENSVQ_Fdrop, cb->drop) |
	    JENS_FMK(JENSVQ_Fbypass, cb->bypass) |
	    JENS_FMK(JENSVQ_Fuenum, cb->uenum);
	r.psize = qdisc_pkt_len(skb);
	r.sport = cb->sport;
	r.dport = cb->dport;
	r.tos = cx->tosbyte;
	r.nh = cb->nexthdr;
	r.owdelay = ktime_get_ns() - cb->ts_enq;
	janz_record_write(&r, q);
}

static xinline void
janz_record_enqdrop(struct Qdisc *sch, struct jensvq_qd *q,
    struct sk_buff *skb, u64 now, unsigned int ue)
{
	struct jensvq_relay r = {0};

	r.vts = now;
	r.flags = JENS_FMK(JENSVQ_Ftype, 1) |
	    JENS_FMK(JENSVQ_Fdrop, 1) |
	    JENS_FMK(JENSVQ_Fuenum, ue);
	r.psize = qdisc_pkt_len(skb);
	r.upkts = q->ue[ue].pktnum;
	r.ubytes = q->ue[ue].pktlensum;
	janz_record_write(&r, q);
}

static xinline void
janz_drop1(struct Qdisc *sch, struct jensvq_qd *q,
    u64 now, const char *why, unsigned int ue)
{
	struct sk_buff *skb;
	struct janz_skb *cx;
	struct janz_cb *cb;
	unsigned int rpktlen;

	/* caller must ensure presence */
	skb = q->ue[ue].q.first;
	if (!(q->ue[ue].q.first = skb->next))
		q->ue[ue].q.last = NULL;
	rpktlen = qdisc_pkt_len(skb);
	q->ue[ue].pktlensum -= vpktlen(rpktlen);
	checked_dec(q->ue[ue].pktnum);
	checked_dec(sch->q.qlen);
	qdisc_qstats_backlog_dec(sch, skb);

	cx = get_cx(skb);
	cb = get_cb(cx, q);
	cb->drop = 1;
	janz_record_packet(sch, q, skb, cx, cb, now, 0, 0, 2);
	if (JANZDBG || 1)
		pr_info(JTFMT "|dropping skb %08lX from UE #%u for %s\n",
		    jtfmt(now), (unsigned long)skb, ue, why);
	kfree_skb(skb);
	cb->next = q->cb_free;
	q->cb_free = cb;
}

static struct sk_buff *
janz_deq_noinline(struct Qdisc *sch)
{
	struct sk_buff *skb;
#ifdef JANZ_DEV_DEBUG
	struct jensvq_qd * const q = qdisc_priv(sch);
	u64 now = ktime_get_ns();

	if (JANZDBG) {
		pr_info(JTFMT "|janz_deq entering\n", jtfmt(now));
		q->dbg_mnext = 0;
	}
#endif
	skb = janz_deq(sch);
#ifdef JANZ_DEV_DEBUG
	if (JANZDBG && skb) {
		struct janz_skb *cx = get_cx(skb);
		struct janz_cb *cb = get_cb(cx, q);

		pr_info(JTFMT "|janz_deq leaving, skb=%08lX from UE#%c\n", jtfmt(now),
		    (unsigned long)skb, cb->bypass ? 'Y' : '0' + cb->uenum);
	} else if (JANZDBG) {
		const char *res;
		unsigned int ue;

		res = q->dbg_mnext ?
		    "ok not crediting but mnext" :
		    "ok not crediting and not mnext";
		for (ue = 0; ue < JENSVQ_NUE; ++ue)
			if (q->ue[ue].crediting) {
				res = q->dbg_mnext ?
				    "ok crediting and mnext" :
				    "GREP crediting but not mnext";
				break;
			}
		pr_info(JTFMT "|janz_deq leaving, skb=nil, %s\n", jtfmt(now), res);
	}
#endif
	return (skb);
}

static xinline struct sk_buff *
janz_deq(struct Qdisc *sch)
{
	struct jensvq_qd * const q = qdisc_priv(sch);
	struct sk_buff *skb;
	struct janz_skb *cx;
	struct janz_cb *cb;
	u64 now, mnextns, rq_notbefore, vq_notbefore;
	unsigned int rpktlen, ue;
	u32 rexmit_chance;
	struct jensvq_ldue lue;

 redo_deq:
	now = ktime_get_ns();
	if (JANZDBG)
		pr_info(JTFMT "|entering redo_deq\n", jtfmt(now));

	/* check bypass first */
	if (q->byp.first) {
		skb = q->byp.first;
		cx = get_cx(skb);
		cb = get_cb(cx, q);
		if (!(q->byp.first = skb->next))
			q->byp.last = NULL;
		rpktlen = qdisc_pkt_len(skb);
		q->byplensum -= vpktlen(rpktlen);
		checked_dec(q->bypnum);
		checked_dec(sch->q.qlen);
		qdisc_qstats_backlog_dec(sch, skb);
		qdisc_bstats_update(sch, skb);
		janz_record_packet(sch, q, skb, cx, cb, now, 0, 0, 3);
		cb->next = q->cb_free;
		q->cb_free = cb;
		return (skb);
	}

	mnextns = (u64)~(u64)0;
	ue = q->uecur;
 find_ue_to_send:
	if (JANZDBG)
		pr_info(JTFMT "|entering find_ue_to_send, trying UE #%u\n",
		    jtfmt(now), ue);
	/* retransmitted packets held up? */
	if (q->ue[ue].rexmits.first) {
		skb = q->ue[ue].rexmits.first;
		cx = get_cx(skb);
		cb = get_cb(cx, q);
		if (cb->rexnum == 7) {
			/* dequeue */
			if (!(q->ue[ue].rexmits.first = skb->next))
				q->ue[ue].rexmits.last = NULL;
			rpktlen = qdisc_pkt_len(skb);
			q->ue[ue].pktlensum -= vpktlen(rpktlen);
			checked_dec(q->ue[ue].pktnum);
			checked_dec(sch->q.qlen);
			qdisc_qstats_backlog_dec(sch, skb);
			/* no qdisc_bstats_update here! */
			/* also no janz_record_packet */
			q->uecur = (ue + 1U) % JENSVQ_NUE;
			cb->next = q->cb_free;
			q->cb_free = cb;
			return (skb);
		}
		/* don’t peek */
		skb = NULL;
		cx = NULL;
		cb = NULL;
	}
	/* a package still in transit or handover? */
	if (now < q->ue[ue].rq_notbefore) {
 triggered_handover:
		mnextns = min(mnextns, q->ue[ue].rq_notbefore);
 try_next_ue:
		if (JANZDBG)
			pr_info(JTFMT "|entering try_next_ue, mnext=" JTFMT "\n",
			    jtfmt(now), jtfmt(mnextns != (u64)~(u64)0 ? mnextns : 0));
		ue = (ue + 1U) % JENSVQ_NUE;
		if (ue != q->uecur)
			goto find_ue_to_send;
		/* tried every UE */
		if (mnextns != (u64)~(u64)0) {
			if (JANZDBG) {
				if (mnextns <= now)
					pr_info(JTFMT "|GREP mnext < now\n", jtfmt(now));
#ifdef JANZ_DEV_DEBUG
				q->dbg_mnext = 1;
#endif
			} else if (1 && (mnextns <= now))
				pr_info(JTFMT "|GREP mnext " JTFMT "  < now\n",
				    jtfmt(now), jtfmt(mnextns));
			qdisc_watchdog_schedule_ns(&q->watchdog, mnextns);
		}
		return (NULL);
	}

	/* get bandwidths, check whether to trigger a handover */
	lue = jensvq_readlatch(q, ue);
	if (now < lue.hover) {
		q->ue[ue].rq_notbefore = lue.hover;
		q->ue[ue].crediting = 0;
		janz_record_handover(sch, q, now, lue.hover, ue);
		goto triggered_handover;
	}

	/* we have reached notbefore, previous packet is fully sent */
	if (q->ue[ue].rexmits.first) {
		/* we KNOW cb->rexnum != 7 */
		skb = q->ue[ue].rexmits.first;
		cx = get_cx(skb);
		cb = get_cb(cx, q);
		if (now < cb->ts_arrive) {
			mnextns = min(mnextns, cb->ts_arrive);
			goto rexmit_notyet;
		}
		/*
		 * do the entire machinery from below but without
		 * dequeueing the skb first, for in case we have to
		 * transmit at least one more time (rexmit FIFO order)
		 */
		rpktlen = qdisc_pkt_len(skb);
		qdisc_bstats_update(sch, skb);

		/* earliest rexmit ts replaces ts_arrive */
		rq_notbefore = q->ue[ue].crediting ?
		    max(q->ue[ue].rq_notbefore, cb->ts_arrive) : now;
		vq_notbefore = max(rq_notbefore, q->ue[ue].vq_notbefore);
		q->ue[ue].vq_notbefore = vq_notbefore + (lue.vrate * (u64)rpktlen);
		q->ue[ue].rq_notbefore = rq_notbefore + (lue.rrate * (u64)rpktlen);
		q->ue[ue].crediting = 1;

		janz_record_packet(sch, q, skb, cx, cb,
		    rq_notbefore, lue.vrate, lue.rrate, 1);
		if (cb->rexnum == cb->rextot) {
			/* actually dequeue, for sending */
			if (!(q->ue[ue].rexmits.first = skb->next))
				q->ue[ue].rexmits.last = NULL;
			q->ue[ue].pktlensum -= vpktlen(rpktlen);
			checked_dec(q->ue[ue].pktnum);
			checked_dec(sch->q.qlen);
			qdisc_qstats_backlog_dec(sch, skb);
			/* and off */
			q->uecur = (ue + 1U) % JENSVQ_NUE;
			cb->next = q->cb_free;
			q->cb_free = cb;
			return (skb);
		}
		/* no, keep this at the head of the rexmit FIFO */
		++cb->rexnum;
		/* give the other UEs the round-robin */
		q->uecur = (ue + 1U) % JENSVQ_NUE;
		goto redo_deq;

 rexmit_notyet:
		/* don’t peek */
		skb = NULL;
		cx = NULL;
		cb = NULL;
	}
	if (!q->ue[ue].q.first) {
		/* nothing to send, start subsequent packet later */
 nothing_to_send:
		q->ue[ue].crediting = 0;
		goto try_next_ue;
	}
	if (now >= q->ue[ue].drop_next) {
		bool diddrop = false;

		/* drop one packet if one or more are older than 100 ms */
		if (get_cb(get_cx(q->ue[ue].q.first), q)->ts_arrive <
		    now - nsmul(100, NSEC_PER_MSEC)) {
			janz_drop1(sch, q, now, "100 ms age", ue);
			diddrop = true;
		}
		/* drop all packets older than 500 ms */
		while (q->ue[ue].q.first &&
		    get_cb(get_cx(q->ue[ue].q.first), q)->ts_arrive <
		    now - nsmul(500, NSEC_PER_MSEC))
			janz_drop1(sch, q, now, "500 ms age", ue);
		/* check every 200 ms */
		q->ue[ue].drop_next += DROPCHK_INTERVAL;
		if (diddrop)
			now = ktime_get_ns();
		if (q->ue[ue].drop_next < now)
			q->ue[ue].drop_next = now + DROPCHK_INTERVAL;
		if (diddrop && !q->ue[ue].q.first)
			goto nothing_to_send;
	}
	skb = q->ue[ue].q.first;
	cx = get_cx(skb);
	cb = get_cb(cx, q);
	if (cb->ts_arrive > now) {
		/* packet hasn’t reached us yet */
		mnextns = min(mnextns, cb->ts_arrive);
		goto nothing_to_send;
	}
	/* got skb to send */

	if (!(q->ue[ue].q.first = skb->next))
		q->ue[ue].q.last = NULL;
	rpktlen = qdisc_pkt_len(skb);
	q->ue[ue].pktlensum -= vpktlen(rpktlen);
	checked_dec(q->ue[ue].pktnum);
	checked_dec(sch->q.qlen);
	qdisc_qstats_backlog_dec(sch, skb);
	qdisc_bstats_update(sch, skb);

	rq_notbefore = q->ue[ue].crediting ?
	    max(q->ue[ue].rq_notbefore, cb->ts_arrive) : now;
	vq_notbefore = max(rq_notbefore, q->ue[ue].vq_notbefore);
	q->ue[ue].vq_notbefore = vq_notbefore + (lue.vrate * (u64)rpktlen);
	q->ue[ue].rq_notbefore = rq_notbefore + (lue.rrate * (u64)rpktlen);
	q->ue[ue].crediting = 1;

	cx->rqdelay = rq_notbefore - cb->ts_arrive;
	if (unlikely(cb->ts_arrive > rq_notbefore))
		cx->rqdelay = 0;
	else if (unlikely(cb->ts_arrive == rq_notbefore))
		cx->rqdelay = 1;

	cx->vqdelay = vq_notbefore - cb->ts_arrive;
	if (unlikely(cb->ts_arrive > vq_notbefore))
		cx->vqdelay = 0;
	else if (unlikely(cb->ts_arrive == vq_notbefore))
		cx->vqdelay = 1;

	if (cx->vqdelay >= q->markfull) {
		goto domark;
	} else if (cx->vqdelay <= q->markfree) {
		/* nothing */
	} else {
		u64 t = cx->vqdelay - q->markfree;
		/* janz_chg ensuring this fits */
		u32 tmax = q->markfull - q->markfree;

		if (get_random_u32_below(tmax) < t) {
 domark:
			cb->mark = 1;
			if (INET_ECN_set_ce(skb))
				cb->ecndeq = INET_ECN_CE;
		}
	}

	/* up to 5 retransmissions but perhaps not */
	rexmit_chance = get_random_u32_below(100000U);
	cb->rextot = rexmit_chance < 1U ? 5 :
	    rexmit_chance < 10U ? 4 :
	    rexmit_chance < 100U ? 3 :
	    rexmit_chance < 1000U ? 2 :
	    rexmit_chance < 10000U ? 1 : 0;
	if (cb->rextot) {
		/* sent-but-retransmitted */
		janz_record_packet(sch, q, skb, cx, cb,
		    rq_notbefore, lue.vrate, lue.rrate, 1);
		++cb->rexnum;
		/* next transmission not before: */
		cb->ts_arrive = rq_notbefore + nsmul(8, NSEC_PER_MSEC);
		if (JANZDBG)
			pr_info(JTFMT "|enq UE#%u for rexmit at " JTFMT "\n",
			    jtfmt(now), ue, jtfmt(cb->ts_arrive));
		/* enqueue and retry dequeueing with next UE */
		if (!q->ue[ue].rexmits.first) {
			q->ue[ue].rexmits.first = skb;
			q->ue[ue].rexmits.last = skb;
		} else {
			q->ue[ue].rexmits.last->next = skb;
			q->ue[ue].rexmits.last = skb;
		}
		q->ue[ue].pktlensum += vpktlen(rpktlen);
		++q->ue[ue].pktnum;
		++sch->q.qlen;
		qdisc_qstats_backlog_inc(sch, skb);
		skb = NULL;
		cx = NULL;
		cb = NULL;
		q->uecur = (ue + 1U) % JENSVQ_NUE;
		goto redo_deq;
	}

	/* held up by previous package still in retransmission? */
	if (unlikely(q->ue[ue].rexmits.first)) {
		/* signal this */
		cb->rexnum = 7;
		/* append into nōn-reorder retransmission loop */
		if (!q->ue[ue].rexmits.first) {
			q->ue[ue].rexmits.first = skb;
			q->ue[ue].rexmits.last = skb;
		} else {
			q->ue[ue].rexmits.last->next = skb;
			q->ue[ue].rexmits.last = skb;
		}
		q->ue[ue].pktlensum += vpktlen(rpktlen);
		++q->ue[ue].pktnum;
		++sch->q.qlen;
		qdisc_qstats_backlog_inc(sch, skb);
		/* but do report as sent already with flag */
		janz_record_packet(sch, q, skb, cx, cb,
		    rq_notbefore, lue.vrate, lue.rrate, 1);
		/* don’t send this packet */
		skb = NULL;
		cx = NULL;
		cb = NULL;
		q->uecur = (ue + 1U) % JENSVQ_NUE;
		goto redo_deq;
	}

	janz_record_packet(sch, q, skb, cx, cb,
	    rq_notbefore, lue.vrate, lue.rrate, 1);
	q->uecur = (ue + 1U) % JENSVQ_NUE;
	cb->next = q->cb_free;
	q->cb_free = cb;
	return (skb);
}

/*
 * JENS qdisc (shared parts, later in the file)
 *
 * Copyright © 2022, 2023 mirabilos <t.glaser@tarent.de>
 * Licensor: Deutsche Telekom LLCTO
 *
 * This module for the Linux kernel is published under the GPLv2.
 */

#ifndef __NET_SCHED_JANZ_IMPL_H
#define __NET_SCHED_JANZ_IMPL_H

static inline void janz_drop_overlen(struct Qdisc *, Mjanz *, u64, bool);

static inline u32
delay_encode(u64 now, u64 base, u64 *qdelayp)
{
	u64 qdelay;

	if (unlikely(base > now)) {
		if (qdelayp)
			*qdelayp = 0;
		return (0xFFFFFFFEUL);
	}

	qdelay = now - base;
	if (qdelayp)
		*qdelayp = qdelay;

	qdelay >>= TC_JANZ_TIMESHIFT;
	if (unlikely(qdelay > 0xFFFFFFFDUL))
		return (0xFFFFFFFDUL);
	return ((u32)qdelay);
}

static inline void
qdelay_encode(struct janz_skb *cb, u64 now, u64 *qdelayp, bool resizing)
{
	u32 delay1024;

	delay1024 = unlikely(resizing) ? 0xFFFFFFFFUL :
	    delay_encode(now, cb->ts_enq + cb->pktxlatency, qdelayp);
	/* overlays cb->pktxlatency, do not move up */
	cb->qdelay1024 = delay1024;
}

static inline void
janz_record_write(struct tc_janz_relay *record, Sjanz *q)
{
	unsigned long flags;	/* used by spinlock macros */

	spin_lock_irqsave(&q->record_lock, flags);
	__relay_write(q->record_chan, record, sizeof(struct tc_janz_relay));
	spin_unlock_irqrestore(&q->record_lock, flags);
}

static inline void
janz_record_queuesz(struct Qdisc *sch, Sjanz *q, u64 now,
    u64 rate, u8 f)
{
	struct tc_janz_relay r = {0};

	if (!rate)
		rate = (u64)atomic64_read_acquire(&(q->ns_pro_byte));
	q->lastknownrate = rate;

	r.ts = now;
	r.type = TC_JANZ_RELAY_QUEUESZ;
	r.d32 = q->pktlensum;
	r.e16 = sch->q.qlen > 0xFFFFU ? 0xFFFFU : sch->q.qlen;
	r.f8 = f;
	r.x64[0] = max(div64_u64(8ULL * NSEC_PER_SEC, rate), 1ULL);
	r.x64[1] = (u64)ktime_to_ns(ktime_mono_to_real(ns_to_ktime(now))) - now;
	janz_record_write(&r, q);

	/* use of ktime_get_ns() is deliberate */
	q->qsz_next = ktime_get_ns() + QSZ_INTERVAL;
}

static inline void
janz_record_packet(Sjanz *q,
    struct sk_buff *skb, struct janz_skb *cb, u64 now)
{
	struct tc_janz_relay r = {0};

	r.ts = now;
	r.type = TC_JANZ_RELAY_SOJOURN;
	r.d32 = cb->qdelay1024;
	r.e16 = 0;
	r.f8 = cb->record_flag;
	r.z.zSOJOURN.psize = ((unsigned int)cb->xqid << 30) |
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

	r.z.zSOJOURN.real_owd = delay_encode(ktime_get_ns(), cb->ts_enq, NULL);
	janz_record_write(&r, q);
}

static inline void
janz_fragcache_maint(Mjanz *q, u64 now)
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

static inline struct sk_buff *
q_deq(struct Qdisc *sch, Sjanz *sq, struct janz_skbfifo *q)
{
	struct sk_buff *skb;

	skb = q->first;
	if (likely(skb)) {
		qdisc_qstats_backlog_dec(sch, skb);
		--sch->q.qlen;
		sq->pktlensum -= qdisc_pkt_len(skb);
		if (!(q->first = skb->next))
			q->last = NULL;
		skb->next = NULL;
	}
	return (skb);
}

static inline void
q_enq(struct Qdisc *sch, Sjanz *sq, struct janz_skbfifo *q, struct sk_buff *skb)
{
	if (!q->first) {
		q->first = skb;
		q->last = skb;
	} else {
		q->last->next = skb;
		q->last = skb;
	}
	sq->pktlensum += qdisc_pkt_len(skb);
	++sch->q.qlen;
	qdisc_qstats_backlog_inc(sch, skb);
}

static inline int
jq_enq(struct Qdisc *sch, Mjanz *mq, Sjanz *sq, struct janz_skbfifo *q,
    struct sk_buff *skb, u64 now, u32 prev_backlog)
{
	bool overlimit;

	// assumption is exactly 1 packet is passed
	if (WARN(skb->next != NULL, "jq_enq passed multiple packets?"))
		skb->next = NULL;
	skb_orphan(skb);
	q_enq(sch, sq, q, skb);

	overlimit = sch->q.qlen > sch->limit;
	if (unlikely(overlimit)) {
		janz_drop_overlen(sch, mq, now, true);
		qdisc_qstats_overlimit(sch);
		qdisc_tree_reduce_backlog(sch, 0,
		    prev_backlog - sch->qstats.backlog);
	}

	if (now >= sq->qsz_next)
		janz_record_queuesz(sch, sq, now, 0, 0);
	return (unlikely(overlimit) ? NET_XMIT_CN : NET_XMIT_SUCCESS);
}

static inline void
janz_drop_pkt(struct Qdisc *sch, Sjanz *q, u64 now,
    int qid, bool resizing)
{
	struct sk_buff *skb;
	struct janz_skb *cb;

	skb = q_deq(sch, q, &(q->q[qid]));
	cb = get_janz_skb(skb);
	cb->xqid = qid + 1;
	cb->record_flag |= TC_JANZ_RELAY_SOJOURN_DROP;
	qdelay_encode(cb, now, NULL, resizing);
	janz_record_packet(q, skb, cb, now);
	/* inefficient for large reduction in sch->limit (resizing = true) */
	/* but we assume this doesn’t happen often, if at all */
	kfree_skb(skb);
}

static inline void
janz_drop_1pkt_whenold(struct Qdisc *sch, Sjanz *q,
    u64 now, bool resizing)
{
	if (q->q[0].first)
		janz_drop_pkt(sch, q, now, 0, resizing);
	else if (likely(q->q[1].first))
		janz_drop_pkt(sch, q, now, 1, resizing);
	else if (likely(q->q[2].first))
		janz_drop_pkt(sch, q, now, 2, resizing);
}

static inline void
janz_drop_1pkt_overlen(struct Qdisc *sch, Sjanz *q,
    u64 now, bool resizing)
{
	if (q->q[2].first)
		janz_drop_pkt(sch, q, now, 2, resizing);
	else if (q->q[1].first)
		janz_drop_pkt(sch, q, now, 1, resizing);
	else if (likely(q->q[0].first))
		janz_drop_pkt(sch, q, now, 0, resizing);
}

static inline bool
janz_qheadolder(Sjanz *q, u64 ots, int qid)
{
	struct janz_skb *cb;

	if (unlikely(!q->q[qid].first))
		return (false);
	cb = get_janz_skb(q->q[qid].first);
	return ((unlikely(cb->ts_enq + cb->pktxlatency < ots)) ? true : false);
}

static inline void
janz_dropchk(struct Qdisc *sch, Sjanz *q, u64 now)
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
		janz_drop_1pkt_whenold(sch, q, now, false);

	/* drop all packets older than 500 ms */
	ots = now - nsmul(500, NSEC_PER_MSEC);
	for (qid = 0; qid <= 2; ++qid)
		while (janz_qheadolder(q, ots, qid))
			janz_drop_pkt(sch, q, now, qid, false);

	q->drop_next += DROPCHK_INTERVAL;
	now = ktime_get_ns();
	if (q->drop_next < now)
		q->drop_next = now + DROPCHK_INTERVAL;
}

static inline struct sk_buff *
janz_sendoff(struct Qdisc *sch, Sjanz *q, struct sk_buff *skb,
    struct janz_skb *cb, u64 now)
{
	u64 qdelay;

	qdelay_encode(cb, now, &qdelay, false);

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
		goto domark;
	} else if (qdelay <= q->markfree)
		/* nothing */;
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
	janz_record_packet(q, skb, cb, now);
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
janz_analyse(struct Qdisc *sch, Mjanz *q,
    struct sk_buff *skb, struct janz_skb *cb, u64 now)
{
	unsigned char *hdrp;
	unsigned char *endoflineardata = skb->data + skb_headlen(skb);
	/* normally: the nexthdr for IPv6’s no payload marker */
	u8 noportinfo = 59;
	int fragoff = -1;
	struct janz_fragcomp fc;
	struct ipv6hdr *ih6 = NULL;
	struct iphdr *ih4 = NULL;

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
		fe->ts = cb->ts_enq;
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

#undef Mjanz
#undef Sjanz

#endif /* !__NET_SCHED_JANZ_IMPL_H */

#ifndef __NET_SCHED_JENS_CODEL_QDISC_H
#define __NET_SCHED_JENS_CODEL_QDISC_H

/* part of sch_jens (fork of sch_fq_codel), Deutsche Telekom LLCTO */

/*
 * Codel - The Controlled-Delay Active Queue Management algorithm
 *
 *  Copyright (C) 2011-2012 Kathleen Nichols <nichols@pollere.com>
 *  Copyright (C) 2011-2012 Van Jacobson <van@pollere.net>
 *  Copyright (C) 2012 Michael D. Taht <dave.taht@bufferbloat.net>
 *  Copyright (C) 2012,2015 Eric Dumazet <edumazet@google.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the authors may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2, in which case the provisions of the
 * GPL apply INSTEAD OF those given above.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 */

/* Controlling Queue Delay (CoDel) algorithm
 * =========================================
 * Source : Kathleen Nichols and Van Jacobson
 * http://queue.acm.org/detail.cfm?id=2209336
 *
 * Implemented on linux by Dave Taht and Eric Dumazet
 */

/* Qdiscs using codel plugin must use jens_skb_cb in their own cb[] */
struct jens_skb_cb {
	codel_time_t enqueue_time;
	unsigned int mem_usage;
	__u8 record_flag;
};

static struct jens_skb_cb *get_jens_cb(const struct sk_buff *skb)
{
	qdisc_cb_private_validate(skb, sizeof(struct jens_skb_cb));
	return (struct jens_skb_cb *)qdisc_skb_cb(skb)->data;
}

static codel_time_t codel_get_enqueue_time(const struct sk_buff *skb)
{
	return get_jens_cb(skb)->enqueue_time;
}

/* from INET_ECN_set_ce (net/inet_ecn.h) */
static __u8 jens_get_ecn(struct sk_buff *skb)
{
	__u8 tos;

	switch (skb->protocol) {
	case cpu_to_be16(ETH_P_IP):
		if (skb_network_header(skb) + sizeof(struct iphdr) <=
		    skb_tail_pointer(skb)) {
			tos = ip_hdr(skb)->tos;
			return ((tos & INET_ECN_MASK) | 4);
		}
		break;
	case cpu_to_be16(ETH_P_IPV6):
		if (skb_network_header(skb) + sizeof(struct ipv6hdr) <=
		    skb_tail_pointer(skb)) {
			tos = ipv6_get_dsfield(ipv6_hdr(skb));
			return ((tos & INET_ECN_MASK) | 4);
		}
		break;
	}
	return (0);
}

static void jens_set_enqueue_data(struct sk_buff *skb)
{
	struct jens_skb_cb *cb = get_jens_cb(skb);

	cb->record_flag = jens_get_ecn(skb);
	cb->enqueue_time = codel_get_time();
}

static __u8 jens_update_record_flag(struct sk_buff *skb, __u8 data)
{
	struct jens_skb_cb *cb = get_jens_cb(skb);

	cb->record_flag |= data;
	return (cb->record_flag);
}

#endif

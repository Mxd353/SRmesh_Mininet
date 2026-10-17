// SPDX-License-Identifier: GPL-2.0
/*
 * responder.bpf.c -- SRmesh Design 1 的内核态响应端 (TC ingress)
 * ===============================================================
 * 挂在响应端网卡的 TC ingress. 收到探测后:
 *   1. 从 payload 取出[反向 SID 列表]
 *   2. 用 bpf_skb_adjust_room 在前面塞入 外层IPv6 + SRH
 *   3. 交换内层方向 (h1->h2 改成 h2->h1)
 *   4. bpf_redirect 原路发回
 *
 * 线格式 (应用层协议 253, 无 L4 校验和):
 *   inner IPv6 (nxt=253) + [magic(4) probe_id(4) seq(4) tx_ns(8) rev_cnt(1) pad(3) rev_sids(16*n)]
 *
 * 配置 (MAC/IP) 由 orchestrator 运行时生成 responder_cfg.h 注入.
 */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "responder_cfg.h"

#define MAGIC        0x53526D31u   /* "SRm1" */
#define PROBE_PROTO  253           /* 自定义探测协议 */
#define SRH_TYPE     4
#define MAX_SIDS     8
#define PROBE_HDR_SZ 24

struct probe_hdr {
	__u32 magic;
	__u32 probe_id;
	__u32 seq;
	__u64 tx_ns;
	__u8  rev_cnt;
	__u8  pad[3];
} __attribute__((packed));

struct ip6h {
	__u8  ver_tc_flow[4];
	__be16 payload_len;
	__u8  nexthdr;
	__u8  hop_limit;
	struct in6_addr saddr;
	struct in6_addr daddr;
} __attribute__((packed));

struct srh_fixed {
	__u8  nexthdr;
	__u8  hdrlen;
	__u8  type;
	__u8  segments_left;
	__u8  last_entry;
	__u8  flags;
	__be16 tag;
} __attribute__((packed));

static const __u8 h2_mac[6] = CFG_H2_MAC;
static const __u8 r4_mac[6] = CFG_R4_MAC;
static const __u8 h2_ip[16] = CFG_H2_IP;

SEC("tc")
int responder(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IPV6))
		return TC_ACT_OK;

	struct ip6h *ip6 = (void *)(eth + 1);
	if ((void *)(ip6 + 1) > data_end)
		return TC_ACT_OK;
	/* 只处理我们自己的探测协议 */
	if (ip6->nexthdr != PROBE_PROTO)
		return TC_ACT_OK;

	__u8 *pl = (__u8 *)(ip6 + 1);
	if ((void *)(pl + PROBE_HDR_SZ) > data_end)
		return TC_ACT_OK;
	struct probe_hdr *ph = (struct probe_hdr *)pl;
	/* payload 里 magic 是大端序 (!I 打包), 转成主机序再比 */
	if (bpf_ntohl(ph->magic) != MAGIC)
		return TC_ACT_OK;

	__u8 n = ph->rev_cnt;
	if (n == 0 || n > MAX_SIDS)
		return TC_ACT_OK;

	__u32 srh_len = 8 + 16 * (__u32)n;
	__u32 inner_plen = bpf_ntohs(ip6->payload_len);
	if (inner_plen < PROBE_HDR_SZ + 16 * (__u32)n)
		return TC_ACT_OK;

	/* 保存内层原始源地址 (= 发起端地址, 回复时用作 dst) */
	__u8 peer[16];
	__builtin_memcpy(peer, &ip6->saddr, 16);

	/* 把反向 SID 列表读到栈上 */
	__u8 revs[MAX_SIDS * 16];
#pragma unroll
	for (int i = 0; i < MAX_SIDS; i++) {
		if (i < n) {
			if ((void *)(pl + PROBE_HDR_SZ + 16 * i + 16) > data_end)
				return TC_ACT_OK;
			__builtin_memcpy(revs + 16 * i, pl + PROBE_HDR_SZ + 16 * i, 16);
		}
	}

	/* 在前面插入 外层IPv6 + SRH */
	__u32 add = 40 + srh_len;
	if (bpf_skb_adjust_room(skb, (int)add, BPF_ADJ_ROOM_MAC, 0))
		return TC_ACT_OK;

	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;
	eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	struct ip6h *o = (void *)(eth + 1);
	if ((void *)(o + 1) > data_end)
		return TC_ACT_OK;
	struct srh_fixed *srh = (void *)(o + 1);
	if ((void *)(srh + 1) > data_end)
		return TC_ACT_OK;
	__u8 *seg = (__u8 *)(srh + 1);
	if ((void *)(seg + 16 * (__u32)n) > data_end)
		return TC_ACT_OK;
	struct ip6h *in = (void *)((char *)o + 40 + srh_len);
	if ((void *)(in + 1) > data_end)
		return TC_ACT_OK;

	/* 以太网头: 回发给网关 r4 */
	__builtin_memcpy(eth->h_dest, r4_mac, 6);
	__builtin_memcpy(eth->h_source, h2_mac, 6);
	eth->h_proto = bpf_htons(ETH_P_IPV6);

	/* 外层 IPv6 */
	__builtin_memset(o, 0, sizeof(*o));
	o->ver_tc_flow[0] = 0x60;
	o->payload_len = bpf_htons(srh_len + 40 + inner_plen);
	o->nexthdr = 43;          /* SRH */
	o->hop_limit = 64;
	__builtin_memcpy(&o->saddr, h2_ip, 16);
	__builtin_memcpy(&o->daddr, revs, 16);   /* DA = rev[0] */

	/* SRH: 段表逆序存 */
	srh->nexthdr = 41;                        /* 内层是 IPv6 */
	srh->hdrlen = (__u8)((srh_len / 8) - 1);
	srh->type = SRH_TYPE;
	srh->segments_left = (__u8)(n - 1);
	srh->last_entry = (__u8)(n - 1);
	srh->flags = 0;
	srh->tag = 0;
#pragma unroll
	for (int i = 0; i < MAX_SIDS; i++) {
		if (i < n) {
			/* 逐次显式边界检查: 让 verifier 能证明常量偏移的写是安全的 */
			if ((void *)(seg + 16 * i + 16) > data_end)
				return TC_ACT_OK;
			/* 逆序取源: 掩码把变长索引夹进 [0, MAX_SIDS-1], verifier 可证 */
			__u8 *src = revs + 16 * (((unsigned)(n - 1 - i)) & (MAX_SIDS - 1));
			__builtin_memcpy(seg + 16 * i, src, 16);
		}
	}

	/* 内层 IPv6: 交换方向 h1->h2 => h2->h1 */
	__builtin_memcpy(&in->saddr, h2_ip, 16);
	__builtin_memcpy(&in->daddr, peer, 16);
	in->hop_limit = 64;

	return bpf_redirect(CFG_IFINDEX, 0);
}

char _license[] SEC("license") = "GPL";

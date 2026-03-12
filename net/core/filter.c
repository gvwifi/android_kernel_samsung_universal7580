/*
 * Linux Socket Filter - Kernel level socket filtering
 *
 * Based on the design of the Berkeley Packet Filter. The new
 * internal format has been designed by PLUMgrid:
 *
 *	Copyright (c) 2011 - 2014 PLUMgrid, http://plumgrid.com
 *
 * Authors:
 *
 *	Jay Schulist <jschlst@samba.org>
 *	Alexei Starovoitov <ast@plumgrid.com>
 *	Daniel Borkmann <dborkman@redhat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * Andi Kleen - Fix a few bad bugs and races.
 * Kris Katterjohn - Added many additional checks in bpf_check_classic()
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/fcntl.h>
#include <linux/socket.h>
#include <linux/sock_diag.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/gfp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/flow_dissector.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <asm/unaligned.h>
#include <linux/filter.h>
#include <linux/ratelimit.h>
#include <linux/seccomp.h>

#ifndef BPF_CGROUP_RUN_PROG_INET_INGRESS
#define BPF_CGROUP_RUN_PROG_INET_INGRESS(sk,skb) (0)
#endif
#ifndef PKT_TYPE_OFFSET
#define PKT_TYPE_OFFSET() 0
#endif

static inline u32 skb_get_poff(const struct sk_buff *skb) { return 0; }

#include <linux/if_vlan.h>
#include <linux/bpf.h>
#include <linux/ftrace_event.h>

#ifndef TC_ACT_REDIRECT
#define TC_ACT_REDIRECT 7
#endif
#include <net/sch_generic.h>
#include <net/cls_cgroup.h>
#include <net/dst_metadata.h>
#include <net/dst.h>
#include <net/sock_reuseport.h>
#include <net/busy_poll.h>
#include <net/tcp.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/bpf_trace.h>

#ifndef PKT_TYPE_MAX
#define PKT_TYPE_MAX 7
#endif

/**
 *	sk_filter_trim_cap - run a packet through a socket filter
 *	@sk: sock associated with &sk_buff
 *	@skb: buffer to filter
 *	@cap: limit on how short the eBPF program may trim the packet
 *
 * Run the eBPF program and then cut skb->data to correct size returned by
 * the program. If pkt_len is 0 we toss packet. If skb->len is smaller
 * than pkt_len we keep whole skb->data. This is the socket level
 * wrapper to BPF_PROG_RUN. It returns 0 if the packet should
 * be accepted or -EPERM if the packet should be tossed.
 *
 */
int sk_filter_trim_cap(struct sock *sk, struct sk_buff *skb, unsigned int cap)
{
	int err;
	struct sk_filter *filter;

	/*
	 * If the skb was allocated from pfmemalloc reserves, only
	 * allow SOCK_MEMALLOC sockets to use it as this socket is
	 * helping free memory
	 */
	if (skb_pfmemalloc(skb) && !sock_flag(sk, SOCK_MEMALLOC)) {
#ifdef LINUX_MIB_PFMEMALLOCDROP
		NET_INC_STATS(sock_net(sk), LINUX_MIB_PFMEMALLOCDROP);
#endif
		return -ENOMEM;
	}
	err = BPF_CGROUP_RUN_PROG_INET_INGRESS(sk, skb);
	if (err)
		return err;

	err = security_sock_rcv_skb(sk, skb);
	if (err)
		return err;

	rcu_read_lock();
	filter = rcu_dereference(sk->sk_filter);
	if (filter) {
		struct sock *save_sk = skb->sk;
		unsigned int pkt_len;

		skb->sk = sk;
		pkt_len = bpf_prog_run_save_cb(filter->prog, skb);
		skb->sk = save_sk;
		err = pkt_len ? pskb_trim(skb, max(cap, pkt_len)) : -EPERM;
	}
	rcu_read_unlock();

	return err;
}
EXPORT_SYMBOL(sk_filter_trim_cap);

BPF_CALL_1(__skb_get_pay_offset, struct sk_buff *, skb)
{
	return skb_get_poff(skb);
}

BPF_CALL_3(__skb_get_nlattr, struct sk_buff *, skb, u32, a, u32, x)
{
	struct nlattr *nla;

	if (skb_is_nonlinear(skb))
		return 0;

	if (skb->len < sizeof(struct nlattr))
		return 0;

	if (a > skb->len - sizeof(struct nlattr))
		return 0;

	nla = nla_find((struct nlattr *) &skb->data[a], skb->len - a, x);
	if (nla)
		return (void *) nla - (void *) skb->data;

	return 0;
}

BPF_CALL_3(__skb_get_nlattr_nest, struct sk_buff *, skb, u32, a, u32, x)
{
	struct nlattr *nla;

	if (skb_is_nonlinear(skb))
		return 0;

	if (skb->len < sizeof(struct nlattr))
		return 0;

	if (a > skb->len - sizeof(struct nlattr))
		return 0;

	nla = (struct nlattr *) &skb->data[a];
	if (nla->nla_len > skb->len - a)
		return 0;

	nla = nla_find_nested(nla, x);
	if (nla)
		return (void *) nla - (void *) skb->data;

	return 0;
}

BPF_CALL_0(__get_raw_cpu_id)
{
	return raw_smp_processor_id();
}

static const struct bpf_func_proto bpf_get_raw_smp_processor_id_proto = {
	.func		= __get_raw_cpu_id,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

static u32 convert_skb_access(int skb_field, int dst_reg, int src_reg,
			      struct bpf_insn *insn_buf)
{
	struct bpf_insn *insn = insn_buf;

	switch (skb_field) {
	case SKF_AD_MARK:
		BUILD_BUG_ON(FIELD_SIZEOF(struct sk_buff, mark) != 4);

		*insn++ = BPF_LDX_MEM(BPF_W, dst_reg, src_reg,
				      offsetof(struct sk_buff, mark));
		break;

	case SKF_AD_PKTTYPE:
		*insn++ = BPF_LDX_MEM(BPF_B, dst_reg, src_reg, PKT_TYPE_OFFSET());
		*insn++ = BPF_ALU32_IMM(BPF_AND, dst_reg, PKT_TYPE_MAX);
#ifdef __BIG_ENDIAN_BITFIELD
		*insn++ = BPF_ALU32_IMM(BPF_RSH, dst_reg, 5);
#endif
		break;

	case SKF_AD_QUEUE:
		BUILD_BUG_ON(FIELD_SIZEOF(struct sk_buff, queue_mapping) != 2);

		*insn++ = BPF_LDX_MEM(BPF_H, dst_reg, src_reg,
				      offsetof(struct sk_buff, queue_mapping));
		break;

	case SKF_AD_VLAN_TAG:
	case SKF_AD_VLAN_TAG_PRESENT:
		BUILD_BUG_ON(FIELD_SIZEOF(struct sk_buff, vlan_tci) != 2);
		BUILD_BUG_ON(VLAN_TAG_PRESENT != 0x1000);

		/* dst_reg = *(u16 *) (src_reg + offsetof(vlan_tci)) */
		*insn++ = BPF_LDX_MEM(BPF_H, dst_reg, src_reg,
				      offsetof(struct sk_buff, vlan_tci));
		if (skb_field == SKF_AD_VLAN_TAG) {
			*insn++ = BPF_ALU32_IMM(BPF_AND, dst_reg,
						~VLAN_TAG_PRESENT);
		} else {
			/* dst_reg >>= 12 */
			*insn++ = BPF_ALU32_IMM(BPF_RSH, dst_reg, 12);
			/* dst_reg &= 1 */
			*insn++ = BPF_ALU32_IMM(BPF_AND, dst_reg, 1);
		}
		break;
	}

	return insn - insn_buf;
}

static bool convert_bpf_extensions(struct sock_filter *fp,
				   struct bpf_insn **insnp)
{
	struct bpf_insn *insn = *insnp;
	u32 cnt;

	switch (fp->k) {
	case SKF_AD_OFF + SKF_AD_PROTOCOL:
		BUILD_BUG_ON(FIELD_SIZEOF(struct sk_buff, protocol) != 2);

		/* A = *(u16 *) (CTX + offsetof(protocol)) */
		*insn++ = BPF_LDX_MEM(BPF_H, BPF_REG_A, BPF_REG_CTX,
				      offsetof(struct sk_buff, protocol));
		/* A = ntohs(A) [emitting a nop or swap16] */
		*insn = BPF_ENDIAN(BPF_FROM_BE, BPF_REG_A, 16);
		break;

	case SKF_AD_OFF + SKF_AD_PKTTYPE:
		cnt = convert_skb_access(SKF_AD_PKTTYPE, BPF_REG_A, BPF_REG_CTX, insn);
		insn += cnt - 1;
		break;

	case SKF_AD_OFF + SKF_AD_IFINDEX:
	case SKF_AD_OFF + SKF_AD_HATYPE:
		BUILD_BUG_ON(FIELD_SIZEOF(struct net_device, ifindex) != 4);
		BUILD_BUG_ON(FIELD_SIZEOF(struct net_device, type) != 2);

		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, dev),
				      BPF_REG_TMP, BPF_REG_CTX,
				      offsetof(struct sk_buff, dev));
		/* if (tmp != 0) goto pc + 1 */
		*insn++ = BPF_JMP_IMM(BPF_JNE, BPF_REG_TMP, 0, 1);
		*insn++ = BPF_EXIT_INSN();
		if (fp->k == SKF_AD_OFF + SKF_AD_IFINDEX)
			*insn = BPF_LDX_MEM(BPF_W, BPF_REG_A, BPF_REG_TMP,
					    offsetof(struct net_device, ifindex));
		else
			*insn = BPF_LDX_MEM(BPF_H, BPF_REG_A, BPF_REG_TMP,
					    offsetof(struct net_device, type));
		break;

	case SKF_AD_OFF + SKF_AD_MARK:
		cnt = convert_skb_access(SKF_AD_MARK, BPF_REG_A, BPF_REG_CTX, insn);
		insn += cnt - 1;
		break;

	case SKF_AD_OFF + SKF_AD_RXHASH:
		BUILD_BUG_ON(FIELD_SIZEOF(struct sk_buff, rxhash) != 4);

		*insn = BPF_LDX_MEM(BPF_W, BPF_REG_A, BPF_REG_CTX,
				    offsetof(struct sk_buff, rxhash));
		break;

	case SKF_AD_OFF + SKF_AD_QUEUE:
		cnt = convert_skb_access(SKF_AD_QUEUE, BPF_REG_A, BPF_REG_CTX, insn);
		insn += cnt - 1;
		break;

	case SKF_AD_OFF + SKF_AD_VLAN_TAG:
		cnt = convert_skb_access(SKF_AD_VLAN_TAG,
					 BPF_REG_A, BPF_REG_CTX, insn);
		insn += cnt - 1;
		break;

	case SKF_AD_OFF + SKF_AD_VLAN_TAG_PRESENT:
		cnt = convert_skb_access(SKF_AD_VLAN_TAG_PRESENT,
					 BPF_REG_A, BPF_REG_CTX, insn);
		insn += cnt - 1;
		break;

	case SKF_AD_OFF + SKF_AD_VLAN_TPID:
		BUILD_BUG_ON(FIELD_SIZEOF(struct sk_buff, vlan_proto) != 2);

		/* A = *(u16 *) (CTX + offsetof(vlan_proto)) */
		*insn++ = BPF_LDX_MEM(BPF_H, BPF_REG_A, BPF_REG_CTX,
				      offsetof(struct sk_buff, vlan_proto));
		/* A = ntohs(A) [emitting a nop or swap16] */
		*insn = BPF_ENDIAN(BPF_FROM_BE, BPF_REG_A, 16);
		break;

	case SKF_AD_OFF + SKF_AD_PAY_OFFSET:
	case SKF_AD_OFF + SKF_AD_NLATTR:
	case SKF_AD_OFF + SKF_AD_NLATTR_NEST:
	case SKF_AD_OFF + SKF_AD_CPU:
	case SKF_AD_OFF + SKF_AD_RANDOM:
		/* arg1 = CTX */
		*insn++ = BPF_MOV64_REG(BPF_REG_ARG1, BPF_REG_CTX);
		/* arg2 = A */
		*insn++ = BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_A);
		/* arg3 = X */
		*insn++ = BPF_MOV64_REG(BPF_REG_ARG3, BPF_REG_X);
		/* Emit call(arg1=CTX, arg2=A, arg3=X) */
		switch (fp->k) {
		case SKF_AD_OFF + SKF_AD_PAY_OFFSET:
			*insn = BPF_EMIT_CALL(__skb_get_pay_offset);
			break;
		case SKF_AD_OFF + SKF_AD_NLATTR:
			*insn = BPF_EMIT_CALL(__skb_get_nlattr);
			break;
		case SKF_AD_OFF + SKF_AD_NLATTR_NEST:
			*insn = BPF_EMIT_CALL(__skb_get_nlattr_nest);
			break;
		case SKF_AD_OFF + SKF_AD_CPU:
			*insn = BPF_EMIT_CALL(__get_raw_cpu_id);
			break;
		case SKF_AD_OFF + SKF_AD_RANDOM:
			*insn = BPF_EMIT_CALL(bpf_user_rnd_u32);
			bpf_user_rnd_init_once();
			break;
		}
		break;

	case SKF_AD_OFF + SKF_AD_ALU_XOR_X:
		/* A ^= X */
		*insn = BPF_ALU32_REG(BPF_XOR, BPF_REG_A, BPF_REG_X);
		break;

	default:
		/* This is just a dummy call to avoid letting the compiler
		 * evict __bpf_call_base() as an optimization. Placed here
		 * where no-one bothers.
		 */
		WARN_ONCE(__bpf_call_base(0, 0, 0, 0, 0) != 0,
			  "bpf_convert_ctx_access: unexpected opcode");
		return false;
	}

	*insnp = insn;
	return true;
}

/**
 *	bpf_convert_filter - convert filter program
 *	@prog: the user passed filter program
 *	@len: the length of the user passed filter program
 *	@new_prog: allocated 'struct bpf_prog' or NULL
 *	@new_len: pointer to store length of converted program
 *
 * Remap 'sock_filter' style classic BPF (cBPF) instruction set to 'bpf_insn'
 * style extended BPF (eBPF).
 * Conversion workflow:
 *
 * 1) First pass for calculating the new program length:
 *   bpf_convert_filter(old_prog, old_len, NULL, &new_len)
 *
 * 2) 2nd pass to remap in two passes: 1st pass finds new
 *    jump offsets, 2nd pass remapping:
 *   bpf_convert_filter(old_prog, old_len, new_prog, &new_len);
 */
static int bpf_convert_filter(struct sock_filter *prog, int len,
			      struct bpf_prog *new_prog, int *new_len)
{
	int new_flen = 0, pass = 0, target, i, stack_off;
	struct bpf_insn *new_insn, *first_insn = NULL;
	struct sock_filter *fp;
	int *addrs = NULL;
	u8 bpf_src;

	BUILD_BUG_ON(BPF_MEMWORDS * sizeof(u32) > MAX_BPF_STACK);
	BUILD_BUG_ON(BPF_REG_FP + 1 != MAX_BPF_REG);

	if (len <= 0 || len > BPF_MAXINSNS)
		return -EINVAL;

	if (new_prog) {
		first_insn = new_prog->insnsi;
		addrs = kcalloc(len, sizeof(*addrs),
				GFP_KERNEL | __GFP_NOWARN);
		if (!addrs)
			return -ENOMEM;
	}

do_pass:
	new_insn = first_insn;
	fp = prog;

	/* Classic BPF related prologue emission. */
	if (new_prog) {
		/* Classic BPF expects A and X to be reset first. These need
		 * to be guaranteed to be the first two instructions.
		 */
		*new_insn++ = BPF_ALU64_REG(BPF_XOR, BPF_REG_A, BPF_REG_A);
		*new_insn++ = BPF_ALU64_REG(BPF_XOR, BPF_REG_X, BPF_REG_X);

		/* All programs must keep CTX in callee saved BPF_REG_CTX.
		 * In eBPF case it's done by the compiler, here we need to
		 * do this ourself. Initial CTX is present in BPF_REG_ARG1.
		 */
		*new_insn++ = BPF_MOV64_REG(BPF_REG_CTX, BPF_REG_ARG1);
	} else {
		new_insn += 3;
	}

	for (i = 0; i < len; fp++, i++) {
		struct bpf_insn tmp_insns[6] = { };
		struct bpf_insn *insn = tmp_insns;

		if (addrs)
			addrs[i] = new_insn - first_insn;

		switch (fp->code) {
		/* All arithmetic insns and skb loads map as-is. */
		case BPF_ALU | BPF_ADD | BPF_X:
		case BPF_ALU | BPF_ADD | BPF_K:
		case BPF_ALU | BPF_SUB | BPF_X:
		case BPF_ALU | BPF_SUB | BPF_K:
		case BPF_ALU | BPF_AND | BPF_X:
		case BPF_ALU | BPF_AND | BPF_K:
		case BPF_ALU | BPF_OR | BPF_X:
		case BPF_ALU | BPF_OR | BPF_K:
		case BPF_ALU | BPF_LSH | BPF_X:
		case BPF_ALU | BPF_LSH | BPF_K:
		case BPF_ALU | BPF_RSH | BPF_X:
		case BPF_ALU | BPF_RSH | BPF_K:
		case BPF_ALU | BPF_XOR | BPF_X:
		case BPF_ALU | BPF_XOR | BPF_K:
		case BPF_ALU | BPF_MUL | BPF_X:
		case BPF_ALU | BPF_MUL | BPF_K:
		case BPF_ALU | BPF_DIV | BPF_X:
		case BPF_ALU | BPF_DIV | BPF_K:
		case BPF_ALU | BPF_MOD | BPF_X:
		case BPF_ALU | BPF_MOD | BPF_K:
		case BPF_ALU | BPF_NEG:
		case BPF_LD | BPF_ABS | BPF_W:
		case BPF_LD | BPF_ABS | BPF_H:
		case BPF_LD | BPF_ABS | BPF_B:
		case BPF_LD | BPF_IND | BPF_W:
		case BPF_LD | BPF_IND | BPF_H:
		case BPF_LD | BPF_IND | BPF_B:
			/* Check for overloaded BPF extension and
			 * directly convert it if found, otherwise
			 * just move on with mapping.
			 */
			if (BPF_CLASS(fp->code) == BPF_LD &&
			    BPF_MODE(fp->code) == BPF_ABS &&
			    convert_bpf_extensions(fp, &insn))
				break;

			if (fp->code == (BPF_ALU | BPF_DIV | BPF_X) ||
			    fp->code == (BPF_ALU | BPF_MOD | BPF_X)) {
				*insn++ = BPF_MOV32_REG(BPF_REG_X, BPF_REG_X);
				/* Error with exception code on div/mod by 0.
				 * For cBPF programs, this was always return 0.
				 */
				*insn++ = BPF_JMP_IMM(BPF_JNE, BPF_REG_X, 0, 2);
				*insn++ = BPF_ALU32_REG(BPF_XOR, BPF_REG_A, BPF_REG_A);
				*insn++ = BPF_EXIT_INSN();
			}

			*insn = BPF_RAW_INSN(fp->code, BPF_REG_A, BPF_REG_X, 0, fp->k);
			break;

		/* Jump transformation cannot use BPF block macros
		 * everywhere as offset calculation and target updates
		 * require a bit more work than the rest, i.e. jump
		 * opcodes map as-is, but offsets need adjustment.
		 */

#define BPF_EMIT_JMP							\
	do {								\
		const s32 off_min = S16_MIN, off_max = S16_MAX;		\
		s32 off;						\
									\
		if (target >= len || target < 0)			\
			goto err;					\
		off = addrs ? addrs[target] - addrs[i] - 1 : 0;		\
		/* Adjust pc relative offset for 2nd or 3rd insn. */	\
		off -= insn - tmp_insns;				\
		/* Reject anything not fitting into insn->off. */	\
		if (off < off_min || off > off_max)			\
			goto err;					\
		insn->off = off;					\
	} while (0)

		case BPF_JMP | BPF_JA:
			target = i + fp->k + 1;
			insn->code = fp->code;
			BPF_EMIT_JMP;
			break;

		case BPF_JMP | BPF_JEQ | BPF_K:
		case BPF_JMP | BPF_JEQ | BPF_X:
		case BPF_JMP | BPF_JSET | BPF_K:
		case BPF_JMP | BPF_JSET | BPF_X:
		case BPF_JMP | BPF_JGT | BPF_K:
		case BPF_JMP | BPF_JGT | BPF_X:
		case BPF_JMP | BPF_JGE | BPF_K:
		case BPF_JMP | BPF_JGE | BPF_X:
			if (BPF_SRC(fp->code) == BPF_K && (int) fp->k < 0) {
				/* BPF immediates are signed, zero extend
				 * immediate into tmp register and use it
				 * in compare insn.
				 */
				*insn++ = BPF_MOV32_IMM(BPF_REG_TMP, fp->k);

				insn->dst_reg = BPF_REG_A;
				insn->src_reg = BPF_REG_TMP;
				bpf_src = BPF_X;
			} else {
				insn->dst_reg = BPF_REG_A;
				insn->imm = fp->k;
				bpf_src = BPF_SRC(fp->code);
				insn->src_reg = bpf_src == BPF_X ? BPF_REG_X : 0;
			}

			/* Common case where 'jump_false' is next insn. */
			if (fp->jf == 0) {
				insn->code = BPF_JMP | BPF_OP(fp->code) | bpf_src;
				target = i + fp->jt + 1;
				BPF_EMIT_JMP;
				break;
			}

			/* Convert some jumps when 'jump_true' is next insn. */
			if (fp->jt == 0) {
				switch (BPF_OP(fp->code)) {
				case BPF_JEQ:
					insn->code = BPF_JMP | BPF_JNE | bpf_src;
					break;
				case BPF_JGT:
					insn->code = BPF_JMP | BPF_JLE | bpf_src;
					break;
				case BPF_JGE:
					insn->code = BPF_JMP | BPF_JLT | bpf_src;
					break;
				default:
					goto jmp_rest;
				}

				target = i + fp->jf + 1;
				BPF_EMIT_JMP;
				break;
			}
jmp_rest:
			/* Other jumps are mapped into two insns: Jxx and JA. */
			target = i + fp->jt + 1;
			insn->code = BPF_JMP | BPF_OP(fp->code) | bpf_src;
			BPF_EMIT_JMP;
			insn++;

			insn->code = BPF_JMP | BPF_JA;
			target = i + fp->jf + 1;
			BPF_EMIT_JMP;
			break;

		/* ldxb 4 * ([14] & 0xf) is remaped into 6 insns. */
		case BPF_LDX | BPF_MSH | BPF_B:
			/* tmp = A */
			*insn++ = BPF_MOV64_REG(BPF_REG_TMP, BPF_REG_A);
			/* A = BPF_R0 = *(u8 *) (skb->data + K) */
			*insn++ = BPF_LD_ABS(BPF_B, fp->k);
			/* A &= 0xf */
			*insn++ = BPF_ALU32_IMM(BPF_AND, BPF_REG_A, 0xf);
			/* A <<= 2 */
			*insn++ = BPF_ALU32_IMM(BPF_LSH, BPF_REG_A, 2);
			/* X = A */
			*insn++ = BPF_MOV64_REG(BPF_REG_X, BPF_REG_A);
			/* A = tmp */
			*insn = BPF_MOV64_REG(BPF_REG_A, BPF_REG_TMP);
			break;

		/* RET_K is remaped into 2 insns. RET_A case doesn't need an
		 * extra mov as BPF_REG_0 is already mapped into BPF_REG_A.
		 */
		case BPF_RET | BPF_A:
		case BPF_RET | BPF_K:
			if (BPF_RVAL(fp->code) == BPF_K)
				*insn++ = BPF_MOV32_RAW(BPF_K, BPF_REG_0,
							0, fp->k);
			*insn = BPF_EXIT_INSN();
			break;

		/* Store to stack. */
		case BPF_ST:
		case BPF_STX:
			stack_off = fp->k * 4  + 4;
			*insn = BPF_STX_MEM(BPF_W, BPF_REG_FP, BPF_CLASS(fp->code) ==
					    BPF_ST ? BPF_REG_A : BPF_REG_X,
					    -stack_off);
			/* check_load_and_stores() verifies that classic BPF can
			 * load from stack only after write, so tracking
			 * stack_depth for ST|STX insns is enough
			 */
			if (new_prog && new_prog->aux->stack_depth < stack_off)
				new_prog->aux->stack_depth = stack_off;
			break;

		/* Load from stack. */
		case BPF_LD | BPF_MEM:
		case BPF_LDX | BPF_MEM:
			stack_off = fp->k * 4  + 4;
			*insn = BPF_LDX_MEM(BPF_W, BPF_CLASS(fp->code) == BPF_LD  ?
					    BPF_REG_A : BPF_REG_X, BPF_REG_FP,
					    -stack_off);
			break;

		/* A = K or X = K */
		case BPF_LD | BPF_IMM:
		case BPF_LDX | BPF_IMM:
			*insn = BPF_MOV32_IMM(BPF_CLASS(fp->code) == BPF_LD ?
					      BPF_REG_A : BPF_REG_X, fp->k);
			break;

		/* X = A */
		case BPF_MISC | BPF_TAX:
			*insn = BPF_MOV64_REG(BPF_REG_X, BPF_REG_A);
			break;

		/* A = X */
		case BPF_MISC | BPF_TXA:
			*insn = BPF_MOV64_REG(BPF_REG_A, BPF_REG_X);
			break;

		/* A = skb->len or X = skb->len */
		case BPF_LD | BPF_W | BPF_LEN:
		case BPF_LDX | BPF_W | BPF_LEN:
			*insn = BPF_LDX_MEM(BPF_W, BPF_CLASS(fp->code) == BPF_LD ?
					    BPF_REG_A : BPF_REG_X, BPF_REG_CTX,
					    offsetof(struct sk_buff, len));
			break;

		/* Access seccomp_data fields. */
		case BPF_LDX | BPF_ABS | BPF_W:
			/* A = *(u32 *) (ctx + K) */
			*insn = BPF_LDX_MEM(BPF_W, BPF_REG_A, BPF_REG_CTX, fp->k);
			break;

		/* Unknown instruction. */
		default:
			goto err;
		}

		insn++;
		if (new_prog)
			memcpy(new_insn, tmp_insns,
			       sizeof(*insn) * (insn - tmp_insns));
		new_insn += insn - tmp_insns;
	}

	if (!new_prog) {
		/* Only calculating new length. */
		*new_len = new_insn - first_insn;
		return 0;
	}

	pass++;
	if (new_flen != new_insn - first_insn) {
		new_flen = new_insn - first_insn;
		if (pass > 2)
			goto err;
		goto do_pass;
	}

	kfree(addrs);
	if (WARN_ONCE(*new_len != new_flen,
		      "BPF: length mismatch (expected %d, got %d)\n",
		      *new_len, new_flen)) {
		return -EINVAL;
	}
	return 0;
err:
	kfree(addrs);
	return -EINVAL;
}

/* Security:
 *
 * As we dont want to clear mem[] array for each packet going through
 * __bpf_prog_run(), we check that filter loaded by user never try to read
 * a cell if not previously written, and we check all branches to be sure
 * a malicious user doesn't try to abuse us.
 */
static int check_load_and_stores(const struct sock_filter *filter, int flen)
{
	u16 *masks, memvalid = 0; /* One bit per cell, 16 cells */
	int pc, ret = 0;

	BUILD_BUG_ON(BPF_MEMWORDS > 16);

	masks = kmalloc_array(flen, sizeof(*masks), GFP_KERNEL);
	if (!masks)
		return -ENOMEM;

	memset(masks, 0xff, flen * sizeof(*masks));

	for (pc = 0; pc < flen; pc++) {
		memvalid &= masks[pc];

		switch (filter[pc].code) {
		case BPF_ST:
		case BPF_STX:
			memvalid |= (1 << filter[pc].k);
			break;
		case BPF_LD | BPF_MEM:
		case BPF_LDX | BPF_MEM:
			if (!(memvalid & (1 << filter[pc].k))) {
				ret = -EINVAL;
				goto error;
			}
			break;
		case BPF_JMP | BPF_JA:
			/* A jump must set masks on target */
			masks[pc + 1 + filter[pc].k] &= memvalid;
			memvalid = ~0;
			break;
		case BPF_JMP | BPF_JEQ | BPF_K:
		case BPF_JMP | BPF_JEQ | BPF_X:
		case BPF_JMP | BPF_JGE | BPF_K:
		case BPF_JMP | BPF_JGE | BPF_X:
		case BPF_JMP | BPF_JGT | BPF_K:
		case BPF_JMP | BPF_JGT | BPF_X:
		case BPF_JMP | BPF_JSET | BPF_K:
		case BPF_JMP | BPF_JSET | BPF_X:
			/* A jump must set masks on targets */
			masks[pc + 1 + filter[pc].jt] &= memvalid;
			masks[pc + 1 + filter[pc].jf] &= memvalid;
			memvalid = ~0;
			break;
		}
	}
error:
	kfree(masks);
	return ret;
}

static bool chk_code_allowed(u16 code_to_probe)
{
	static const bool codes[] = {
		/* 32 bit ALU operations */
		[BPF_ALU | BPF_ADD | BPF_K] = true,
		[BPF_ALU | BPF_ADD | BPF_X] = true,
		[BPF_ALU | BPF_SUB | BPF_K] = true,
		[BPF_ALU | BPF_SUB | BPF_X] = true,
		[BPF_ALU | BPF_MUL | BPF_K] = true,
		[BPF_ALU | BPF_MUL | BPF_X] = true,
		[BPF_ALU | BPF_DIV | BPF_K] = true,
		[BPF_ALU | BPF_DIV | BPF_X] = true,
		[BPF_ALU | BPF_MOD | BPF_K] = true,
		[BPF_ALU | BPF_MOD | BPF_X] = true,
		[BPF_ALU | BPF_AND | BPF_K] = true,
		[BPF_ALU | BPF_AND | BPF_X] = true,
		[BPF_ALU | BPF_OR | BPF_K] = true,
		[BPF_ALU | BPF_OR | BPF_X] = true,
		[BPF_ALU | BPF_XOR | BPF_K] = true,
		[BPF_ALU | BPF_XOR | BPF_X] = true,
		[BPF_ALU | BPF_LSH | BPF_K] = true,
		[BPF_ALU | BPF_LSH | BPF_X] = true,
		[BPF_ALU | BPF_RSH | BPF_K] = true,
		[BPF_ALU | BPF_RSH | BPF_X] = true,
		[BPF_ALU | BPF_NEG] = true,
		/* Load instructions */
		[BPF_LD | BPF_W | BPF_ABS] = true,
		[BPF_LD | BPF_H | BPF_ABS] = true,
		[BPF_LD | BPF_B | BPF_ABS] = true,
		[BPF_LD | BPF_W | BPF_LEN] = true,
		[BPF_LD | BPF_W | BPF_IND] = true,
		[BPF_LD | BPF_H | BPF_IND] = true,
		[BPF_LD | BPF_B | BPF_IND] = true,
		[BPF_LD | BPF_IMM] = true,
		[BPF_LD | BPF_MEM] = true,
		[BPF_LDX | BPF_W | BPF_LEN] = true,
		[BPF_LDX | BPF_B | BPF_MSH] = true,
		[BPF_LDX | BPF_IMM] = true,
		[BPF_LDX | BPF_MEM] = true,
		/* Store instructions */
		[BPF_ST] = true,
		[BPF_STX] = true,
		/* Misc instructions */
		[BPF_MISC | BPF_TAX] = true,
		[BPF_MISC | BPF_TXA] = true,
		/* Return instructions */
		[BPF_RET | BPF_K] = true,
		[BPF_RET | BPF_A] = true,
		/* Jump instructions */
		[BPF_JMP | BPF_JA] = true,
		[BPF_JMP | BPF_JEQ | BPF_K] = true,
		[BPF_JMP | BPF_JEQ | BPF_X] = true,
		[BPF_JMP | BPF_JGE | BPF_K] = true,
		[BPF_JMP | BPF_JGE | BPF_X] = true,
		[BPF_JMP | BPF_JGT | BPF_K] = true,
		[BPF_JMP | BPF_JGT | BPF_X] = true,
		[BPF_JMP | BPF_JSET | BPF_K] = true,
		[BPF_JMP | BPF_JSET | BPF_X] = true,
	};

	if (code_to_probe >= ARRAY_SIZE(codes))
		return false;

	return codes[code_to_probe];
}

static bool bpf_check_basics_ok(const struct sock_filter *filter,
				unsigned int flen)
{
	if (filter == NULL)
		return false;
	if (flen == 0 || flen > BPF_MAXINSNS)
		return false;

	return true;
}

/**
 *	bpf_check_classic - verify socket filter code
 *	@filter: filter to verify
 *	@flen: length of filter
 *
 * Check the user's filter code. If we let some ugly
 * filter code slip through kaboom! The filter must contain
 * no references or jumps that are out of range, no illegal
 * instructions, and must end with a RET instruction.
 *
 * All jumps are forward as they are not signed.
 *
 * Returns 0 if the rule set is legal or -EINVAL if not.
 */
static int bpf_check_classic(const struct sock_filter *filter,
			     unsigned int flen)
{
	bool anc_found;
	int pc;

	/* Check the filter code now */
	for (pc = 0; pc < flen; pc++) {
		const struct sock_filter *ftest = &filter[pc];

		/* May we actually operate on this code? */
		if (!chk_code_allowed(ftest->code))
			return -EINVAL;

		/* Some instructions need special checks */
		switch (ftest->code) {
		case BPF_ALU | BPF_DIV | BPF_K:
		case BPF_ALU | BPF_MOD | BPF_K:
			/* Check for division by zero */
			if (ftest->k == 0)
				return -EINVAL;
			break;
		case BPF_ALU | BPF_LSH | BPF_K:
		case BPF_ALU | BPF_RSH | BPF_K:
			if (ftest->k >= 32)
				return -EINVAL;
			break;
		case BPF_LD | BPF_MEM:
		case BPF_LDX | BPF_MEM:
		case BPF_ST:
		case BPF_STX:
			/* Check for invalid memory addresses */
			if (ftest->k >= BPF_MEMWORDS)
				return -EINVAL;
			break;
		case BPF_JMP | BPF_JA:
			/* Note, the large ftest->k might cause loops.
			 * Compare this with conditional jumps below,
			 * where offsets are limited. --ANK (981016)
			 */
			if (ftest->k >= (unsigned int)(flen - pc - 1))
				return -EINVAL;
			break;
		case BPF_JMP | BPF_JEQ | BPF_K:
		case BPF_JMP | BPF_JEQ | BPF_X:
		case BPF_JMP | BPF_JGE | BPF_K:
		case BPF_JMP | BPF_JGE | BPF_X:
		case BPF_JMP | BPF_JGT | BPF_K:
		case BPF_JMP | BPF_JGT | BPF_X:
		case BPF_JMP | BPF_JSET | BPF_K:
		case BPF_JMP | BPF_JSET | BPF_X:
			/* Both conditionals must be safe */
			if (pc + ftest->jt + 1 >= flen ||
			    pc + ftest->jf + 1 >= flen)
				return -EINVAL;
			break;
		case BPF_LD | BPF_W | BPF_ABS:
		case BPF_LD | BPF_H | BPF_ABS:
		case BPF_LD | BPF_B | BPF_ABS:
			anc_found = false;
			if (bpf_anc_helper(ftest) & BPF_ANC)
				anc_found = true;
			/* Ancillary operation unknown or unsupported */
			if (anc_found == false && ftest->k >= SKF_AD_OFF)
				return -EINVAL;
		}
	}

	/* Last instruction must be a RET code */
	switch (filter[flen - 1].code) {
	case BPF_RET | BPF_K:
	case BPF_RET | BPF_A:
		return check_load_and_stores(filter, flen);
	}

	return -EINVAL;
}

static int bpf_prog_store_orig_filter(struct bpf_prog *fp,
				      const struct sock_fprog *fprog)
{
	unsigned int fsize = bpf_classic_proglen(fprog);
	struct sock_fprog_kern *fkprog;

	fp->orig_prog = kmalloc(sizeof(*fkprog), GFP_KERNEL);
	if (!fp->orig_prog)
		return -ENOMEM;

	fkprog = fp->orig_prog;
	fkprog->len = fprog->len;

	fkprog->filter = kmemdup(fp->insns, fsize,
				 GFP_KERNEL | __GFP_NOWARN);
	if (!fkprog->filter) {
		kfree(fp->orig_prog);
		return -ENOMEM;
	}

	return 0;
}


static void bpf_release_orig_filter(struct bpf_prog *fp)
{
	struct sock_fprog_kern *fprog = fp->orig_prog;

	if (fprog) {
		kfree(fprog->filter);
		kfree(fprog);
	}
}

static void __bpf_prog_release(struct bpf_prog *prog)
{
	if (prog->type == BPF_PROG_TYPE_SOCKET_FILTER) {
		bpf_prog_put(prog);
	} else {
		bpf_release_orig_filter(prog);
		bpf_prog_free(prog);
	}
}


/**
 * 	sk_filter_release_rcu - Release a socket filter by rcu_head
 *	@rcu: rcu_head that contains the sk_filter to free
 */

static struct bpf_prog *bpf_migrate_filter(struct bpf_prog *fp)
{
	struct sock_filter *old_prog;
	struct bpf_prog *old_fp;
	int err, new_len, old_len = fp->len;

	/* We are free to overwrite insns et al right here as it
	 * won't be used at this point in time anymore internally
	 * after the migration to the internal BPF instruction
	 * representation.
	 */
	BUILD_BUG_ON(sizeof(struct sock_filter) !=
		     sizeof(struct bpf_insn));

	/* Conversion cannot happen on overlapping memory areas,
	 * so we need to keep the user BPF around until the 2nd
	 * pass. At this time, the user BPF is stored in fp->insns.
	 */
	old_prog = kmemdup(fp->insns, old_len * sizeof(struct sock_filter),
			   GFP_KERNEL | __GFP_NOWARN);
	if (!old_prog) {
		err = -ENOMEM;
		goto out_err;
	}

	/* 1st pass: calculate the new program length. */
	err = bpf_convert_filter(old_prog, old_len, NULL, &new_len);
	if (err)
		goto out_err_free;

	/* Expand fp for appending the new filter representation. */
	old_fp = fp;
	fp = bpf_prog_realloc(old_fp, bpf_prog_size(new_len), 0);
	if (!fp) {
		/* The old_fp is still around in case we couldn't
		 * allocate new memory, so uncharge on that one.
		 */
		fp = old_fp;
		err = -ENOMEM;
		goto out_err_free;
	}

	fp->len = new_len;

	/* 2nd pass: remap sock_filter insns into bpf_insn insns. */
	err = bpf_convert_filter(old_prog, old_len, fp, &new_len);
	if (err)
		/* 2nd bpf_convert_filter() can fail only if it fails
		 * to allocate memory, remapping must succeed. Note,
		 * that at this time old_fp has already been released
		 * by krealloc().
		 */
		goto out_err_free;

	fp = bpf_prog_select_runtime(fp, &err);
	if (err)
		goto out_err_free;

	kfree(old_prog);
	return fp;

out_err_free:
	kfree(old_prog);
out_err:
	__bpf_prog_release(fp);
	return ERR_PTR(err);
}

struct bpf_prog *bpf_prepare_filter(struct bpf_prog *fp,
				    bpf_aux_classic_check_t trans)
{
	int err;

	fp->bpf_func = NULL;
	fp->jited = 0;

	err = bpf_check_classic(fp->insns, fp->len);
	if (err) {
		__bpf_prog_release(fp);
		return ERR_PTR(err);
	}

	/* There might be additional checks and transformations
	 * needed on classic filters, f.e. in case of seccomp.
	 */
	if (trans) {
		err = trans(fp->insns, fp->len);
		if (err) {
			__bpf_prog_release(fp);
			return ERR_PTR(err);
		}
	}

	/* Probe if we can JIT compile the filter and if so, do
	 * the compilation of the filter.
	 */
	bpf_jit_compile(fp);

	/* JIT compiler couldn't process this filter, so do the
	 * internal BPF translation for the optimized interpreter.
	 */
	if (!fp->jited)
		fp = bpf_migrate_filter(fp);

	return fp;
}

/**
 *	bpf_prog_create - create an unattached filter
 *	@pfp: the unattached filter that is created
 *	@fprog: the filter program
 *
 * Create a filter independent of any socket. We first run some
 * sanity checks on it to make sure it does not explode on us later.
 * If an error occurs or there is insufficient memory for the filter
 * a negative errno code is returned. On success the return is zero.
 */
int bpf_prog_create(struct bpf_prog **pfp, struct sock_fprog_kern *fprog)
{
	unsigned int fsize = bpf_classic_proglen(fprog);
	struct bpf_prog *fp;

	/* Make sure new filter is there and in the right amounts. */
	if (!bpf_check_basics_ok(fprog->filter, fprog->len))
		return -EINVAL;

	fp = bpf_prog_alloc(bpf_prog_size(fprog->len), 0);
	if (!fp)
		return -ENOMEM;

	memcpy(fp->insns, fprog->filter, fsize);

	fp->len = fprog->len;
	/* Since unattached filters are not copied back to user
	 * space through sk_get_filter(), we do not need to hold
	 * a copy here, and can spare us the work.
	 */
	fp->orig_prog = NULL;

	/* bpf_prepare_filter() already takes care of freeing
	 * memory in case something goes wrong.
	 */
	fp = bpf_prepare_filter(fp, NULL);
	if (IS_ERR(fp))
		return PTR_ERR(fp);

	*pfp = fp;
	return 0;
}
EXPORT_SYMBOL_GPL(bpf_prog_create);

/**
 *	bpf_prog_create_from_user - create an unattached filter from user buffer
 *	@pfp: the unattached filter that is created
 *	@fprog: the filter program
 *	@trans: post-classic verifier transformation handler
 *	@save_orig: save classic BPF program
 *
 * This function effectively does the same as bpf_prog_create(), only
 * that it builds up its insns buffer from user space provided buffer.
 * It also allows for passing a bpf_aux_classic_check_t handler.
 */
int bpf_prog_create_from_user(struct bpf_prog **pfp, struct sock_fprog *fprog,
			      bpf_aux_classic_check_t trans, bool save_orig)
{
	unsigned int fsize = bpf_classic_proglen(fprog);
	struct bpf_prog *fp;
	int err;

	/* Make sure new filter is there and in the right amounts. */
	if (!bpf_check_basics_ok(fprog->filter, fprog->len))
		return -EINVAL;

	fp = bpf_prog_alloc(bpf_prog_size(fprog->len), 0);
	if (!fp)
		return -ENOMEM;

	if (copy_from_user(fp->insns, fprog->filter, fsize)) {
		__bpf_prog_free(fp);
		return -EFAULT;
	}

	fp->len = fprog->len;
	fp->orig_prog = NULL;

	if (save_orig) {
		err = bpf_prog_store_orig_filter(fp, fprog);
		if (err) {
			__bpf_prog_free(fp);
			return -ENOMEM;
		}
	}

	/* bpf_prepare_filter() already takes care of freeing
	 * memory in case something goes wrong.
	 */
	fp = bpf_prepare_filter(fp, trans);
	if (IS_ERR(fp))
		return PTR_ERR(fp);

	*pfp = fp;
	return 0;
}
EXPORT_SYMBOL_GPL(bpf_prog_create_from_user);

void bpf_prog_destroy(struct bpf_prog *fp)
{
	__bpf_prog_release(fp);
}
EXPORT_SYMBOL_GPL(bpf_prog_destroy);

/* try to charge the socket memory if there is space available
 * return true on success
 */
static bool __sk_filter_charge(struct sock *sk, struct sk_filter *fp)
{
	u32 filter_size = bpf_prog_size(fp->prog->len);

	/* same check as in sock_kmalloc() */
	if (filter_size <= sysctl_optmem_max &&
	    atomic_read(&sk->sk_omem_alloc) + filter_size < sysctl_optmem_max) {
		atomic_add(filter_size, &sk->sk_omem_alloc);
		return true;
	}
	return false;
}

static int __sk_attach_prog(struct bpf_prog *prog, struct sock *sk)
{
	struct sk_filter *fp, *old_fp;

	fp = kmalloc(sizeof(*fp), GFP_KERNEL);
	if (!fp)
		return -ENOMEM;

	fp->prog = prog;

	if (!__sk_filter_charge(sk, fp)) {
		kfree(fp);
		return -ENOMEM;
	}
	atomic_set(&fp->refcnt, 1);

	old_fp = rcu_dereference_protected(sk->sk_filter,
					   lockdep_sock_is_held(sk));
	rcu_assign_pointer(sk->sk_filter, fp);

	if (old_fp)
		sk_filter_uncharge(sk, old_fp);

	return 0;
}

static int __reuseport_attach_prog(struct bpf_prog *prog, struct sock *sk)
{
	struct bpf_prog *old_prog;

	if (bpf_prog_size(prog->len) > sysctl_optmem_max)
		return -ENOMEM;

#if 0
	if (sk_unhashed(sk) && sk->sk_reuseport) {
		err = reuseport_alloc(sk);
		if (err)
			return err;
	}
#endif
#if 0
	} else if (!rcu_access_pointer(sk->sk_reuseport_cb)) {
		/* The socket doesn't have a reused port so attach the
		 * program directly to the socket logic
		 */
	}
#endif
#if 0
	old_prog = reuseport_attach_prog(sk, prog);
#endif
	if (old_prog)
		bpf_prog_destroy(old_prog);

	return 0;
}


static int __bpf_redirect(struct sk_buff *skb, struct net_device *dev, u32 flags)
{
	return -EOPNOTSUPP;
}

static
struct bpf_prog *__get_filter(struct sock_fprog *fprog, struct sock *sk)
{
	unsigned int fsize = bpf_classic_proglen(fprog);
	struct bpf_prog *prog;
	int err;

	if (sock_flag(sk, SOCK_FILTER_LOCKED))
		return ERR_PTR(-EPERM);

	/* Make sure new filter is there and in the right amounts. */
	if (!bpf_check_basics_ok(fprog->filter, fprog->len))
		return ERR_PTR(-EINVAL);

	prog = bpf_prog_alloc(bpf_prog_size(fprog->len), 0);
	if (!prog)
		return ERR_PTR(-ENOMEM);

	if (copy_from_user(prog->insns, fprog->filter, fsize)) {
		__bpf_prog_free(prog);
		return ERR_PTR(-EFAULT);
	}

	prog->len = fprog->len;

	err = bpf_prog_store_orig_filter(prog, fprog);
	if (err) {
		__bpf_prog_free(prog);
		return ERR_PTR(-ENOMEM);
	}

	/* bpf_prepare_filter() already takes care of freeing
	 * memory in case something goes wrong.
	 */
	return bpf_prepare_filter(prog, NULL);
}

/**
 *	sk_attach_filter - attach a socket filter
 *	@fprog: the filter program
 *	@sk: the socket
 *
 *	Attaches the specified filter to the socket...
 */
int sk_attach_filter(struct sock_fprog *fprog, struct sock *sk)
{
	struct bpf_prog *prog = __get_filter(fprog, sk);
	int err;

	if (IS_ERR(prog))
		return PTR_ERR(prog);

	err = __sk_attach_prog(prog, sk);
	if (err < 0) {
		__bpf_prog_release(prog);
		return err;
	}

	return 0;
}
/* try to charge the socket memory if there is space available */
EXPORT_SYMBOL_GPL(sk_attach_filter);

int sk_reuseport_attach_filter(struct sock_fprog *fprog, struct sock *sk)
{
	struct bpf_prog *prog = __get_filter(fprog, sk);
	int err;

	if (IS_ERR(prog))
		return PTR_ERR(prog);

	err = __reuseport_attach_prog(prog, sk);
	if (err < 0) {
		__bpf_prog_release(prog);
		return err;
	}

	return 0;
}

static struct bpf_prog *__get_bpf(u32 ufd, struct sock *sk)
{
	if (sock_flag(sk, SOCK_FILTER_LOCKED))
		return ERR_PTR(-EPERM);

	return bpf_prog_get_type(ufd, BPF_PROG_TYPE_SOCKET_FILTER);
}

int sk_attach_bpf(u32 ufd, struct sock *sk)
{
	struct bpf_prog *prog = __get_bpf(ufd, sk);
	int err;

	if (IS_ERR(prog))
		return PTR_ERR(prog);

	err = __sk_attach_prog(prog, sk);
	if (err < 0) {
		bpf_prog_put(prog);
		return err;
	}

	return 0;
}

int sk_reuseport_attach_bpf(u32 ufd, struct sock *sk)
{
	struct bpf_prog *prog = __get_bpf(ufd, sk);
	int err;

	if (IS_ERR(prog))
		return PTR_ERR(prog);

	err = __reuseport_attach_prog(prog, sk);
	if (err < 0) {
		bpf_prog_put(prog);
		return err;
	}

	return 0;
}

struct bpf_scratchpad {
	union {
		__be32 diff[MAX_BPF_STACK / sizeof(__be32)];
		u8     buff[MAX_BPF_STACK];
	};
};

#if 0
static DEFINE_PER_CPU(struct bpf_scratchpad, bpf_sp);
#endif

static inline void bpf_compute_data_pointers(struct sk_buff *skb)
{
	/* stub */
}

static inline int __bpf_try_make_writable(struct sk_buff *skb,
					  unsigned int write_len)
{
	return skb_make_writable(skb, write_len);
}

static inline int bpf_try_make_writable(struct sk_buff *skb,
					unsigned int write_len)
{
	int err = __bpf_try_make_writable(skb, write_len);

	bpf_compute_data_pointers(skb);
	return err;
}

static inline bool skb_pkt_type_ok(u32 pkt_type)
{
	return pkt_type == PACKET_HOST ||
	       pkt_type == PACKET_BROADCAST ||
	       pkt_type == PACKET_MULTICAST ||
	       pkt_type == PACKET_OTHERHOST ||
	       pkt_type == PACKET_OUTGOING;
}

static inline int __skb_grow_rcsum(struct sk_buff *skb, unsigned int len)
{
	return -EOPNOTSUPP;
}

static inline int __skb_trim_rcsum(struct sk_buff *skb, unsigned int len)
{
	return 0;
}

static inline void skb_gso_reset(struct sk_buff *skb)
{
}

static inline void _trace_xdp_redirect(struct net_device *dev, struct bpf_prog *xdp, int index) {}
static inline void _trace_xdp_redirect_err(struct net_device *dev, struct bpf_prog *xdp, int index, int err) {}
static inline void _trace_xdp_redirect_map(struct net_device *dev, struct bpf_prog *xdp, struct net_device *fwd, struct bpf_map *map, int index) {}
static inline void _trace_xdp_redirect_map_err(struct net_device *dev, struct bpf_prog *xdp, struct net_device *fwd, struct bpf_map *map, int index, int err) {}

static inline u32 skb_mac_header_len(const struct sk_buff *skb) { return skb->mac_len; }

static inline void bpf_pull_mac_rcsum_stub(struct sk_buff *skb)
{
}

BPF_CALL_5(bpf_skb_store_bytes, struct sk_buff *, skb, u32, offset,
	   const void *, from, u32, len, u64, flags)
{
	return -EOPNOTSUPP;
}

static const struct bpf_func_proto bpf_skb_store_bytes_proto = {
	.func		= bpf_skb_store_bytes,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_MEM,
	.arg4_type	= ARG_CONST_SIZE,
	.arg5_type	= ARG_ANYTHING,
};

BPF_CALL_4(bpf_skb_load_bytes, const struct sk_buff *, skb, u32, offset,
	   void *, to, u32, len)
{
	void *ptr;

	if (unlikely(offset > INT_MAX))
		goto err_clear;

	ptr = skb_header_pointer(skb, offset, len, to);
	if (unlikely(!ptr))
		goto err_clear;
	if (ptr != to)
		memcpy(to, ptr, len);

	return 0;
err_clear:
	memset(to, 0, len);
	return -EFAULT;
}

static const struct bpf_func_proto bpf_skb_load_bytes_proto = {
	.func		= bpf_skb_load_bytes,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg4_type	= ARG_CONST_SIZE,
};

BPF_CALL_2(bpf_skb_pull_data, struct sk_buff *, skb, u32, len)
{
	/* Idea is the following: should the needed direct read/write
	 * test fail during runtime, we can pull in more data and redo
	 * again, since implicitly, we invalidate previous checks here.
	 *
	 * Or, since we know how much we need to make read/writeable,
	 * this can be done once at the program beginning for direct
	 * access case. By this we overcome limitations of only current
	 * headroom being accessible.
	 */
	return bpf_try_make_writable(skb, len ? : skb_headlen(skb));
}

static const struct bpf_func_proto bpf_skb_pull_data_proto = {
	.func		= bpf_skb_pull_data,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

#if 0
static int ____bpf_l3_csum_replace(struct sk_buff *skb, u32 header_size,
				   u32 offset, __wsum from, __wsum to,
				   u64 flags)
{
	return -EOPNOTSUPP;
}

static int ____bpf_l4_csum_replace(struct sk_buff *skb, u32 offset,
				   __wsum from, __wsum to, u64 flags)
{
	return -EOPNOTSUPP;
}
#endif
BPF_CALL_5(bpf_l3_csum_replace, struct sk_buff *, skb, u32, offset,
	   u64, from, u64, to, u64, flags)
{
	return -EOPNOTSUPP;
}

static const struct bpf_func_proto bpf_l3_csum_replace_proto = {
	.func		= bpf_l3_csum_replace,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
	.arg5_type	= ARG_ANYTHING,
};

BPF_CALL_5(bpf_l4_csum_replace, struct sk_buff *, skb, u32, offset,
	   u64, from, u64, to, u64, flags)
{
	return -EOPNOTSUPP;
}

static const struct bpf_func_proto bpf_l4_csum_replace_proto = {
	.func		= bpf_l4_csum_replace,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
	.arg5_type	= ARG_ANYTHING,
};

BPF_CALL_5(bpf_csum_diff, __be32 *, from, u32, from_size,
	   __be32 *, to, u32, to_size, __wsum, seed)
{
	return -EOPNOTSUPP;
}

static const struct bpf_func_proto bpf_csum_diff_proto = {
	.func		= bpf_csum_diff,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM,
	.arg2_type	= ARG_CONST_SIZE,
	.arg3_type	= ARG_PTR_TO_MEM,
	.arg4_type	= ARG_CONST_SIZE,
	.arg5_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_csum_update, struct sk_buff *, skb, __wsum, csum)
{
	/* The interface is to be used in combination with bpf_csum_diff()
	 * for direct packet writes. csum rotation for alignment as well
	 * as emulating csum_sub() can be done from the eBPF program.
	 */
	if (skb->ip_summed == CHECKSUM_COMPLETE)
		return (skb->csum = csum_add(skb->csum, csum));

	return -ENOTSUPP;
}

static const struct bpf_func_proto bpf_csum_update_proto = {
	.func		= bpf_csum_update,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,

};


BPF_CALL_2(bpf_skb_change_type, struct sk_buff *, skb, u32, pkt_type)
{
	return -EOPNOTSUPP;
}

static const struct bpf_func_proto bpf_skb_change_type_proto = {
	.func		= bpf_skb_change_type,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

BPF_CALL_4(bpf_skb_adjust_room, struct sk_buff *, skb, s32, len_diff, u32, mode, u64, flags)
{
	return -EOPNOTSUPP;
}

static const struct bpf_func_proto bpf_skb_adjust_room_proto = {
	.func		= bpf_skb_adjust_room,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
};

BPF_CALL_3(bpf_clone_redirect, struct sk_buff *, skb, u32, ifindex, u64, flags)
{
	struct net_device *dev;
	struct sk_buff *clone;

	if (unlikely(flags & ~(BPF_F_INGRESS)))
		return -EINVAL;

	dev = dev_get_by_index_rcu(dev_net(skb->dev), ifindex);
	if (unlikely(!dev))
		return -EINVAL;

	clone = skb_clone(skb, GFP_ATOMIC);
	if (unlikely(!clone))
		return -ENOMEM;
	
	return __bpf_redirect(clone, dev, flags);
}

struct redirect_info {
	u32 ifindex;
	u32 flags;
	struct bpf_map *map;
	struct bpf_map *map_to_flush;
	unsigned long   map_owner;
};

static DEFINE_PER_CPU(struct redirect_info, redirect_info);





static const struct bpf_func_proto bpf_clone_redirect_proto = {
	.func		= bpf_clone_redirect,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_redirect, u32, ifindex, u64, flags)
{
	struct redirect_info *ri = this_cpu_ptr(&redirect_info);

	if (unlikely(flags & ~(BPF_F_INGRESS)))
		return TC_ACT_SHOT;

	ri->ifindex = ifindex;
	ri->flags = flags;
	
	return TC_ACT_REDIRECT;
}

static const struct bpf_func_proto bpf_redirect_proto = {
	.func           = bpf_redirect,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_ANYTHING,
	.arg2_type      = ARG_ANYTHING,
};

BPF_CALL_1(bpf_get_cgroup_classid, const struct sk_buff *, skb)
{
	return 0;
}

static const struct bpf_func_proto bpf_get_cgroup_classid_proto = {
	.func           = bpf_get_cgroup_classid,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};

BPF_CALL_1(bpf_get_route_realm, const struct sk_buff *, skb)
{
	return 0;
}

static const struct bpf_func_proto bpf_get_route_realm_proto = {
	.func           = bpf_get_route_realm,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};

BPF_CALL_1(bpf_get_hash_recalc, struct sk_buff *, skb)
{
	return 0;
}

static const struct bpf_func_proto bpf_get_hash_recalc_proto = {
	.func		= bpf_get_hash_recalc,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
};

BPF_CALL_1(bpf_set_hash_invalid, struct sk_buff *, skb)
{
	return 0;
}

static const struct bpf_func_proto bpf_set_hash_invalid_proto = {
	.func		= bpf_set_hash_invalid,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
};

BPF_CALL_2(bpf_set_hash, struct sk_buff *, skb, u32, hash)
{
	return 0;
}

static const struct bpf_func_proto bpf_set_hash_proto = {
	.func		= bpf_set_hash,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

BPF_CALL_3(bpf_skb_vlan_push, struct sk_buff *, skb, __be16, vlan_proto,
	   u16, vlan_tci)
{
	return -EOPNOTSUPP;
}

const struct bpf_func_proto bpf_skb_vlan_push_proto = {
	.func           = bpf_skb_vlan_push,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_ANYTHING,
	.arg3_type      = ARG_ANYTHING,
};
EXPORT_SYMBOL_GPL(bpf_skb_vlan_push_proto);

BPF_CALL_1(bpf_skb_vlan_pop, struct sk_buff *, skb)
{
	return -EOPNOTSUPP;
}

const struct bpf_func_proto bpf_skb_vlan_pop_proto = {
	.func           = bpf_skb_vlan_pop,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};
EXPORT_SYMBOL_GPL(bpf_skb_vlan_pop_proto);





static int bpf_skb_proto_4_to_6(struct sk_buff *skb)
{
	return -EOPNOTSUPP;
}

static int bpf_skb_proto_6_to_4(struct sk_buff *skb)
{
	return -EOPNOTSUPP;
}

static int bpf_skb_proto_xlat(struct sk_buff *skb, __be16 to_proto)
{
	__be16 from_proto = skb->protocol;

	if (from_proto == htons(ETH_P_IP) &&
	      to_proto == htons(ETH_P_IPV6))
		return bpf_skb_proto_4_to_6(skb);

	if (from_proto == htons(ETH_P_IPV6) &&
	      to_proto == htons(ETH_P_IP))
		return bpf_skb_proto_6_to_4(skb);

	return -ENOTSUPP;
}

BPF_CALL_3(bpf_skb_change_proto, struct sk_buff *, skb, __be16, proto,
	   u64, flags)
{
	int ret;

	ret = bpf_skb_proto_xlat(skb, proto);
	bpf_compute_data_end(skb);
	return ret;
}

static const struct bpf_func_proto bpf_skb_change_proto_proto = {
	.func		= bpf_skb_change_proto,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};





#define BPF_SKB_MAX_LEN SKB_MAX_ALLOC



static u32 __bpf_skb_min_len(const struct sk_buff *skb)
{
	u32 min_len = skb_network_offset(skb);

	if (skb_transport_header_was_set(skb))
		min_len = skb_transport_offset(skb);
	if (skb->ip_summed == CHECKSUM_PARTIAL)
		min_len = skb_checksum_start_offset(skb) +
			  skb->csum_offset + sizeof(__sum16);
	return min_len;
}

static int bpf_skb_grow_rcsum(struct sk_buff *skb, unsigned int new_len)
{
	unsigned int old_len = skb->len;
	int ret;

	ret = __skb_grow_rcsum(skb, new_len);
	if (!ret)
		memset(skb->data + old_len, 0, new_len - old_len);
	return ret;
}

static int bpf_skb_trim_rcsum(struct sk_buff *skb, unsigned int new_len)
{
	return __skb_trim_rcsum(skb, new_len);
}

BPF_CALL_3(bpf_skb_change_tail, struct sk_buff *, skb, u32, new_len,
	   u64, flags)
{
	u32 max_len = BPF_SKB_MAX_LEN;
	u32 min_len = __bpf_skb_min_len(skb);
	int ret;

	if (unlikely(flags || new_len > max_len || new_len < min_len))
		return -EINVAL;
	if (skb->encapsulation)
		return -ENOTSUPP;

	/* The basic idea of this helper is that it's performing the
	 * needed work to either grow or trim an skb, and eBPF program
	 * rewrites the rest via helpers like bpf_skb_store_bytes(),
	 * bpf_lX_csum_replace() and others rather than passing a raw
	 * buffer here. This one is a slow path helper and intended
	 * for replies with control messages.
	 *
	 * Like in bpf_skb_change_proto(), we want to keep this rather
	 * minimal and without protocol specifics so that we are able
	 * to separate concerns as in bpf_skb_store_bytes() should only
	 * be the one responsible for writing buffers.
	 *
	 * It's really expected to be a slow path operation here for
	 * control message replies, so we're implicitly linearizing,
	 * uncloning and drop offloads from the skb by this.
	 */
	ret = __bpf_try_make_writable(skb, skb->len);
	if (!ret) {
		if (new_len > skb->len)
			ret = bpf_skb_grow_rcsum(skb, new_len);
		else if (new_len < skb->len)
			ret = bpf_skb_trim_rcsum(skb, new_len);
		if (!ret && skb_is_gso(skb))
			skb_gso_reset(skb);
	}

	bpf_compute_data_end(skb);
	return ret;
}

static const struct bpf_func_proto bpf_skb_change_tail_proto = {
	.func		= bpf_skb_change_tail,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};

BPF_CALL_3(bpf_skb_change_head, struct sk_buff *, skb, u32, head_room,
	   u64, flags)
{
	u32 max_len = BPF_SKB_MAX_LEN;
	u32 new_len = skb->len + head_room;
	int ret;

	if (unlikely(flags || (!skb_is_gso(skb) && new_len > max_len) ||
		     new_len < skb->len))
		return -EINVAL;

	ret = skb_cow(skb, head_room);
	if (likely(!ret)) {
		/* Idea for this helper is that we currently only
		 * allow to expand on mac header. This means that
		 * skb->protocol network header, etc, stay as is.
		 * Compared to bpf_skb_change_tail(), we're more
		 * flexible due to not needing to linearize or
		 * reset GSO. Intention for this helper is to be
		 * used by an L3 skb that needs to push mac header
		 * for redirection into L2 device.
		 */
		__skb_push(skb, head_room);
		memset(skb->data, 0, head_room);
		skb_reset_mac_header(skb);
		skb_reset_mac_len(skb);
	}

	bpf_compute_data_end(skb);
	return 0;
}

static const struct bpf_func_proto bpf_skb_change_head_proto = {
	.func		= bpf_skb_change_head,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_xdp_adjust_head, struct xdp_buff *, xdp, int, offset)
{
	void *data = xdp->data + offset;

	if (unlikely(data < xdp->data_hard_start ||
		     data > xdp->data_end - ETH_HLEN))
		return -EINVAL;

	xdp->data = data;

	return 0;
}

static const struct bpf_func_proto bpf_xdp_adjust_head_proto = {
	.func		= bpf_xdp_adjust_head,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

static int __bpf_tx_xdp(struct net_device *dev,
			struct bpf_map *map,
			struct xdp_buff *xdp,
			u32 index)
{
	return -EOPNOTSUPP;
}

void xdp_do_flush_map(void)
{
	struct redirect_info *ri = this_cpu_ptr(&redirect_info);
	struct bpf_map *map = ri->map_to_flush;

	ri->map_to_flush = NULL;
	if (map)
		__dev_map_flush(map);
}
EXPORT_SYMBOL_GPL(xdp_do_flush_map);

static inline bool xdp_map_invalid(const struct bpf_prog *xdp_prog,
				   unsigned long aux)
{
	return (unsigned long)xdp_prog->aux != aux;
}

static int xdp_do_redirect_map(struct net_device *dev, struct xdp_buff *xdp,
			       struct bpf_prog *xdp_prog)
{
	struct redirect_info *ri = this_cpu_ptr(&redirect_info);
	unsigned long map_owner = ri->map_owner;
	struct bpf_map *map = ri->map;
	struct net_device *fwd = NULL;
	u32 index = ri->ifindex;
	int err;

	ri->ifindex = 0;
	ri->map = NULL;
	ri->map_owner = 0;

	if (unlikely(xdp_map_invalid(xdp_prog, map_owner))) {
		err = -EFAULT;
		map = NULL;
		goto err;
	}

	fwd = __dev_map_lookup_elem(map, index);
	if (!fwd) {
		err = -EINVAL;
		goto err;
	}
	if (ri->map_to_flush && ri->map_to_flush != map)
		xdp_do_flush_map();

	err = __bpf_tx_xdp(fwd, map, xdp, index);
	if (unlikely(err))
		goto err;

	ri->map_to_flush = map;
	_trace_xdp_redirect_map(dev, xdp_prog, fwd, map, index);
	return 0;
err:
	_trace_xdp_redirect_map_err(dev, xdp_prog, fwd, map, index, err);
	return err;
}

int xdp_do_redirect(struct net_device *dev, struct xdp_buff *xdp,
		    struct bpf_prog *xdp_prog)
{
	struct redirect_info *ri = this_cpu_ptr(&redirect_info);
	struct net_device *fwd;
	u32 index = ri->ifindex;
	int err;

	if (ri->map)
		return xdp_do_redirect_map(dev, xdp, xdp_prog);

	fwd = dev_get_by_index_rcu(dev_net(dev), index);
	ri->ifindex = 0;
	if (unlikely(!fwd)) {
		err = -EINVAL;
		goto err;
	}

	err = __bpf_tx_xdp(fwd, NULL, xdp, 0);
	if (unlikely(err))
		goto err;

	_trace_xdp_redirect(dev, xdp_prog, index);
	return 0;
err:
	_trace_xdp_redirect_err(dev, xdp_prog, index, err);
	return err;
}
EXPORT_SYMBOL_GPL(xdp_do_redirect);

int xdp_do_generic_redirect(struct net_device *dev, struct sk_buff *skb,
			    struct bpf_prog *xdp_prog)
{
	struct redirect_info *ri = this_cpu_ptr(&redirect_info);
	unsigned long map_owner = ri->map_owner;
	struct bpf_map *map = ri->map;
	struct net_device *fwd = NULL;
	u32 index = ri->ifindex;
	unsigned int len;
	int err = 0;

	ri->ifindex = 0;
	ri->map = NULL;
	ri->map_owner = 0;

	if (map) {
		if (unlikely(xdp_map_invalid(xdp_prog, map_owner))) {
			err = -EFAULT;
			map = NULL;
			goto err;
		}
		fwd = __dev_map_lookup_elem(map, index);
	} else {
		fwd = dev_get_by_index_rcu(dev_net(dev), index);
	}
	if (unlikely(!fwd)) {
		err = -EINVAL;
		goto err;
	}

	if (unlikely(!(fwd->flags & IFF_UP))) {
		err = -ENETDOWN;
		goto err;
	}

	len = fwd->mtu + fwd->hard_header_len + VLAN_HLEN;
	if (skb->len > len) {
		err = -EMSGSIZE;
		goto err;
	}

	skb->dev = fwd;
	map ? _trace_xdp_redirect_map(dev, xdp_prog, fwd, map, index)
		: _trace_xdp_redirect(dev, xdp_prog, index);
	return 0;
err:
	map ? _trace_xdp_redirect_map_err(dev, xdp_prog, fwd, map, index, err)
		: _trace_xdp_redirect_err(dev, xdp_prog, index, err);
	return err;
}
EXPORT_SYMBOL_GPL(xdp_do_generic_redirect);

BPF_CALL_2(bpf_xdp_redirect, u32, ifindex, u64, flags)
{
	struct redirect_info *ri = this_cpu_ptr(&redirect_info);

	if (unlikely(flags))
		return XDP_ABORTED;

	ri->ifindex = ifindex;
	ri->flags = flags;
	ri->map = NULL;
	ri->map_owner = 0;

	return XDP_REDIRECT;
}

static const struct bpf_func_proto bpf_xdp_redirect_proto = {
	.func           = bpf_xdp_redirect,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_ANYTHING,
	.arg2_type      = ARG_ANYTHING,
};

BPF_CALL_4(bpf_xdp_redirect_map, struct bpf_map *, map, u32, ifindex, u64, flags,
	   unsigned long, map_owner)
{
	struct redirect_info *ri = this_cpu_ptr(&redirect_info);

	if (unlikely(flags))
		return XDP_ABORTED;

	ri->ifindex = ifindex;
	ri->flags = flags;
	ri->map = map;
	ri->map_owner = map_owner;

	return XDP_REDIRECT;
}

/* Note, arg4 is hidden from users and populated by the verifier
 * with the right pointer.
 */
static const struct bpf_func_proto bpf_xdp_redirect_map_proto = {
	.func           = bpf_xdp_redirect_map,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_CONST_MAP_PTR,
	.arg2_type      = ARG_ANYTHING,
	.arg3_type      = ARG_ANYTHING,
};

bool bpf_helper_changes_pkt_data(void *func)
{
	if (func == bpf_skb_vlan_push ||
	    func == bpf_skb_vlan_pop ||
	    func == bpf_skb_store_bytes ||
	    func == bpf_skb_change_proto ||
	    func == bpf_skb_change_head ||
	    func == bpf_skb_change_tail ||
	    func == bpf_skb_adjust_room ||
	    func == bpf_skb_pull_data ||
	    func == bpf_clone_redirect ||
	    func == bpf_l3_csum_replace ||
	    func == bpf_l4_csum_replace ||
	    func == bpf_xdp_adjust_head)
		return true;

	return false;
}

static unsigned long bpf_skb_copy(void *dst_buff, const void *skb,
				  unsigned long off, unsigned long len)
{
	void *ptr = skb_header_pointer(skb, off, len, dst_buff);

	if (unlikely(!ptr))
		return len;
	if (ptr != dst_buff)
		memcpy(dst_buff, ptr, len);

	return 0;
}

BPF_CALL_5(bpf_skb_event_output, struct sk_buff *, skb, struct bpf_map *, map,
	   u64, flags, void *, meta, u64, meta_size)
{
	u64 skb_size = (flags & BPF_F_CTXLEN_MASK) >> 32;

	if (unlikely(flags & ~(BPF_F_CTXLEN_MASK | BPF_F_INDEX_MASK)))
		return -EINVAL;
	if (unlikely(skb_size > skb->len))
		return -EFAULT;

	return bpf_event_output(map, flags, meta, meta_size, skb, skb_size,
				bpf_skb_copy);
}

static const struct bpf_func_proto bpf_skb_event_output_proto = {
	.func		= bpf_skb_event_output,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_MEM,
	.arg5_type	= ARG_CONST_SIZE,
};

#if 0
static unsigned short bpf_tunnel_key_af(u64 flags)
{
	return flags & BPF_F_TUNINFO_IPV6 ? AF_INET6 : AF_INET;
}
#endif

#if 0
	   const u8 *, from, u32, size)
{
	return -1;
}

static const struct bpf_func_proto bpf_skb_set_tunnel_opt_proto = {
	.func		= bpf_skb_set_tunnel_opt,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_MEM,
	.arg3_type	= ARG_CONST_SIZE,
};
#endif

#if 0
static const struct bpf_func_proto *
bpf_get_skb_set_tunnel_proto(enum bpf_func_id which)
{
	if (!md_dst) {
		/* verification checks that the anonymous struct bpf_tunnel_key
		 * fits into the __sk_buff common part that is shared with
		 * all other skb types.
		 */
		BUILD_BUG_ON(sizeof(struct bpf_tunnel_key) >
			     sizeof(struct __sk_buff));
		return NULL;
	}

	switch (which) {
	case BPF_FUNC_skb_set_tunnel_key:
		return &bpf_skb_set_tunnel_key_proto;
	case BPF_FUNC_skb_set_tunnel_opt:
		return &bpf_skb_set_tunnel_opt_proto;
	default:
		return NULL;
	}
}
#endif

#if 0
BPF_CALL_3(bpf_skb_under_cgroup, struct sk_buff *, skb, struct bpf_map *, map,
	   u32, idx)
{
	return -1;
}

static const struct bpf_func_proto bpf_skb_under_cgroup_proto = {
	.func		= bpf_skb_under_cgroup,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
};

static unsigned long bpf_xdp_copy(void *dst_buff, const void *src_buff,
				  unsigned long off, unsigned long len)
{
	memcpy(dst_buff, src_buff + off, len);
	return 0;
}

BPF_CALL_5(bpf_xdp_event_output, struct xdp_buff *, xdp, struct bpf_map *, map,
	   u64, flags, void *, meta, u64, meta_size)
{
	return -1;
}

static const struct bpf_func_proto bpf_xdp_event_output_proto = {
	.func		= bpf_xdp_event_output,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_MEM,
	.arg5_type	= ARG_CONST_SIZE,
};

BPF_CALL_5(bpf_setsockopt, struct bpf_sock_ops_kern *, bpf_sock,
	   int, level, int, optname, char *, optval, int, optlen)
{
	return -EINVAL;
}

static const struct bpf_func_proto bpf_setsockopt_proto = {
	.func		= bpf_setsockopt,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_MEM,
	.arg5_type	= ARG_CONST_SIZE,
};
#endif

/* Socket helper functions for Android 16 BPF */
BPF_CALL_1(bpf_get_socket_cookie, struct sk_buff *, skb)
{
	return 0;
}

static const struct bpf_func_proto bpf_get_socket_cookie_proto = {
	.func           = bpf_get_socket_cookie,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};

BPF_CALL_1(bpf_get_socket_uid, struct sk_buff *, skb)
{
	struct sock *sk;
	
	if (!skb || !skb->sk)
		return overflowuid;
	
	sk = skb->sk;
	if (!sk || !sk->sk_socket)
		return overflowuid;
	
	/* In 3.10, we use current_fsuid() as fallback */
	return from_kuid_munged(sock_net(sk)->user_ns, current_fsuid());
}

static const struct bpf_func_proto bpf_get_socket_uid_proto = {
	.func           = bpf_get_socket_uid,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
};

BPF_CALL_5(bpf_skb_load_bytes_relative, const struct sk_buff *, skb,
	   u32, offset, void *, to, u32, len, u32, start_header)
{
	u8 *end = skb_tail_pointer(skb);
	u8 *start, *ptr;

	if (unlikely(offset > 0xffff))
		goto err_clear;

	switch (start_header) {
	case BPF_HDR_START_MAC:
		if (unlikely(!skb_mac_header_was_set(skb)))
			goto err_clear;
		start = skb_mac_header(skb);
		break;
	case BPF_HDR_START_NET:
		start = skb_network_header(skb);
		break;
	default:
		goto err_clear;
	}

	ptr = start + offset;

	if (likely(ptr + len <= end)) {
		memcpy(to, ptr, len);
		return 0;
	}

err_clear:
	memset(to, 0, len);
	return -EFAULT;
}

static const struct bpf_func_proto bpf_skb_load_bytes_relative_proto = {
	.func		= bpf_skb_load_bytes_relative,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg4_type	= ARG_CONST_SIZE,
	.arg5_type	= ARG_ANYTHING,
};

/* --- Ringbuf helper protos (defined in kernel/bpf/bpf_ringbuf.c) --- */
extern const struct bpf_func_proto bpf_ringbuf_output_proto;
extern const struct bpf_func_proto bpf_ringbuf_reserve_proto;
extern const struct bpf_func_proto bpf_ringbuf_submit_proto;
extern const struct bpf_func_proto bpf_ringbuf_discard_proto;

/* --- bpf_sk_fullsock stub (func 95) ---
 * Returns NULL so the BPF program takes the fallback path.
 * Uses RET_PTR_TO_MAP_VALUE_OR_NULL; the verifier's dummy-map
 * fallback allows this without a real map argument.
 */
BPF_CALL_1(bpf_sk_fullsock_stub, struct sock *, sk)
{
	return 0; /* NULL */
}

static const struct bpf_func_proto bpf_sk_fullsock_proto = {
	.func		= bpf_sk_fullsock_stub,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_ANYTHING,
};

/* --- bpf_sk_storage_get stub (func 107) ---
 * Returns NULL (no storage found / no creation).
 */
BPF_CALL_4(bpf_sk_storage_get_stub, struct bpf_map *, map,
	   struct sock *, sk, void *, value, u64, flags)
{
	return 0; /* NULL */
}

static const struct bpf_func_proto bpf_sk_storage_get_proto = {
	.func		= bpf_sk_storage_get_stub,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
};

/* --- bpf_sk_storage_delete stub (func 108) --- */
BPF_CALL_2(bpf_sk_storage_delete_stub, struct bpf_map *, map,
	   struct sock *, sk)
{
	return -ENOENT;
}

static const struct bpf_func_proto bpf_sk_storage_delete_proto = {
	.func		= bpf_sk_storage_delete_stub,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_ANYTHING,
};

static const struct bpf_func_proto *
bpf_base_func_proto(enum bpf_func_id func_id)
{
	switch (func_id) {
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	case BPF_FUNC_get_prandom_u32:
		return &bpf_get_prandom_u32_proto;
	case BPF_FUNC_get_smp_processor_id:
		return &bpf_get_raw_smp_processor_id_proto;
	case BPF_FUNC_get_numa_node_id:
		return &bpf_get_numa_node_id_proto;
	case BPF_FUNC_tail_call:
		return &bpf_tail_call_proto;
	case BPF_FUNC_ktime_get_ns:
		return &bpf_ktime_get_ns_proto;
	case BPF_FUNC_ktime_get_boot_ns:
		return &bpf_ktime_get_boot_ns_proto;
	case BPF_FUNC_trace_printk:
		if (capable(CAP_SYS_ADMIN))
			return bpf_get_trace_printk_proto();
	case BPF_FUNC_ringbuf_output:
		return &bpf_ringbuf_output_proto;
	case BPF_FUNC_ringbuf_reserve:
		return &bpf_ringbuf_reserve_proto;
	case BPF_FUNC_ringbuf_submit:
		return &bpf_ringbuf_submit_proto;
	case BPF_FUNC_ringbuf_discard:
		return &bpf_ringbuf_discard_proto;
	default:
		return NULL;
	}
}

static const struct bpf_func_proto *
sock_filter_func_proto(enum bpf_func_id func_id)
{
	switch (func_id) {
	/* inet and inet6 sockets are created in a process
	 * context so there is always a valid uid/gid
	 */
	case BPF_FUNC_get_current_uid_gid:
		return &bpf_get_current_uid_gid_proto;
	case BPF_FUNC_get_socket_cookie:
		return &bpf_get_socket_cookie_proto;
	case BPF_FUNC_sk_storage_get:
		return &bpf_sk_storage_get_proto;
	case BPF_FUNC_sk_storage_delete:
		return &bpf_sk_storage_delete_proto;
	default:
		return bpf_base_func_proto(func_id);
	}
}

static const struct bpf_func_proto * __attribute__((unused))
sk_filter_func_proto(enum bpf_func_id func_id)
{
	switch (func_id) {
	case BPF_FUNC_skb_load_bytes:
		return &bpf_skb_load_bytes_proto;
	case BPF_FUNC_get_socket_cookie:
		return &bpf_get_socket_cookie_proto;
	case BPF_FUNC_get_socket_uid:
		return &bpf_get_socket_uid_proto;
	case BPF_FUNC_skb_load_bytes_relative:
		return &bpf_skb_load_bytes_relative_proto;
	case BPF_FUNC_sk_fullsock:
		return &bpf_sk_fullsock_proto;
	default:
		return bpf_base_func_proto(func_id);
	}
}

#if 0

static const struct bpf_func_proto *
xdp_func_proto(enum bpf_func_id func_id)
{
	return NULL;
}

static const struct bpf_func_proto *
lwt_inout_func_proto(enum bpf_func_id func_id)
{
	return NULL;
}

static const struct bpf_func_proto *
sock_ops_func_proto(enum bpf_func_id func_id)
{
	return NULL;
}

static const struct bpf_func_proto *
sk_skb_func_proto(enum bpf_func_id func_id)
{
	return NULL;
}

static const struct bpf_func_proto *
lwt_xmit_func_proto(enum bpf_func_id func_id)
{
	return NULL;
}
#endif

static bool bpf_skb_is_valid_access(int off, int size, enum bpf_access_type type,
				    struct bpf_insn_access_aux *info)
{
	const int size_default = sizeof(__u32);

	if (off < 0 || off >= sizeof(struct __sk_buff))
		return false;

	/* The verifier guarantees that size > 0. */
	if (off % size != 0)
		return false;

	switch (off) {
	case bpf_ctx_range_till(struct __sk_buff, cb[0], cb[4]):
		if (off + size > offsetofend(struct __sk_buff, cb[4]))
			return false;
		break;
	case bpf_ctx_range_till(struct __sk_buff, remote_ip6[0], remote_ip6[3]):
	case bpf_ctx_range_till(struct __sk_buff, local_ip6[0], local_ip6[3]):
	case bpf_ctx_range_till(struct __sk_buff, remote_ip4, remote_ip4):
	case bpf_ctx_range_till(struct __sk_buff, local_ip4, local_ip4):
	case bpf_ctx_range(struct __sk_buff, data):
		info->reg_type = PTR_TO_PACKET;
		if (size != size_default)
			return false;
		break;
	case bpf_ctx_range(struct __sk_buff, data_end):
		info->reg_type = PTR_TO_PACKET_END;
		if (size != size_default)
			return false;
		break;
	case bpf_ctx_range(struct __sk_buff, flow_keys):
		/* __u64 pointer field — not directly accessible from BPF */
		return false;
	case bpf_ctx_range(struct __sk_buff, tstamp):
		/* __u64 timestamp — read/write at 8-byte granularity */
		if (size != sizeof(__u64))
			return false;
		break;
	case bpf_ctx_range(struct __sk_buff, sk):
		/* __u64 pointer to sock — read-only, 8-byte access.
		 * Return as SCALAR_VALUE (= 0 at runtime); the BPF program
		 * will call bpf_sk_fullsock() on it, whose stub returns NULL.
		 * Using PTR_TO_MAP_VALUE_OR_NULL here would crash the verifier
		 * in mark_map_reg() because map_ptr is not set for ctx reads.
		 */
		if (type == BPF_WRITE || size != sizeof(__u64))
			return false;
		/* reg_type stays SCALAR_VALUE (default) */
		break;
	default:
		/* Only narrow read access allowed for now. */
		if (type == BPF_WRITE) {
			if (size != size_default)
				return false;
		} else {
			bpf_ctx_record_field_size(info, size_default);
			if (!bpf_ctx_narrow_access_ok(off, size, size_default))
				return false;
		}
	}

	return true;
}

static bool __attribute__((unused))
sk_filter_is_valid_access(int off, int size,
				      enum bpf_access_type type,
				      struct bpf_insn_access_aux *info)
{
	switch (off) {
	case bpf_ctx_range(struct __sk_buff, tc_classid):
	case bpf_ctx_range(struct __sk_buff, data):
	case bpf_ctx_range(struct __sk_buff, data_end):
	case bpf_ctx_range_till(struct __sk_buff, family, local_port):
		return false;
	}

	if (type == BPF_WRITE) {
		switch (off) {
		case bpf_ctx_range_till(struct __sk_buff, cb[0], cb[4]):
			break;
		default:
			return false;
		}
	}

	return bpf_skb_is_valid_access(off, size, type, info);
}

#if 0
static bool lwt_is_valid_access(int off, int size,
				enum bpf_access_type type,
				struct bpf_insn_access_aux *info)
{
	return false;
}
#endif

static int tc_cls_act_prologue(struct bpf_insn *insn_buf, bool direct_write,
			       const struct bpf_prog *prog)
{
	return 0;
}

static bool tc_cls_act_is_valid_access(int off, int size,
				       enum bpf_access_type type,
				       struct bpf_insn_access_aux *info)
{
	return bpf_skb_is_valid_access(off, size, type, info);
}

#if 0
static bool xdp_is_valid_access(int off, int size,
				enum bpf_access_type type,
				struct bpf_insn_access_aux *info)
{
	return false;
}

static bool sock_ops_is_valid_access(int off, int size,
				     enum bpf_access_type type,
				     struct bpf_insn_access_aux *info)
{
	return false;
}

static int sk_skb_prologue(struct bpf_insn *insn_buf, bool direct_write,
			   const struct bpf_prog *prog)
{
	return 0;
}

static bool sk_skb_is_valid_access(int off, int size,
				   enum bpf_access_type type,
				   struct bpf_insn_access_aux *info)
{
	return false;
}
#endif

static u32 bpf_convert_ctx_access(enum bpf_access_type type,
				  const struct bpf_insn *si,
				  struct bpf_insn *insn_buf,
				  struct bpf_prog *prog, u32 *target_size);

static u32 tc_cls_act_convert_ctx_access(enum bpf_access_type type,
					 const struct bpf_insn *si,
					 struct bpf_insn *insn_buf,
					 struct bpf_prog *prog, u32 *target_size)
{
	struct bpf_insn *insn = insn_buf;

	switch (si->off) {
	case offsetof(struct __sk_buff, data):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, data),
				      si->dst_reg, si->src_reg,
				      offsetof(struct sk_buff, data));
		break;
	case offsetof(struct __sk_buff, data_end):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, head),
				      si->dst_reg, si->src_reg,
				      offsetof(struct sk_buff, head));
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, tail),
				      BPF_REG_AX, si->src_reg,
				      offsetof(struct sk_buff, tail));
		*insn++ = BPF_ALU64_REG(BPF_ADD, si->dst_reg, BPF_REG_AX);
		break;
	default:
		return bpf_convert_ctx_access(type, si, insn_buf, prog, target_size);
	}

	return insn - insn_buf;
}

static const struct bpf_func_proto *
tc_cls_act_func_proto(enum bpf_func_id func_id)
{
	switch (func_id) {
	case BPF_FUNC_skb_store_bytes:
		return &bpf_skb_store_bytes_proto;
	case BPF_FUNC_skb_load_bytes:
		return &bpf_skb_load_bytes_proto;
	case BPF_FUNC_skb_pull_data:
		return &bpf_skb_pull_data_proto;
	case BPF_FUNC_csum_diff:
		return &bpf_csum_diff_proto;
	case BPF_FUNC_l3_csum_replace:
		return &bpf_l3_csum_replace_proto;
	case BPF_FUNC_l4_csum_replace:
		return &bpf_l4_csum_replace_proto;
	case BPF_FUNC_csum_update:
		return &bpf_csum_update_proto;
	case BPF_FUNC_clone_redirect:
		return &bpf_clone_redirect_proto;
	case BPF_FUNC_redirect:
		return &bpf_redirect_proto;
	case BPF_FUNC_get_cgroup_classid:
		return &bpf_get_cgroup_classid_proto;
	case BPF_FUNC_skb_vlan_push:
		return &bpf_skb_vlan_push_proto;
	case BPF_FUNC_skb_vlan_pop:
		return &bpf_skb_vlan_pop_proto;
	case BPF_FUNC_skb_change_proto:
		return &bpf_skb_change_proto_proto;
	case BPF_FUNC_skb_change_type:
		return &bpf_skb_change_type_proto;
	case BPF_FUNC_skb_change_tail:
		return &bpf_skb_change_tail_proto;
	case BPF_FUNC_skb_change_head:
		return &bpf_skb_change_head_proto;
	case BPF_FUNC_skb_adjust_room:
		return &bpf_skb_adjust_room_proto;
	default:
		return bpf_base_func_proto(func_id);
	}
}

const struct bpf_verifier_ops tc_cls_act_prog_ops = {
	.get_func_proto		= tc_cls_act_func_proto,
	.is_valid_access	= tc_cls_act_is_valid_access,
	.convert_ctx_access	= tc_cls_act_convert_ctx_access,
	.gen_prologue		= tc_cls_act_prologue,
};

#if 0
static bool sock_filter_is_valid_access(int off, int size,
					enum bpf_access_type type,
					struct bpf_insn_access_aux *info)
{
	if (type == BPF_WRITE) {
		switch (off) {
		case offsetof(struct bpf_sock, bound_dev_if):
		case offsetof(struct bpf_sock, mark):
		case offsetof(struct bpf_sock, priority):
			break;
		default:
			return false;
		}
	}

	if (off < 0 || off + size > sizeof(struct bpf_sock))
		return false;
	/* The verifier guarantees that size > 0. */
	if (off % size != 0)
		return false;
	if (size != sizeof(__u32))
		return false;

	return true;
}

static int bpf_unclone_prologue(struct bpf_insn *insn_buf, bool direct_write,
				const struct bpf_prog *prog, int drop_verdict)
{
	struct bpf_insn *insn = insn_buf;

	if (!direct_write)
		return 0;

	/* if (!skb->cloned)
	 *       goto start;
	 *
	 * (Fast-path, otherwise approximation that we might be
	 *  a clone, do the rest in helper.)
	 */
	*insn++ = BPF_LDX_MEM(BPF_B, BPF_REG_6, BPF_REG_1, CLONED_OFFSET());
	*insn++ = BPF_ALU32_IMM(BPF_AND, BPF_REG_6, CLONED_MASK);
	*insn++ = BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, 0, 7);

	/* ret = bpf_skb_pull_data(skb, 0); */
	*insn++ = BPF_MOV64_REG(BPF_REG_6, BPF_REG_1);
	*insn++ = BPF_ALU64_REG(BPF_XOR, BPF_REG_2, BPF_REG_2);
	*insn++ = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
			       BPF_FUNC_skb_pull_data);
	/* if (!ret)
	 *      goto restore;
	 * return TC_ACT_SHOT;
	 */
	*insn++ = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2);
	*insn++ = BPF_ALU32_IMM(BPF_MOV, BPF_REG_0, drop_verdict);
	*insn++ = BPF_EXIT_INSN();

	/* restore: */
	*insn++ = BPF_MOV64_REG(BPF_REG_1, BPF_REG_6);
	/* start: */
	*insn++ = prog->insnsi[0];

	return insn - insn_buf;
}

static bool __is_valid_xdp_access(int off, int size)
{
	if (off < 0 || off >= sizeof(struct xdp_md))
		return false;
	if (off % size != 0)
		return false;
	if (size != sizeof(__u32))
		return false;

	return true;
}

void bpf_warn_invalid_xdp_action(u32 act)
{
	const u32 act_max = XDP_REDIRECT;

	pr_warn_once("%s XDP return value %u, expect packet loss!\n",
		     act > act_max ? "Illegal" : "Driver unsupported",
		     act);
}
EXPORT_SYMBOL_GPL(bpf_warn_invalid_xdp_action);

static bool __is_valid_sock_ops_access(int off, int size)
{
	if (off < 0 || off >= sizeof(struct bpf_sock_ops))
		return false;
	/* The verifier guarantees that size > 0. */
	if (off % size != 0)
		return false;
	if (size != sizeof(__u32))
		return false;

	return true;
}

static u32 bpf_convert_ctx_access(enum bpf_access_type type,
				  const struct bpf_insn *si,
				  struct bpf_insn *insn_buf,
				  struct bpf_prog *prog, u32 *target_size);
#endif

static u32 bpf_convert_ctx_access(enum bpf_access_type type,
				  const struct bpf_insn *si,
				  struct bpf_insn *insn_buf,
				  struct bpf_prog *prog, u32 *target_size)
{
	struct bpf_insn *insn = insn_buf;
	int off;

	switch (si->off) {
	case offsetof(struct __sk_buff, len):
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
				      bpf_target_off(struct sk_buff, len, 4,
						     target_size));
		break;

	case offsetof(struct __sk_buff, protocol):
		*insn++ = BPF_LDX_MEM(BPF_H, si->dst_reg, si->src_reg,
				      bpf_target_off(struct sk_buff, protocol, 2,
						     target_size));
		break;

	case offsetof(struct __sk_buff, vlan_proto):
		*insn++ = BPF_LDX_MEM(BPF_H, si->dst_reg, si->src_reg,
				      bpf_target_off(struct sk_buff, vlan_proto, 2,
						     target_size));
		break;

	case offsetof(struct __sk_buff, priority):
		if (type == BPF_WRITE)
			*insn++ = BPF_STX_MEM(BPF_W, si->dst_reg, si->src_reg,
					      bpf_target_off(struct sk_buff, priority, 4,
							     target_size));
		else
			*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
					      bpf_target_off(struct sk_buff, priority, 4,
							     target_size));
		break;

	case offsetof(struct __sk_buff, ingress_ifindex):
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
				      bpf_target_off(struct sk_buff, skb_iif, 4,
						     target_size));
		break;

	case offsetof(struct __sk_buff, ifindex):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, dev),
				      si->dst_reg, si->src_reg,
				      offsetof(struct sk_buff, dev));
		*insn++ = BPF_JMP_IMM(BPF_JEQ, si->dst_reg, 0, 1);
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->dst_reg,
				      bpf_target_off(struct net_device, ifindex, 4,
						     target_size));
		break;

	case offsetof(struct __sk_buff, hash):
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
				      bpf_target_off(struct sk_buff, rxhash, 4,
						     target_size));
		break;

	case offsetof(struct __sk_buff, mark):
		if (type == BPF_WRITE)
			*insn++ = BPF_STX_MEM(BPF_W, si->dst_reg, si->src_reg,
					      bpf_target_off(struct sk_buff, mark, 4,
							     target_size));
		else
			*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
					      bpf_target_off(struct sk_buff, mark, 4,
							     target_size));
		break;

	case offsetof(struct __sk_buff, pkt_type):
		*target_size = 1;
		*insn++ = BPF_LDX_MEM(BPF_B, si->dst_reg, si->src_reg,
				      PKT_TYPE_OFFSET());
		*insn++ = BPF_ALU32_IMM(BPF_AND, si->dst_reg, PKT_TYPE_MAX);
#ifdef __BIG_ENDIAN_BITFIELD
		*insn++ = BPF_ALU32_IMM(BPF_RSH, si->dst_reg, 5);
#endif
		break;

	case offsetof(struct __sk_buff, queue_mapping):
		*insn++ = BPF_LDX_MEM(BPF_H, si->dst_reg, si->src_reg,
				      bpf_target_off(struct sk_buff, queue_mapping, 2,
						     target_size));
		break;

	case offsetof(struct __sk_buff, vlan_present):
	case offsetof(struct __sk_buff, vlan_tci):
		BUILD_BUG_ON(VLAN_TAG_PRESENT != 0x1000);

		*insn++ = BPF_LDX_MEM(BPF_H, si->dst_reg, si->src_reg,
				      bpf_target_off(struct sk_buff, vlan_tci, 2,
						     target_size));
		if (si->off == offsetof(struct __sk_buff, vlan_tci)) {
			*insn++ = BPF_ALU32_IMM(BPF_AND, si->dst_reg,
						~VLAN_TAG_PRESENT);
		} else {
			*insn++ = BPF_ALU32_IMM(BPF_RSH, si->dst_reg, 12);
			*insn++ = BPF_ALU32_IMM(BPF_AND, si->dst_reg, 1);
		}
		break;

	case offsetof(struct __sk_buff, cb[0]) ...
	     offsetof(struct __sk_buff, cb[4]):
		/* qdisc_skb_cb/tc_classid check disabled for 3.10 compat */
#if 0
		BUILD_BUG_ON(FIELD_SIZEOF(struct sk_buff, rxhash) != 4);
	BUILD_BUG_ON(__alignof__(struct sk_buff) != 8);
	BUILD_BUG_ON(offsetof(struct sk_buff, rxhash) !=
		     offsetof(struct sk_buff, headers_start) +
		     offsetof(struct sk_buff_data_head, rxhash));
		BUILD_BUG_ON(FIELD_SIZEOF(struct qdisc_skb_cb, data) < 20);
		BUILD_BUG_ON((offsetof(struct sk_buff, cb) +
			      offsetof(struct qdisc_skb_cb, data)) %
			     sizeof(__u64));

		if (type == BPF_WRITE)
			*insn++ = BPF_STX_MEM(BPF_W, si->dst_reg, si->src_reg,
					      bpf_target_off(struct sk_buff, cb, 4,
							     target_size) +
					      offsetof(struct qdisc_skb_cb, data) +
					      si->off - offsetof(struct __sk_buff, cb[0]));
		else
			*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
					      bpf_target_off(struct sk_buff, cb, 4,
							     target_size) +
					      offsetof(struct qdisc_skb_cb, data) +
					      si->off - offsetof(struct __sk_buff, cb[0]));
#endif
		break;

	case offsetof(struct __sk_buff, tc_classid):
#if 0
		BUILD_BUG_ON(FIELD_SIZEOF(struct qdisc_skb_cb, tc_classid) != 2);

		if (type == BPF_WRITE)
			*insn++ = BPF_STX_MEM(BPF_H, si->dst_reg, si->src_reg,
					      bpf_target_off(struct sk_buff, cb, 2,
							     target_size) +
					      offsetof(struct qdisc_skb_cb, tc_classid));
		else
			*insn++ = BPF_LDX_MEM(BPF_H, si->dst_reg, si->src_reg,
					      bpf_target_off(struct sk_buff, cb, 2,
							     target_size) +
					      offsetof(struct qdisc_skb_cb, tc_classid));
#endif
		break;

	case offsetof(struct __sk_buff, data):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, data),
				      si->dst_reg, si->src_reg,
				      offsetof(struct sk_buff, data));
		break;

	case offsetof(struct __sk_buff, data_end):
		off  = si->off;
		off -= offsetof(struct __sk_buff, data_end);
		off += offsetof(struct sk_buff, cb);
		/* bpf.data_end disabled if tcp_skb_cb/bpf missing */
#if 0
		off += offsetof(struct bpf_skb_data_end, data_end);
#endif
		*insn++ = BPF_LDX_MEM(BPF_SIZEOF(void *), si->dst_reg,
				      si->src_reg, off);
		break;

	case offsetof(struct __sk_buff, tc_index):
#if 0 /* CONFIG_NET_SCHED */
		if (type == BPF_WRITE)
			*insn++ = BPF_STX_MEM(BPF_H, si->dst_reg, si->src_reg,
					      bpf_target_off(struct sk_buff, tc_index, 2,
							     target_size));
		else
			*insn++ = BPF_LDX_MEM(BPF_H, si->dst_reg, si->src_reg,
					      bpf_target_off(struct sk_buff, tc_index, 2,
							     target_size));
#endif
		*target_size = 2;
		*insn++ = BPF_MOV64_IMM(si->dst_reg, 0);
		break;

	case offsetof(struct __sk_buff, napi_id):
		*target_size = 4;
		*insn++ = BPF_MOV64_IMM(si->dst_reg, 0);
		break;
	case offsetof(struct __sk_buff, family):
		BUILD_BUG_ON(FIELD_SIZEOF(struct sock_common, skc_family) != 2);

		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, sk),
				      si->dst_reg, si->src_reg,
				      offsetof(struct sk_buff, sk));
		*insn++ = BPF_LDX_MEM(BPF_H, si->dst_reg, si->dst_reg,
				      bpf_target_off(struct sock_common,
						     skc_family,
						     2, target_size));
		break;
	case offsetof(struct __sk_buff, remote_ip4):
		BUILD_BUG_ON(FIELD_SIZEOF(struct sock_common, skc_daddr) != 4);

		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, sk),
				      si->dst_reg, si->src_reg,
				      offsetof(struct sk_buff, sk));
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->dst_reg,
				      bpf_target_off(struct sock_common,
						     skc_daddr,
						     4, target_size));
		break;
	case offsetof(struct __sk_buff, local_ip4):
		BUILD_BUG_ON(FIELD_SIZEOF(struct sock_common,
					  skc_rcv_saddr) != 4);

		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, sk),
				      si->dst_reg, si->src_reg,
				      offsetof(struct sk_buff, sk));
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->dst_reg,
				      bpf_target_off(struct sock_common,
						     skc_rcv_saddr,
						     4, target_size));
		break;
	case offsetof(struct __sk_buff, remote_ip6[0]) ...
	     offsetof(struct __sk_buff, remote_ip6[3]):
#if 0
		BUILD_BUG_ON(FIELD_SIZEOF(struct sock_common,
					  skc_v6_daddr.s6_addr32[0]) != 4);

		off = si->off;
		off -= offsetof(struct __sk_buff, remote_ip6[0]);
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, sk),
				      si->dst_reg, si->src_reg,
				      offsetof(struct sk_buff, sk));
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->dst_reg,
				      bpf_target_off(struct sock_common,
						     skc_v6_daddr.s6_addr32[0],
						     4, target_size) + off);
#else
		*target_size = 4;
		*insn++ = BPF_MOV32_IMM(si->dst_reg, 0);
#endif
		break;
	case offsetof(struct __sk_buff, local_ip6[0]) ...
	     offsetof(struct __sk_buff, local_ip6[3]):
#if 0
		BUILD_BUG_ON(FIELD_SIZEOF(struct sock_common,
					  skc_v6_rcv_saddr.s6_addr32[0]) != 4);

		off = si->off;
		off -= offsetof(struct __sk_buff, local_ip6[0]);
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, sk),
				      si->dst_reg, si->src_reg,
				      offsetof(struct sk_buff, sk));
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->dst_reg,
				      bpf_target_off(struct sock_common,
						     skc_v6_rcv_saddr.s6_addr32[0],
						     4, target_size) + off);
#else
		*target_size = 4;
		*insn++ = BPF_MOV32_IMM(si->dst_reg, 0);
#endif
		break;

	case offsetof(struct __sk_buff, remote_port):
		BUILD_BUG_ON(FIELD_SIZEOF(struct sock_common, skc_dport) != 2);

		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, sk),
				      si->dst_reg, si->src_reg,
				      offsetof(struct sk_buff, sk));
		*insn++ = BPF_LDX_MEM(BPF_H, si->dst_reg, si->dst_reg,
				      bpf_target_off(struct sock_common,
						     skc_dport,
						     2, target_size));
#ifndef __BIG_ENDIAN_BITFIELD
		*insn++ = BPF_ALU32_IMM(BPF_LSH, si->dst_reg, 16);
#endif
		break;

	case offsetof(struct __sk_buff, local_port):
		BUILD_BUG_ON(FIELD_SIZEOF(struct sock_common, skc_num) != 2);

		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, sk),
				      si->dst_reg, si->src_reg,
				      offsetof(struct sk_buff, sk));
		*insn++ = BPF_LDX_MEM(BPF_H, si->dst_reg, si->dst_reg,
				      bpf_target_off(struct sock_common,
						     skc_num, 2, target_size));
		break;

	case offsetof(struct __sk_buff, data_meta):
		/* data_meta not supported on 3.10, return 0 */
		*target_size = 4;
		*insn++ = BPF_MOV64_IMM(si->dst_reg, 0);
		break;

	case offsetof(struct __sk_buff, flow_keys):
		/* flow_keys not supported on 3.10, return 0 */
		*target_size = 8;
		*insn++ = BPF_MOV64_IMM(si->dst_reg, 0);
		break;

	case offsetof(struct __sk_buff, tstamp):
		/* ktime_t on arm64 is s64, tstamp.tv64 is the s64 value */
		*target_size = 8;
		if (type == BPF_WRITE)
			*insn++ = BPF_STX_MEM(BPF_DW,
					      si->dst_reg, si->src_reg,
					      offsetof(struct sk_buff, tstamp));
		else
			*insn++ = BPF_LDX_MEM(BPF_DW,
					      si->dst_reg, si->src_reg,
					      offsetof(struct sk_buff, tstamp));
		break;

	case offsetof(struct __sk_buff, wire_len):
		/* wire_len not directly available on 3.10, return 0 */
		*target_size = 4;
		*insn++ = BPF_MOV64_IMM(si->dst_reg, 0);
		break;

	case offsetof(struct __sk_buff, gso_segs):
		/* skb_shinfo(skb)->gso_segs via NET_SKBUFF_DATA_USES_OFFSET path */
		*target_size = 2;
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, end),
				      BPF_REG_AX, si->src_reg,
				      offsetof(struct sk_buff, end));
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, head),
				      si->dst_reg, si->src_reg,
				      offsetof(struct sk_buff, head));
		*insn++ = BPF_ALU64_REG(BPF_ADD, si->dst_reg, BPF_REG_AX);
		*insn++ = BPF_LDX_MEM(BPF_H, si->dst_reg, si->dst_reg,
				      offsetof(struct skb_shared_info, gso_segs));
		break;

	case offsetof(struct __sk_buff, sk):
		/* sk pointer not exposed on 3.10, return 0 */
		*target_size = 8;
		*insn++ = BPF_MOV64_IMM(si->dst_reg, 0);
		break;

	case offsetof(struct __sk_buff, gso_size):
		/* skb_shinfo(skb)->gso_size via NET_SKBUFF_DATA_USES_OFFSET path */
		*target_size = 2;
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, end),
				      BPF_REG_AX, si->src_reg,
				      offsetof(struct sk_buff, end));
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_buff, head),
				      si->dst_reg, si->src_reg,
				      offsetof(struct sk_buff, head));
		*insn++ = BPF_ALU64_REG(BPF_ADD, si->dst_reg, BPF_REG_AX);
		*insn++ = BPF_LDX_MEM(BPF_H, si->dst_reg, si->dst_reg,
				      offsetof(struct skb_shared_info, gso_size));
		break;
	}

	return insn - insn_buf;
}

#if 0 /* Unsupported */
static u32 sock_filter_convert_ctx_access(enum bpf_access_type type,
					  const struct bpf_insn *si,
					  struct bpf_insn *insn_buf,
					  struct bpf_prog *prog, u32 *target_size)
{
	/* stubbed */
	return 0;
}
#endif

#if 0 /* Unsupported types in 3.10 */
static u32 xdp_convert_ctx_access(enum bpf_access_type type,
				  const struct bpf_insn *si,
				  struct bpf_insn *insn_buf,
				  struct bpf_prog *prog, u32 *target_size)
{
	return 0;
}

static u32 sock_ops_convert_ctx_access(enum bpf_access_type type,
				       const struct bpf_insn *si,
				       struct bpf_insn *insn_buf,
				       struct bpf_prog *prog,
				       u32 *target_size)
{
	return 0;
}

static u32 sk_skb_convert_ctx_access(enum bpf_access_type type,
				     const struct bpf_insn *si,
				     struct bpf_insn *insn_buf,
				     struct bpf_prog *prog, u32 *target_size)
{
	return 0;
}

const struct bpf_verifier_ops xdp_prog_ops = {};
const struct bpf_verifier_ops lwt_inout_prog_ops = {};
const struct bpf_verifier_ops lwt_xmit_prog_ops = {};
#endif

/* cgroup SKB support for Android 16 BPF */
const struct bpf_verifier_ops cg_skb_prog_ops = {
	.get_func_proto		= sk_filter_func_proto,
	.is_valid_access	= sk_filter_is_valid_access,
	.convert_ctx_access	= bpf_convert_ctx_access,
};

const struct bpf_verifier_ops sk_filter_prog_ops = {
	.get_func_proto		= sk_filter_func_proto,
	.is_valid_access	= sk_filter_is_valid_access,
	.convert_ctx_access	= bpf_convert_ctx_access,
};

static bool sock_filter_is_valid_access(int off, int size,
					enum bpf_access_type type,
					struct bpf_insn_access_aux *info)
{
	if (type == BPF_WRITE) {
		switch (off) {
		case offsetof(struct bpf_sock, bound_dev_if):
		case offsetof(struct bpf_sock, mark):
		case offsetof(struct bpf_sock, priority):
			break;
		default:
			return false;
		}
	}

	if (off < 0 || off + size > sizeof(struct bpf_sock))
		return false;
	/* The verifier guarantees that size > 0. */
	if (off % size != 0)
		return false;
	if (size != sizeof(__u32))
		return false;

	return true;
}

static u32 sock_filter_convert_ctx_access(enum bpf_access_type type,
					  const struct bpf_insn *si,
					  struct bpf_insn *insn_buf,
					  struct bpf_prog *prog, u32 *target_size)
{
	struct bpf_insn *insn = insn_buf;

	switch (si->off) {
	case offsetof(struct bpf_sock, bound_dev_if):
		BUILD_BUG_ON(FIELD_SIZEOF(struct sock, sk_bound_dev_if) != 4);

		if (type == BPF_WRITE)
			*insn++ = BPF_STX_MEM(BPF_W, si->dst_reg, si->src_reg,
					offsetof(struct sock, sk_bound_dev_if));
		else
			*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
				      offsetof(struct sock, sk_bound_dev_if));
		break;

	case offsetof(struct bpf_sock, mark):
		BUILD_BUG_ON(FIELD_SIZEOF(struct sock, sk_mark) != 4);

		if (type == BPF_WRITE)
			*insn++ = BPF_STX_MEM(BPF_W, si->dst_reg, si->src_reg,
					offsetof(struct sock, sk_mark));
		else
			*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
				      offsetof(struct sock, sk_mark));
		break;

	case offsetof(struct bpf_sock, priority):
		BUILD_BUG_ON(FIELD_SIZEOF(struct sock, sk_priority) != 4);

		if (type == BPF_WRITE)
			*insn++ = BPF_STX_MEM(BPF_W, si->dst_reg, si->src_reg,
					offsetof(struct sock, sk_priority));
		else
			*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
				      offsetof(struct sock, sk_priority));
		break;

	case offsetof(struct bpf_sock, family):
		BUILD_BUG_ON(FIELD_SIZEOF(struct sock, sk_family) != 2);

		*insn++ = BPF_LDX_MEM(BPF_H, si->dst_reg, si->src_reg,
				      offsetof(struct sock, sk_family));
		break;

	case offsetof(struct bpf_sock, type):
		/* In 3.10, sk_type is a bitfield in a __u32 word right before sk_wmem_queued */
		/* The bitfields: sk_shutdown(2) + sk_no_check(2) + sk_userlocks(4) + sk_protocol(8) + sk_type(16) = 32 bits */
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
				      offsetof(struct sock, sk_wmem_queued) - 4);
		/* Extract sk_type: shift right 16 bits */
		*insn++ = BPF_ALU32_IMM(BPF_RSH, si->dst_reg, 16);
		/* Mask to 16 bits */
		*insn++ = BPF_ALU32_IMM(BPF_AND, si->dst_reg, 0xFFFF);
		break;

	case offsetof(struct bpf_sock, protocol):
		/* In 3.10, sk_protocol is a bitfield in a __u32 word right before sk_wmem_queued */
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
				      offsetof(struct sock, sk_wmem_queued) - 4);
		/* Extract sk_protocol: shift right 8 bits */
		*insn++ = BPF_ALU32_IMM(BPF_RSH, si->dst_reg, 8);
		/* Mask to 8 bits */
		*insn++ = BPF_ALU32_IMM(BPF_AND, si->dst_reg, 0xFF);
		break;
	}

	return insn - insn_buf;
}

const struct bpf_verifier_ops cg_sock_prog_ops = {
	.get_func_proto		= sock_filter_func_proto,
	.is_valid_access	= sock_filter_is_valid_access,
	.convert_ctx_access	= sock_filter_convert_ctx_access,
};

static bool sock_addr_is_valid_access(int off, int size,
				      enum bpf_access_type type,
				      struct bpf_insn_access_aux *info)
{
	/* For now, allow all accesses to simplify implementation */
	/* Android 16 bind programs mainly need user_port and user_ip fields */
	if (off < 0 || off >= 64) /* sizeof(struct bpf_sock_addr) */
		return false;
	if (off % size != 0)
		return false;
	return true;
}

static u32 sock_addr_convert_ctx_access(enum bpf_access_type type,
					const struct bpf_insn *si,
					struct bpf_insn *insn_buf,
					struct bpf_prog *prog, u32 *target_size)
{
	struct bpf_insn *insn = insn_buf;

	/* For now, just return 0 for all reads */
	/* This is a simplified implementation - real implementation would */
	/* extract values from struct bpf_sock_addr_kern */
	if (type == BPF_READ) {
		*insn++ = BPF_MOV64_IMM(si->dst_reg, 0);
	} else {
		/* Writes are no-ops for now */
		*insn++ = BPF_MOV64_REG(si->dst_reg, si->dst_reg);
	}

	return insn - insn_buf;
}

static bool sockopt_is_valid_access(int off, int size,
				    enum bpf_access_type type,
				    struct bpf_insn_access_aux *info)
{
	/* Allow access to struct bpf_sockopt fields */
	/* Simplified implementation - allow aligned accesses within reasonable bounds */
	if (off < 0 || off >= 128) /* Estimate for sizeof(struct bpf_sockopt) */
		return false;
	if (off % size != 0)
		return false;
	return true;
}

static u32 sockopt_convert_ctx_access(enum bpf_access_type type,
				     const struct bpf_insn *si,
				     struct bpf_insn *insn_buf,
				     struct bpf_prog *prog, u32 *target_size)
{
	struct bpf_insn *insn = insn_buf;

	/* Simplified: return 0 for reads, no-op for writes */
	if (type == BPF_READ) {
		*insn++ = BPF_MOV64_IMM(si->dst_reg, 0);
	} else {
		/* Writes: no-op - just move register to itself */
		*insn++ = BPF_MOV64_REG(si->dst_reg, si->dst_reg);
	}

	return insn - insn_buf;
}

/* ---- BPF tracing program type implementations ---- */

/* Probe read helper implementations using probe_kernel_read */
static __always_inline int __bpf_probe_read_kernel_impl(void *dst, u32 size,
							const void *unsafe_ptr)
{
	int ret;
	if (!size)
		return 0;
	ret = probe_kernel_read(dst, (void *)unsafe_ptr, size);
	if (unlikely(ret < 0))
		memset(dst, 0, size);
	return ret;
}

BPF_CALL_3(bpf_probe_read, void *, dst, u32, size, const void *, unsafe_ptr)
{
	return __bpf_probe_read_kernel_impl(dst, size, unsafe_ptr);
}

const struct bpf_func_proto bpf_probe_read_proto = {
	.func		= bpf_probe_read,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
};

BPF_CALL_3(bpf_probe_read_kernel, void *, dst, u32, size, const void *, unsafe_ptr)
{
	return __bpf_probe_read_kernel_impl(dst, size, unsafe_ptr);
}

const struct bpf_func_proto bpf_probe_read_kernel_proto = {
	.func		= bpf_probe_read_kernel,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
};

/* bpf_probe_read_user: stub that reads user-space memory atomically.
 * Returns -EFAULT if the read fails (e.g. page not present).
 */
BPF_CALL_3(bpf_probe_read_user, void *, dst, u32, size, const void __user *, unsafe_ptr)
{
	int ret;
	if (!size)
		return 0;
	ret = __copy_from_user_inatomic(dst, unsafe_ptr, size);
	if (unlikely(ret != 0)) {
		memset(dst, 0, size);
		return -EFAULT;
	}
	return 0;
}

const struct bpf_func_proto bpf_probe_read_user_proto = {
	.func		= bpf_probe_read_user,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
};

/* Common helper function proto for tracing-type BPF programs */
static const struct bpf_func_proto *
tracing_func_proto(enum bpf_func_id func_id)
{
	switch (func_id) {
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	case BPF_FUNC_ktime_get_ns:
		return &bpf_ktime_get_ns_proto;
	case BPF_FUNC_ktime_get_boot_ns:
		return &bpf_ktime_get_boot_ns_proto;
	case BPF_FUNC_tail_call:
		return &bpf_tail_call_proto;
	case BPF_FUNC_get_current_pid_tgid:
		return &bpf_get_current_pid_tgid_proto;
	case BPF_FUNC_get_current_uid_gid:
		return &bpf_get_current_uid_gid_proto;
	case BPF_FUNC_get_current_comm:
		return &bpf_get_current_comm_proto;
	case BPF_FUNC_get_smp_processor_id:
		return &bpf_get_smp_processor_id_proto;
	case BPF_FUNC_get_numa_node_id:
		return &bpf_get_numa_node_id_proto;
	case BPF_FUNC_get_prandom_u32:
		return &bpf_get_prandom_u32_proto;
	/* Probe read helpers */
	case BPF_FUNC_probe_read:
		return &bpf_probe_read_proto;
	case BPF_FUNC_probe_read_kernel:
		return &bpf_probe_read_kernel_proto;
	case BPF_FUNC_probe_read_user:
		return &bpf_probe_read_user_proto;
	/* Ringbuf helpers */
	case BPF_FUNC_ringbuf_output:
		return &bpf_ringbuf_output_proto;
	case BPF_FUNC_ringbuf_reserve:
		return &bpf_ringbuf_reserve_proto;
	case BPF_FUNC_ringbuf_submit:
		return &bpf_ringbuf_submit_proto;
	case BPF_FUNC_ringbuf_discard:
		return &bpf_ringbuf_discard_proto;
	default:
		return NULL;
	}
}

/* Tracepoint BPF program helpers */
static const struct bpf_func_proto *
tp_prog_func_proto(enum bpf_func_id func_id)
{
	return tracing_func_proto(func_id);
}

/*
 * Tracepoint BPF context: first sizeof(void *) bytes are hidden
 * (contain a pointer to struct pt_regs), rest up to PERF_MAX_TRACE_SIZE
 * are the tracepoint fields, accessible read-only.
 */
static bool tp_prog_is_valid_access(int off, int size,
				    enum bpf_access_type type,
				    struct bpf_insn_access_aux *info)
{
	if (off < sizeof(void *) || off >= PERF_MAX_TRACE_SIZE)
		return false;
	if (type != BPF_READ)
		return false;
	if (off % size != 0)
		return false;

	BUILD_BUG_ON(PERF_MAX_TRACE_SIZE % sizeof(__u64));
	return true;
}

/* Raw tracepoint BPF context validation */
static bool raw_tp_prog_is_valid_access(int off, int size,
					enum bpf_access_type type,
					struct bpf_insn_access_aux *info)
{
	/* raw tracepoint context is u64 args[MAX_BPF_FUNC_ARGS] = 5 * 8 = 40 bytes */
	if (off < 0 || off + size > sizeof(u64) * 5)
		return false;
	if (type != BPF_READ)
		return false;
	if (off % size != 0)
		return false;
	return true;
}

/* Kprobe BPF context validation - context is struct pt_regs */
static bool kprobe_prog_is_valid_access(int off, int size,
					enum bpf_access_type type,
					struct bpf_insn_access_aux *info)
{
	if (off < 0 || off + size > sizeof(struct pt_regs))
		return false;
	if (type != BPF_READ)
		return false;
	if (off % size != 0)
		return false;
	return true;
}

/* Perf event BPF context: same as tracepoint for our purposes */
static bool pe_prog_is_valid_access(int off, int size,
				    enum bpf_access_type type,
				    struct bpf_insn_access_aux *info)
{
	if (off < 0 || off >= sizeof(u64) * 256)
		return false;
	if (type != BPF_READ)
		return false;
	if (off % size != 0)
		return false;
	return true;
}

/* ---- End BPF tracing program type implementations ---- */

const struct bpf_verifier_ops cg_sock_addr_prog_ops = {
	.get_func_proto		= sock_filter_func_proto,
	.is_valid_access	= sock_addr_is_valid_access,
	.convert_ctx_access	= sock_addr_convert_ctx_access,
};
const struct bpf_verifier_ops sock_ops_prog_ops = {};
const struct bpf_verifier_ops sk_skb_prog_ops = {};
const struct bpf_verifier_ops cg_dev_prog_ops = {};
const struct bpf_verifier_ops sk_msg_prog_ops = {};
const struct bpf_verifier_ops raw_tp_prog_ops = {
	.get_func_proto		= tracing_func_proto,
	.is_valid_access	= raw_tp_prog_is_valid_access,
};
const struct bpf_verifier_ops lwt_seg6local_prog_ops = {};
const struct bpf_verifier_ops lirc_mode2_prog_ops = {};
const struct bpf_verifier_ops sk_reuseport_prog_ops = {};
const struct bpf_verifier_ops flow_dissector_prog_ops = {};
const struct bpf_verifier_ops cg_sysctl_prog_ops = {};
const struct bpf_verifier_ops raw_tp_writable_prog_ops = {
	.get_func_proto		= tracing_func_proto,
	.is_valid_access	= raw_tp_prog_is_valid_access,
};
const struct bpf_verifier_ops cg_sockopt_prog_ops = {
	.get_func_proto		= sock_filter_func_proto,
	.is_valid_access	= sockopt_is_valid_access,
	.convert_ctx_access	= sockopt_convert_ctx_access,
};
/* BPF_EVENTS program types with proper tracing support */
const struct bpf_verifier_ops kprobe_prog_ops = {
	.get_func_proto		= tracing_func_proto,
	.is_valid_access	= kprobe_prog_is_valid_access,
};
const struct bpf_verifier_ops tracepoint_prog_ops = {
	.get_func_proto		= tp_prog_func_proto,
	.is_valid_access	= tp_prog_is_valid_access,
};
const struct bpf_verifier_ops perf_event_prog_ops = {
	.get_func_proto		= tracing_func_proto,
	.is_valid_access	= pe_prog_is_valid_access,
};

int sk_detach_filter(struct sock *sk)
{
	int ret = -ENOENT;
	struct sk_filter *filter;

	if (sock_flag(sk, SOCK_FILTER_LOCKED))
		return -EPERM;

	filter = rcu_dereference_protected(sk->sk_filter,
					   lockdep_sock_is_held(sk));
	if (filter) {
		RCU_INIT_POINTER(sk->sk_filter, NULL);
		sk_filter_uncharge(sk, filter);
		ret = 0;
	}

	return ret;
}
EXPORT_SYMBOL_GPL(sk_detach_filter);

int sk_get_filter(struct sock *sk, struct sock_filter __user *ubuf,
		  unsigned int len)
{
	struct sock_fprog_kern *fprog;
	struct sk_filter *filter;
	int ret = 0;

	lock_sock(sk);
	filter = rcu_dereference_protected(sk->sk_filter,
					   lockdep_sock_is_held(sk));
	if (!filter)
		goto out;

	/* We're copying the filter that has been originally attached,
	 * so no conversion/decode needed anymore. eBPF programs that
	 * have no original program cannot be dumped through this.
	 */
	ret = -EACCES;
	fprog = filter->prog->orig_prog;
	if (!fprog)
		goto out;

	ret = fprog->len;
	if (!len)
		/* User space only enquires number of filter blocks. */
		goto out;

	ret = -EINVAL;
	if (len < fprog->len)
		goto out;

	ret = -EFAULT;
	if (copy_to_user(ubuf, fprog->filter, bpf_classic_proglen(fprog)))
		goto out;

	/* Instead of bytes, the API requests to return the number
	 * of filter blocks.
	 */
	ret = fprog->len;
out:
	release_sock(sk);
	return ret;
}



/* Stubs for missing devmap functions */
/*
void __dev_map_flush(struct bpf_map *map) {}
EXPORT_SYMBOL(__dev_map_flush);

struct net_device *__dev_map_lookup_elem(struct bpf_map *map, u32 key)
{
return NULL;
}
EXPORT_SYMBOL(__dev_map_lookup_elem);
*/

void sk_filter_release_rcu(struct rcu_head *rcu)
{
struct sk_filter *fp = container_of(rcu, struct sk_filter, rcu);

bpf_prog_destroy(fp->prog);
kfree(fp);
}
EXPORT_SYMBOL(sk_filter_release_rcu);


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

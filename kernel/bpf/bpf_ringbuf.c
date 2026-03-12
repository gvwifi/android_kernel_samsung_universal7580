/*
 * Minimal BPF_MAP_TYPE_RINGBUF stub for 3.10 kernel backport.
 * The ringbuf map can be created and freed but doesn't actually
 * buffer data. bpf_ringbuf_reserve always returns NULL so the
 * BPF program takes the early-exit path and never writes to
 * or submits any ringbuf entry.
 */

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/slab.h>

static struct bpf_map *ringbuf_map_alloc(union bpf_attr *attr)
{
	struct bpf_map *map;

	if (attr->key_size != 0)
		return ERR_PTR(-EINVAL);

	map = kzalloc(sizeof(*map), GFP_KERNEL);
	if (!map)
		return ERR_PTR(-ENOMEM);

	map->map_type = attr->map_type;
	map->key_size = 0;
	map->value_size = 0;
	map->max_entries = attr->max_entries;
	map->map_flags = attr->map_flags;
	map->pages = 1;
	return map;
}

static void ringbuf_map_free(struct bpf_map *map)
{
	kfree(map);
}

static void *ringbuf_map_lookup_elem(struct bpf_map *map, void *key)
{
	return NULL;
}

static int ringbuf_map_update_elem(struct bpf_map *map, void *key,
				   void *value, u64 flags)
{
	return -ENOTSUPP;
}

static int ringbuf_map_delete_elem(struct bpf_map *map, void *key)
{
	return -ENOTSUPP;
}

static int ringbuf_map_get_next_key(struct bpf_map *map, void *key,
				    void *next_key)
{
	return -ENOTSUPP;
}

const struct bpf_map_ops ringbuf_map_ops = {
	.map_alloc		= ringbuf_map_alloc,
	.map_free		= ringbuf_map_free,
	.map_lookup_elem	= ringbuf_map_lookup_elem,
	.map_update_elem	= ringbuf_map_update_elem,
	.map_delete_elem	= ringbuf_map_delete_elem,
	.map_get_next_key	= ringbuf_map_get_next_key,
};

/* --- Ringbuf helper stubs --- */

BPF_CALL_4(bpf_ringbuf_output, struct bpf_map *, map,
	   void *, data, u64, size, u64, flags)
{
	return -ENOSPC;
}

const struct bpf_func_proto bpf_ringbuf_output_proto = {
	.func		= bpf_ringbuf_output,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MEM,
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg4_type	= ARG_ANYTHING,
};

BPF_CALL_3(bpf_ringbuf_reserve, struct bpf_map *, map,
	   u64, size, u64, flags)
{
	return 0; /* NULL — no reservation available */
}

const struct bpf_func_proto bpf_ringbuf_reserve_proto = {
	.func		= bpf_ringbuf_reserve,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_ringbuf_submit, void *, data, u64, flags)
{
	/* no-op — reserve always returns NULL so this is dead code */
	return 0;
}

const struct bpf_func_proto bpf_ringbuf_submit_proto = {
	.func		= bpf_ringbuf_submit,
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_PTR_TO_MEM,
	.arg2_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_ringbuf_discard, void *, data, u64, flags)
{
	/* no-op */
	return 0;
}

const struct bpf_func_proto bpf_ringbuf_discard_proto = {
	.func		= bpf_ringbuf_discard,
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_PTR_TO_MEM,
	.arg2_type	= ARG_ANYTHING,
};

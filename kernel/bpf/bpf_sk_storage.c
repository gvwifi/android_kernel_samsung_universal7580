/*
 * Minimal BPF SK_STORAGE map stub for 3.10 kernel backport.
 * Provides a dummy map that can be created/freed but doesn't
 * actually store per-socket data. Programs that use
 * bpf_sk_storage_get() will just get NULL.
 */

#include <linux/bpf.h>
#include <linux/slab.h>

/* BPF_MAP_TYPE_SK_STORAGE requires max_entries=0 and key_size=4 */
static struct bpf_map *sk_storage_map_alloc(union bpf_attr *attr)
{
	struct bpf_map *map;

	/* SK_STORAGE uses key_size=4 (socket fd from userspace) */
	if (attr->key_size != 4)
		return ERR_PTR(-EINVAL);

	map = kzalloc(sizeof(*map), GFP_KERNEL);
	if (!map)
		return ERR_PTR(-ENOMEM);

	map->map_type = attr->map_type;
	map->key_size = attr->key_size;
	map->value_size = attr->value_size;
	map->max_entries = attr->max_entries;
	map->map_flags = attr->map_flags;
	return map;
}

static void sk_storage_map_free(struct bpf_map *map)
{
	kfree(map);
}

static void *sk_storage_map_lookup_elem(struct bpf_map *map, void *key)
{
	return NULL;
}

static int sk_storage_map_update_elem(struct bpf_map *map, void *key,
				      void *value, u64 flags)
{
	return -ENOTSUPP;
}

static int sk_storage_map_delete_elem(struct bpf_map *map, void *key)
{
	return -ENOTSUPP;
}

static int sk_storage_map_get_next_key(struct bpf_map *map, void *key,
				       void *next_key)
{
	return -ENOTSUPP;
}

const struct bpf_map_ops sk_storage_map_ops = {
	.map_alloc	= sk_storage_map_alloc,
	.map_free	= sk_storage_map_free,
	.map_lookup_elem = sk_storage_map_lookup_elem,
	.map_update_elem = sk_storage_map_update_elem,
	.map_delete_elem = sk_storage_map_delete_elem,
	.map_get_next_key = sk_storage_map_get_next_key,
};

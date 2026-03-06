/*
 * Copyright (C) 2014 Sergey Senozhatsky.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/lz4.h>

#include "zcomp_lz4.h"

static void *zcomp_lz4_create(void)
{
	/*
	 * LZ4_compress_default() in this kernel requires an external workmem
	 * buffer of LZ4_MEM_COMPRESS bytes passed as the 5th argument.
	 */
	return kzalloc(LZ4_MEM_COMPRESS, GFP_KERNEL);
}

static void zcomp_lz4_destroy(void *private)
{
	kfree(private);
}

static int zcomp_lz4_compress(const unsigned char *src, unsigned char *dst,
		size_t *dst_len, void *private)
{
	int ret;

	/*
	 * LZ4_compress_default() returns the number of bytes written (>0) on
	 * success, or 0 on failure.  *dst_len is the output buffer size.
	 * private is the workmem buffer (LZ4_MEM_COMPRESS bytes).
	 */
	ret = LZ4_compress_default(src, dst, PAGE_SIZE, *dst_len, private);
	if (ret == 0)
		return -EINVAL;
	*dst_len = ret;
	return 0;
}

static int zcomp_lz4_decompress(const unsigned char *src, size_t src_len,
		unsigned char *dst)
{
	int ret;

	/*
	 * LZ4_decompress_safe() returns the number of bytes decompressed (>=0)
	 * on success, or a negative error code.
	 */
	ret = LZ4_decompress_safe(src, dst, src_len, PAGE_SIZE);
	if (ret < 0)
		return ret;
	return 0;
}

struct zcomp_backend zcomp_lz4 = {
	.compress	= zcomp_lz4_compress,
	.decompress	= zcomp_lz4_decompress,
	.create		= zcomp_lz4_create,
	.destroy	= zcomp_lz4_destroy,
	.name		= "lz4",
};

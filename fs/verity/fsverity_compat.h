#ifndef _FS_VERITY_COMPAT_H
#define _FS_VERITY_COMPAT_H

#include <linux/bio.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/mempool.h>

/* Crypto API compat */
#ifndef DECLARE_CRYPTO_WAIT
struct crypto_wait {
	struct completion completion;
	int err;
};

static inline void crypto_init_wait(struct crypto_wait *wait)
{
	init_completion(&wait->completion);
	wait->err = 0;
}

static inline void crypto_req_done(struct crypto_async_request *req, int err)
{
	struct crypto_wait *wait = req->data;

	if (err == -EINPROGRESS)
		return;

	wait->err = err;
	complete(&wait->completion);
}

static inline int crypto_wait_req(int err, struct crypto_wait *wait)
{
	switch (err) {
	case -EINPROGRESS:
	case -EBUSY:
		wait_for_completion(&wait->completion);
		INIT_COMPLETION(wait->completion);
		err = wait->err;
		break;
	};

	return err;
}

#define DECLARE_CRYPTO_WAIT(_wait) \
	struct crypto_wait _wait = { \
		.completion = COMPLETION_INITIALIZER_ONSTACK((_wait).completion), \
	};
#endif /* DECLARE_CRYPTO_WAIT */

/* Crypto macros */
#ifndef crypto_ahash_driver_name
#define crypto_ahash_driver_name(tfm) crypto_tfm_alg_driver_name(crypto_ahash_tfm(tfm))
#endif

#ifndef crypto_ahash_blocksize
static inline unsigned int crypto_ahash_blocksize(struct crypto_ahash *tfm)
{
	return crypto_tfm_alg_blocksize(crypto_ahash_tfm(tfm));
}
#endif
/* Wait, crypto_ahash_blocksize IS a function in 3.10? Or macro? */
/* In 3.10: #define crypto_ahash_blocksize(tfm) crypto_tfm_alg_blocksize(crypto_ahash_tfm(tfm)) */
/* So it should work if <linux/crypto.h> is included. */

/* d_inode compat */
#ifndef d_inode
#define d_inode(dentry) ((dentry)->d_inode)
#endif

/* Mempool compat */
/* 
 * 3.10 mempool_t is a pointer. 5.4 mempool_t is a struct (sometimes embedded).
 * In 5.4 code: mempool_init_kmalloc_pool(&alg->req_pool, ...)
 * In 3.10 we need to allocate the pool.
 * We will override mempool_init_kmalloc_pool to do mempool_create call and assign to *pool.
 * BUT 'alg->req_pool' in 3.10 is 'mempool_t' (pointer). &alg->req_pool is 'mempool_t *'.
 */
static inline int mempool_init_kmalloc_pool(mempool_t **pool, int min_nr, size_t size)
{
	*pool = mempool_create_kmalloc_pool(min_nr, size);
	return *pool ? 0 : -ENOMEM;
}

static inline void mempool_exit(mempool_t **pool)
{
	if (*pool)
		mempool_destroy(*pool);
	*pool = NULL;
}

/* ahash_request_zero */
static inline void ahash_request_zero(struct ahash_request *req)
{
    /* 5.4 zeroes the request context? Or the request itself? */
    /* Implementation in 5.4: 
       ahash_request_set_tfm(req, NULL); 
       but here we might just memset.
    */
    /* Actually ahash_request structure is opaque to some degree? */
    /* fs/verity/hash_algs.c calls it before freeing. */
    /* In 5.4 it does:
       static inline void ahash_request_zero(struct ahash_request *req) {
           memzero_explicit(req, sizeof(*req) + crypto_ahash_reqsize(crypto_ahash_reqtfm(req)));
       }
    */
    /* We can implement it similarly */
    if (req->base.tfm) {
        memset(req, 0, sizeof(*req) + crypto_ahash_reqsize(crypto_ahash_reqtfm(req)));
    }
}

/* BIO Compat */
#ifdef CONFIG_BLOCK
#ifndef REQ_OP_READ
#define REQ_OP_READ READ
#endif

/* bio_first_page_all */
static inline struct page *bio_first_page_all(struct bio *bio)
{
	if (!bio->bi_io_vec) return NULL;
	return bio->bi_io_vec[0].bv_page;
}

/* 3.10 bio doesn't have bi_opf. Use bi_rw. */
#define bi_opf bi_rw

/* Iterator replacement */
struct bvec_iter_all {
	int idx;
};

#undef bio_for_each_segment_all
#define bio_for_each_segment_all(bvl, bio, iter) \
	for ((iter).idx = 0, (bvl) = (bio)->bi_io_vec; (iter).idx < (bio)->bi_vcnt; (iter).idx++, (bvl)++)

#endif /* CONFIG_BLOCK */

#ifndef KMEM_CACHE_USERCOPY
#define KMEM_CACHE_USERCOPY(name, flags, field) \
	kmem_cache_create(#name, sizeof(struct name), \
			  __alignof__(struct name), (flags), NULL)
#endif

#ifndef u64_to_user_ptr
#define u64_to_user_ptr(x) ((void __user *)(uintptr_t)(x))
#endif

#ifndef inode_lock
#define inode_lock(inode) mutex_lock(&(inode)->i_mutex)
#define inode_unlock(inode) mutex_unlock(&(inode)->i_mutex)
#endif

#endif /* _FS_VERITY_COMPAT_H */

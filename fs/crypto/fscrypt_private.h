/*
 * fscrypt_private.h
 *
 * Copyright (C) 2015, Google, Inc.
 *
 * This contains encryption key functions and internal structures.
 *
 * Written by Michael Halcrow, Ildar Muslukhov, and Uday Savagaonkar, 2015.
 * Backported fscrypt v2 from Linux 5.4.
 */

#ifndef _FSCRYPT_PRIVATE_H
#define _FSCRYPT_PRIVATE_H

#include <linux/fs.h>
#include <linux/bio.h>
#include <linux/fscrypt.h>
#include <crypto/hash.h>
#include <crypto/sha.h>
#include <linux/key.h>
#include <linux/scatterlist.h>

/* Encryption parameters */
#define FS_IV_SIZE			16
#define FS_AES_128_ECB_KEY_SIZE		16
#define FS_AES_128_CBC_KEY_SIZE		16
#define FS_AES_128_CTS_KEY_SIZE		16
#define FS_AES_256_GCM_KEY_SIZE		32
#define FS_AES_256_CBC_KEY_SIZE		32
#define FS_AES_256_CTS_KEY_SIZE		32
#define FS_AES_256_XTS_KEY_SIZE		64

#define FS_KEY_DERIVATION_NONCE_SIZE		16

/* Filename encryption parameters */
#define FSCRYPT_FNAME_MAX_UNDIGESTED_SIZE	32
#define FSCRYPT_FNAME_DIGEST_SIZE		16
#define FSCRYPT_FNAME_DIGEST(name, len)		((u8 *)&(name)[(len) - FSCRYPT_FNAME_DIGEST_SIZE])

/*
 * Digested name structure for representing long encrypted filenames
 * The hash and minor_hash are used for lookups without the key
 */
struct fscrypt_digested_name {
	u32 hash;
	u32 minor_hash;
	u8 digest[FSCRYPT_FNAME_DIGEST_SIZE];
};

/**
 * fscrypt_is_dot_dotdot() - check if the filename is "." or ".."
 */
static inline bool fscrypt_is_dot_dotdot(const struct qstr *str)
{
	if (str->len == 1 && str->name[0] == '.')
		return true;
	if (str->len == 2 && str->name[0] == '.' && str->name[1] == '.')
		return true;
	return false;
}

#define FSCRYPT_MIN_KEY_SIZE		16

#define CONST_STRLEN(str)	(sizeof(str) - 1)

/*
 * Encryption context versions
 */
#define FSCRYPT_CONTEXT_V1	1
#define FSCRYPT_CONTEXT_V2	2

/* Legacy alias for old code */
#define FS_ENCRYPTION_CONTEXT_FORMAT_V1	FSCRYPT_CONTEXT_V1

/*
 * Encryption context v1 - legacy format.
 * Protector format:
 *  1 byte: Protector format (1 = this version)
 *  1 byte: File contents encryption mode
 *  1 byte: File names encryption mode
 *  1 byte: Flags
 *  8 bytes: Master Key descriptor
 *  16 bytes: Encryption Key derivation nonce
 */
struct fscrypt_context_v1 {
	u8 format; /* FSCRYPT_CONTEXT_V1 - called 'format' for legacy compat */
	u8 contents_encryption_mode;
	u8 filenames_encryption_mode;
	u8 flags;
	u8 master_key_descriptor[FSCRYPT_KEY_DESCRIPTOR_SIZE];
	u8 nonce[FS_KEY_DERIVATION_NONCE_SIZE];
} __packed;

/*
 * Encryption context v2 - new format with HKDF.
 */
struct fscrypt_context_v2 {
	u8 version; /* FSCRYPT_CONTEXT_V2 */
	u8 contents_encryption_mode;
	u8 filenames_encryption_mode;
	u8 flags;
	u8 __reserved[4];
	u8 master_key_identifier[FSCRYPT_KEY_IDENTIFIER_SIZE];
	u8 nonce[FS_KEY_DERIVATION_NONCE_SIZE];
} __packed;

/*
 * fscrypt_context - the encryption context of an inode
 *
 * This is the on-disk equivalent of an fscrypt_policy, stored alongside each
 * encrypted file usually in a hidden extended attribute.
 */
union fscrypt_context {
	u8 version;
	struct fscrypt_context_v1 v1;
	struct fscrypt_context_v2 v2;
};

/*
 * Return the size expected for the given fscrypt_context based on its version
 * number, or 0 if the context version is unrecognized.
 */
static inline int fscrypt_context_size(const union fscrypt_context *ctx)
{
	switch (ctx->version) {
	case FSCRYPT_CONTEXT_V1:
		BUILD_BUG_ON(sizeof(ctx->v1) != 28);
		return sizeof(ctx->v1);
	case FSCRYPT_CONTEXT_V2:
		BUILD_BUG_ON(sizeof(ctx->v2) != 40);
		return sizeof(ctx->v2);
	}
	return 0;
}

/* Check whether an fscrypt_context has a recognized version number and size */
static inline bool fscrypt_context_is_valid(const union fscrypt_context *ctx,
					    int ctx_size)
{
	return ctx_size >= 1 && ctx_size == fscrypt_context_size(ctx);
}

/* Retrieve the context's nonce, assuming the context was already validated */
static inline const u8 *fscrypt_context_nonce(const union fscrypt_context *ctx)
{
	switch (ctx->version) {
	case FSCRYPT_CONTEXT_V1:
		return ctx->v1.nonce;
	case FSCRYPT_CONTEXT_V2:
		return ctx->v2.nonce;
	}
	WARN_ON(1);
	return NULL;
}

/*
 * Policy union - internal representation
 * Undefine the macro from uapi/linux/fscrypt.h to avoid conflict
 */
#undef fscrypt_policy
union fscrypt_policy {
	u8 version;
	struct fscrypt_policy_v1 v1;
	struct fscrypt_policy_v2 v2;
};

/*
 * Return the size expected for the given fscrypt_policy based on its version
 */
static inline int fscrypt_policy_size(const union fscrypt_policy *policy)
{
	switch (policy->version) {
	case FSCRYPT_POLICY_V1:
		return sizeof(policy->v1);
	case FSCRYPT_POLICY_V2:
		return sizeof(policy->v2);
	}
	return 0;
}

/* Return the contents encryption mode of a valid encryption policy */
static inline u8
fscrypt_policy_contents_mode(const union fscrypt_policy *policy)
{
	switch (policy->version) {
	case FSCRYPT_POLICY_V1:
		return policy->v1.contents_encryption_mode;
	case FSCRYPT_POLICY_V2:
		return policy->v2.contents_encryption_mode;
	}
	BUG();
}

/* Return the filenames encryption mode of a valid encryption policy */
static inline u8
fscrypt_policy_fnames_mode(const union fscrypt_policy *policy)
{
	switch (policy->version) {
	case FSCRYPT_POLICY_V1:
		return policy->v1.filenames_encryption_mode;
	case FSCRYPT_POLICY_V2:
		return policy->v2.filenames_encryption_mode;
	}
	BUG();
}

/* Return the flags of a valid encryption policy */
static inline u8
fscrypt_policy_flags(const union fscrypt_policy *policy)
{
	switch (policy->version) {
	case FSCRYPT_POLICY_V1:
		return policy->v1.flags;
	case FSCRYPT_POLICY_V2:
		return policy->v2.flags;
	}
	BUG();
}

/*
 * For encrypted symlinks, the ciphertext length is stored at the beginning
 * of the string in little-endian format.
 */
struct fscrypt_symlink_data {
	__le16 len;
	char encrypted_path[1];
} __packed;

typedef enum {
	FS_DECRYPT = 0,
	FS_ENCRYPT,
} fscrypt_direction_t;

#define FS_CTX_REQUIRES_FREE_ENCRYPT_FL		0x00000001
#define FS_CTX_HAS_BOUNCE_BUFFER_FL		0x00000002

/* fscrypt_ctx - used for encryption/decryption context */
struct fscrypt_ctx {
	union {
		struct {
			struct page *bounce_page;
			struct page *control_page;
		} w;
		struct {
			struct bio *bio;
			struct work_struct work;
		} r;
		struct list_head free_list;
	};
	u8 flags;
};

struct fscrypt_completion_result {
	struct completion completion;
	int res;
};

#define DECLARE_FS_COMPLETION_RESULT(ecr) \
	struct fscrypt_completion_result ecr = { \
		COMPLETION_INITIALIZER_ONSTACK((ecr).completion), 0 }

/*
 * HKDF context for v2 key derivation
 */
struct fscrypt_hkdf {
	struct crypto_shash *hmac_tfm;
};

/*
 * The list of contexts in which fscrypt uses HKDF.
 */
#define HKDF_CONTEXT_KEY_IDENTIFIER	1
#define HKDF_CONTEXT_PER_FILE_ENC_KEY	2
#define HKDF_CONTEXT_DIRECT_KEY		3
#define HKDF_CONTEXT_IV_INO_LBLK_64_KEY	4
#define HKDF_CONTEXT_DIRHASH_KEY	5
#define HKDF_CONTEXT_IV_INO_LBLK_32_KEY	6
#define HKDF_CONTEXT_INODE_HASH_KEY	7

/*
 * fscrypt_master_key_secret - secret key material of an in-use master key
 */
struct fscrypt_master_key_secret {
	/*
	 * For v2 policy keys: HKDF context keyed by this master key.
	 * For v1 policy keys: not set (hkdf.hmac_tfm == NULL).
	 */
	struct fscrypt_hkdf	hkdf;

	/* Size of the raw key in bytes */
	u32			size;

	/* The raw key */
	u8			raw[FSCRYPT_MAX_KEY_SIZE];
};

/*
 * fscrypt_master_key - an in-use master key
 *
 * This represents a master encryption key which has been added to the
 * filesystem and can be used to "unlock" encrypted files.
 */
struct fscrypt_master_key {
	/*
	 * The secret key material
	 */
	struct fscrypt_master_key_secret	mk_secret;
	struct rw_semaphore			mk_secret_sem;

	/*
	 * For v1 policy keys: an arbitrary key descriptor.
	 * For v2 policy keys: a cryptographic hash of this key.
	 */
	struct fscrypt_key_specifier		mk_spec;

	/*
	 * Keyring which contains a key for each user who has added this key.
	 */
	struct key		*mk_users;

	/*
	 * Reference count
	 */
	atomic_t		mk_refcount;

	/*
	 * List of inodes that were unlocked using this key.
	 */
	struct list_head	mk_decrypted_inodes;
	spinlock_t		mk_decrypted_inodes_lock;

	/*
	 * Per-mode encryption keys for different encryption policies.
	 */
	struct crypto_ablkcipher *mk_direct_tfms[__FSCRYPT_MODE_MAX + 1];
	struct crypto_ablkcipher *mk_iv_ino_lblk_64_tfms[__FSCRYPT_MODE_MAX + 1];
};

static inline bool
is_master_key_secret_present(const struct fscrypt_master_key_secret *secret)
{
	return secret->size != 0;
}

static inline const char *master_key_spec_type(
				const struct fscrypt_key_specifier *spec)
{
	switch (spec->type) {
	case FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR:
		return "descriptor";
	case FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER:
		return "identifier";
	}
	return "[unknown]";
}

static inline int master_key_spec_len(const struct fscrypt_key_specifier *spec)
{
	switch (spec->type) {
	case FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR:
		return FSCRYPT_KEY_DESCRIPTOR_SIZE;
	case FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER:
		return FSCRYPT_KEY_IDENTIFIER_SIZE;
	}
	return 0;
}

/*
 * fscrypt_info - the "encryption key" for an inode
 *
 * When an encrypted file's key is made available, an instance of this struct is
 * allocated and stored in ->i_crypt_info.
 */
struct fscrypt_info {
	/* The contents/filenames encryption mode */
	u8 ci_data_mode;
	u8 ci_filename_mode;
	u8 ci_flags;

	/* The crypto transform for contents encryption */
	struct crypto_ablkcipher *ci_ctfm;

	/* The crypto transform for filenames encryption (ESSIV) */
	struct crypto_cipher *ci_essiv_tfm;

	/* The master key ref (struct key * ptr) with which this inode was unlocked */
	struct key *ci_master_key_ptr;

	/* Link in list of inodes unlocked with the master key */
	struct list_head ci_master_key_link;

	/* The master key descriptor (8 bytes) - for legacy v1 policies */
	u8 ci_master_key[FSCRYPT_KEY_DESCRIPTOR_SIZE];

	/* The encryption policy used by this inode */
	union fscrypt_policy ci_policy;

	/* This inode's nonce, copied from the fscrypt_context */
	u8 ci_nonce[FS_KEY_DERIVATION_NONCE_SIZE];
};

/*
 * Note: For backward compatibility with policy.c, struct fscrypt_context_v1 is
 * used directly as 'struct fscrypt_context' in legacy code, while union
 * fscrypt_context is used for code that handles both v1 and v2 contexts.
 */

/* Global fscrypt_info slab cache - defined in crypto.c */
extern struct kmem_cache *fscrypt_info_cachep;

/**
 * fscrypt_dummy_context_enabled() - check if dummy context is enabled
 *
 * Checks whether the inode's superblock supports dummy encryption contexts
 * for unencrypted directories (used for test/debug purposes).
 */
static inline bool fscrypt_dummy_context_enabled(struct inode *inode)
{
	if (inode->i_sb->s_cop && inode->i_sb->s_cop->dummy_context)
		return inode->i_sb->s_cop->dummy_context(inode) != 0;
	return false;
}

/*
 * Validate that the encryption modes are valid.
 */
static inline bool fscrypt_valid_enc_modes(u32 contents_mode, u32 filenames_mode)
{
	/* AES-256-XTS for contents, AES-256-CTS for filenames */
	if (contents_mode == FSCRYPT_MODE_AES_256_XTS &&
	    filenames_mode == FSCRYPT_MODE_AES_256_CTS)
		return true;

	/* AES-128-CBC for contents, AES-128-CTS for filenames */
	if (contents_mode == FSCRYPT_MODE_AES_128_CBC &&
	    filenames_mode == FSCRYPT_MODE_AES_128_CTS)
		return true;

	return false;
}

/* 3.10 kernel compatibility helpers */
static inline void inode_lock(struct inode *inode)
{
	mutex_lock(&inode->i_mutex);
}

static inline void inode_unlock(struct inode *inode)
{
	mutex_unlock(&inode->i_mutex);
}

static inline struct inode *d_inode(const struct dentry *dentry)
{
	return dentry->d_inode;
}

static inline bool d_is_negative(const struct dentry *dentry)
{
	return (dentry->d_inode == NULL);
}

/* bio stuffs */
#define REQ_OP_READ	READ
#define REQ_OP_WRITE	WRITE
#define bio_op(bio)	((bio)->bi_rw & 1)

static inline void bio_set_op_attrs(struct bio *bio, unsigned op,
		unsigned op_flags)
{
	bio->bi_rw = op | op_flags;
}

static inline const struct user_key_payload *user_key_payload(const struct key *key)
{
	return (struct user_key_payload *)rcu_dereference_key(key);
}

/* crypto.c */
extern int fscrypt_initialize(unsigned int cop_flags);
extern struct workqueue_struct *fscrypt_read_workqueue;
extern int fscrypt_do_page_crypto(const struct inode *inode,
				  fscrypt_direction_t rw, u64 lblk_num,
				  struct page *src_page,
				  struct page *dest_page,
				  unsigned int len, unsigned int offs,
				  gfp_t gfp_flags);
extern struct page *fscrypt_alloc_bounce_page(struct fscrypt_ctx *ctx,
					      gfp_t gfp_flags);

void __printf(3, 4) __cold
fscrypt_msg(const struct inode *inode, const char *level, const char *fmt, ...);

#define fscrypt_warn(inode, fmt, ...)		\
	fscrypt_msg((inode), KERN_WARNING, fmt, ##__VA_ARGS__)
#define fscrypt_err(inode, fmt, ...)		\
	fscrypt_msg((inode), KERN_ERR, fmt, ##__VA_ARGS__)

/* hkdf.c */
int fscrypt_init_hkdf(struct fscrypt_hkdf *hkdf, const u8 *master_key,
		      unsigned int master_key_size);
int fscrypt_hkdf_expand(const struct fscrypt_hkdf *hkdf, u8 context,
			const u8 *info, unsigned int infolen,
			u8 *okm, unsigned int okmlen);
void fscrypt_destroy_hkdf(struct fscrypt_hkdf *hkdf);

/* keyring.c */
struct key *
fscrypt_find_master_key(struct super_block *sb,
			const struct fscrypt_key_specifier *mk_spec);
int fscrypt_verify_key_added(struct super_block *sb,
			     const u8 identifier[FSCRYPT_KEY_IDENTIFIER_SIZE]);
int __init fscrypt_init_keyring(void);

/* keysetup.c / keyinfo.c */
extern void __exit fscrypt_essiv_cleanup(void);
int fscrypt_setup_v1_file_key(struct fscrypt_info *ci,
			      const u8 *raw_master_key);
int fscrypt_setup_v1_file_key_via_subscribed_keyrings(struct fscrypt_info *ci);
int fscrypt_setup_v2_file_key(struct fscrypt_info *ci,
			      struct fscrypt_master_key *mk);

/* policy.c */
bool fscrypt_policies_equal(const union fscrypt_policy *policy1,
			    const union fscrypt_policy *policy2);
bool fscrypt_supported_policy(const union fscrypt_policy *policy_u,
			      const struct inode *inode);
int fscrypt_policy_from_context(union fscrypt_policy *policy_u,
				const union fscrypt_context *ctx_u,
				int ctx_size);

#endif /* _FSCRYPT_PRIVATE_H */

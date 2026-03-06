/*
 * fscrypt.h: declarations for per-file encryption
 *
 * Filesystems that implement per-file encryption must include this header.
 *
 * Backported from Linux 5.4 to 3.10 for Android 16 fscrypt v2 support.
 *
 * Copyright (C) 2015, Google, Inc.
 * Written by Michael Halcrow, 2015.
 * Modified by Jaegeuk Kim, 2015.
 */
#ifndef _LINUX_FSCRYPT_H
#define _LINUX_FSCRYPT_H

#include <linux/dcache.h>
#include <linux/slab.h>
#include <uapi/linux/fscrypt.h>

#define FS_CRYPTO_BLOCK_SIZE		16

/* Forward declarations */
struct inode;
struct super_block;
struct file;
struct page;
struct bio;
struct fscrypt_ctx;
union fscrypt_context;
struct fscrypt_info;
struct fscrypt_master_key;
struct fscrypt_operations;

struct fscrypt_str {
	unsigned char *name;
	u32 len;
};

struct fscrypt_name {
	const struct qstr *usr_fname;
	struct fscrypt_str disk_name;
	u32 hash;
	u32 minor_hash;
	struct fscrypt_str crypto_buf;
	bool is_ciphertext_name;
};

#define FSTR_INIT(n, l)		{ .name = n, .len = l }
#define FSTR_TO_QSTR(f)		QSTR_INIT((f)->name, (f)->len)
#define fname_name(p)		((p)->disk_name.name)
#define fname_len(p)		((p)->disk_name.len)

/* Maximum value for the third parameter of fscrypt_operations.set_context(). */
#define FSCRYPT_SET_CONTEXT_MAX_SIZE	40

#ifdef CONFIG_FS_ENCRYPTION
/*
 * fscrypt superblock flags
 */
#define FS_CFLG_OWN_PAGES (1U << 1)

/*
 * crypto operations for filesystems
 */
struct fscrypt_operations {
	unsigned int flags;
	const char *key_prefix;
	int (*get_context)(struct inode *inode, void *ctx, size_t len);
	int (*prepare_context)(struct inode *inode);
	int (*set_context)(struct inode *inode, const void *ctx, size_t len,
			   void *fs_data);
	int (*dummy_context)(struct inode *inode);
	const union fscrypt_context *(*get_dummy_context)(
		struct super_block *sb);
	bool (*is_encrypted)(struct inode *inode);
	bool (*empty_dir)(struct inode *inode);
	unsigned int (*max_namelen)(struct inode *inode);
	bool (*has_stable_inodes)(struct super_block *sb);
	void (*get_ino_and_lblk_bits)(struct super_block *sb,
				      int *ino_bits_ret, int *lblk_bits_ret);
};

/* crypto.c */
extern struct workqueue_struct *fscrypt_read_workqueue;
void fscrypt_enqueue_decrypt_work(struct work_struct *work);

struct page *fscrypt_encrypt_page(const struct inode *inode, struct page *page,
				  unsigned int len, unsigned int offs,
				  u64 lblk_num, gfp_t gfp_flags);
int fscrypt_decrypt_page(const struct inode *inode, struct page *page,
			 unsigned int len, unsigned int offs, u64 lblk_num);

void fscrypt_free_bounce_page(struct page *bounce_page);

/* policy.c */
int fscrypt_ioctl_set_policy(struct file *filp, const void __user *arg);
int fscrypt_ioctl_get_policy(struct file *filp, void __user *arg);
int fscrypt_ioctl_get_policy_ex(struct file *filp, void __user *arg);
int fscrypt_ioctl_get_nonce(struct file *filp, void __user *arg);
int fscrypt_has_permitted_context(struct inode *parent, struct inode *child);
int fscrypt_inherit_context(struct inode *parent, struct inode *child,
			    void *fs_data, bool preload);

/* keyring.c */
void fscrypt_sb_free(struct super_block *sb);
int fscrypt_ioctl_add_key(struct file *filp, void __user *arg);
int fscrypt_ioctl_remove_key(struct file *filp, void __user *arg);
int fscrypt_ioctl_remove_key_all_users(struct file *filp, void __user *arg);
int fscrypt_ioctl_get_key_status(struct file *filp, void __user *arg);

/* keysetup.c */
int fscrypt_get_encryption_info(struct inode *inode);
void fscrypt_put_encryption_info(struct inode *inode, struct fscrypt_info *ci);
int fscrypt_drop_inode(struct inode *inode);

/* fname.c */
int fscrypt_setup_filename(struct inode *inode, const struct qstr *iname,
			   int lookup, struct fscrypt_name *fname);

static inline void fscrypt_free_filename(struct fscrypt_name *fname)
{
	kfree(fname->crypto_buf.name);
	fname->crypto_buf.name = NULL;
}

int fscrypt_fname_alloc_buffer(const struct inode *inode, u32 max_encrypted_len,
			       struct fscrypt_str *crypto_str);
void fscrypt_fname_free_buffer(struct fscrypt_str *crypto_str);
int fscrypt_fname_disk_to_usr(struct inode *inode,
			      u32 hash, u32 minor_hash,
			      const struct fscrypt_str *iname,
			      struct fscrypt_str *oname);
bool fscrypt_match_name(const struct fscrypt_name *fname,
			const u8 *de_name, u32 de_name_len);

/* bio.c */
void fscrypt_decrypt_bio_pages(struct fscrypt_ctx *ctx, struct bio *bio);
void fscrypt_pullback_bio_page(struct page **page, bool restore);
int fscrypt_zeroout_range(const struct inode *inode, pgoff_t lblk,
			  sector_t pblk, unsigned int len);

/* fscrypt context allocation */
struct fscrypt_ctx *fscrypt_get_ctx(const struct inode *inode, gfp_t gfp_flags);
void fscrypt_release_ctx(struct fscrypt_ctx *ctx);
struct page *fscrypt_alloc_bounce_page(struct fscrypt_ctx *ctx, gfp_t gfp_flags);
void fscrypt_restore_control_page(struct page *page);

#else  /* !CONFIG_FS_ENCRYPTION */

/* crypto.c */
static inline void fscrypt_enqueue_decrypt_work(struct work_struct *work)
{
}

static inline struct page *fscrypt_encrypt_page(const struct inode *inode,
						struct page *page,
						unsigned int len,
						unsigned int offs,
						u64 lblk_num,
						gfp_t gfp_flags)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline int fscrypt_decrypt_page(const struct inode *inode,
				       struct page *page,
				       unsigned int len,
				       unsigned int offs, u64 lblk_num)
{
	return -EOPNOTSUPP;
}

static inline void fscrypt_free_bounce_page(struct page *bounce_page)
{
}

/* policy.c */
static inline int fscrypt_ioctl_set_policy(struct file *filp,
					   const void __user *arg)
{
	return -EOPNOTSUPP;
}

static inline int fscrypt_ioctl_get_policy(struct file *filp, void __user *arg)
{
	return -EOPNOTSUPP;
}

static inline int fscrypt_ioctl_get_policy_ex(struct file *filp,
					      void __user *arg)
{
	return -EOPNOTSUPP;
}

static inline int fscrypt_ioctl_get_nonce(struct file *filp, void __user *arg)
{
	return -EOPNOTSUPP;
}

static inline int fscrypt_has_permitted_context(struct inode *parent,
						struct inode *child)
{
	return 0;
}

static inline int fscrypt_inherit_context(struct inode *parent,
					  struct inode *child,
					  void *fs_data, bool preload)
{
	return -EOPNOTSUPP;
}

/* keyring.c */
static inline void fscrypt_sb_free(struct super_block *sb)
{
}

static inline int fscrypt_ioctl_add_key(struct file *filp, void __user *arg)
{
	return -EOPNOTSUPP;
}

static inline int fscrypt_ioctl_remove_key(struct file *filp, void __user *arg)
{
	return -EOPNOTSUPP;
}

static inline int fscrypt_ioctl_remove_key_all_users(struct file *filp,
						     void __user *arg)
{
	return -EOPNOTSUPP;
}

static inline int fscrypt_ioctl_get_key_status(struct file *filp,
					       void __user *arg)
{
	return -EOPNOTSUPP;
}

/* keysetup.c */
static inline int fscrypt_get_encryption_info(struct inode *inode)
{
	return -EOPNOTSUPP;
}

static inline void fscrypt_put_encryption_info(struct inode *inode,
					       struct fscrypt_info *ci)
{
}

static inline int fscrypt_drop_inode(struct inode *inode)
{
	return 0;
}

/* fname.c */
static inline int fscrypt_setup_filename(struct inode *dir,
					 const struct qstr *iname,
					 int lookup, struct fscrypt_name *fname)
{
	memset(fname, 0, sizeof(*fname));
	fname->usr_fname = iname;
	fname->disk_name.name = (unsigned char *)iname->name;
	fname->disk_name.len = iname->len;
	return 0;
}

static inline void fscrypt_free_filename(struct fscrypt_name *fname)
{
}

static inline int fscrypt_fname_alloc_buffer(const struct inode *inode,
					     u32 max_encrypted_len,
					     struct fscrypt_str *crypto_str)
{
	return -EOPNOTSUPP;
}

static inline void fscrypt_fname_free_buffer(struct fscrypt_str *crypto_str)
{
}

static inline int fscrypt_fname_disk_to_usr(struct inode *inode,
					    u32 hash, u32 minor_hash,
					    const struct fscrypt_str *iname,
					    struct fscrypt_str *oname)
{
	return -EOPNOTSUPP;
}

static inline bool fscrypt_match_name(const struct fscrypt_name *fname,
				      const u8 *de_name, u32 de_name_len)
{
	if (de_name_len != fname->disk_name.len)
		return false;
	return !memcmp(de_name, fname->disk_name.name, fname->disk_name.len);
}

/* bio.c */
static inline void fscrypt_decrypt_bio_pages(struct fscrypt_ctx *ctx,
					     struct bio *bio)
{
}

static inline void fscrypt_pullback_bio_page(struct page **page, bool restore)
{
}

static inline int fscrypt_zeroout_range(const struct inode *inode, pgoff_t lblk,
					sector_t pblk, unsigned int len)
{
	return -EOPNOTSUPP;
}

static inline struct fscrypt_ctx *fscrypt_get_ctx(const struct inode *inode,
						  gfp_t gfp_flags)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline void fscrypt_release_ctx(struct fscrypt_ctx *ctx)
{
}

#endif	/* !CONFIG_FS_ENCRYPTION */

#endif /* _LINUX_FSCRYPT_H */

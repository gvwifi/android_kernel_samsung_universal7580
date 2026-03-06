/*
 * Encryption policy functions for per-file encryption support.
 *
 * Copyright (C) 2015, Google, Inc.
 * Copyright (C) 2015, Motorola Mobility.
 *
 * Originally written by Michael Halcrow, 2015.
 * Modified by Jaegeuk Kim, 2015.
 * Modified for v2 policy support (backported from 5.4).
 */

#include <linux/random.h>
#include <linux/string.h>
#include <linux/mount.h>
#include "fscrypt_private.h"

/**
 * fscrypt_policies_equal() - check whether two encryption policies are the same
 * @policy1: the first policy
 * @policy2: the second policy
 *
 * Return: %true if equal, else %false
 */
bool fscrypt_policies_equal(const union fscrypt_policy *policy1,
			    const union fscrypt_policy *policy2)
{
	if (policy1->version != policy2->version)
		return false;

	return !memcmp(policy1, policy2, fscrypt_policy_size(policy1));
}

static bool fscrypt_supported_v1_policy(const struct fscrypt_policy_v1 *policy,
					const struct inode *inode)
{
	if (!fscrypt_valid_enc_modes(policy->contents_encryption_mode,
				     policy->filenames_encryption_mode)) {
		pr_warn("fscrypt: inode %lu: unsupported encryption modes (contents %d, filenames %d)\n",
			inode->i_ino,
			policy->contents_encryption_mode,
			policy->filenames_encryption_mode);
		return false;
	}

	if (policy->flags & ~FS_POLICY_FLAGS_VALID) {
		pr_warn("fscrypt: inode %lu: unsupported encryption flags (0x%02x)\n",
			inode->i_ino, policy->flags);
		return false;
	}

	return true;
}

static bool fscrypt_supported_v2_policy(const struct fscrypt_policy_v2 *policy,
					const struct inode *inode)
{
	if (!fscrypt_valid_enc_modes(policy->contents_encryption_mode,
				     policy->filenames_encryption_mode)) {
		pr_warn("fscrypt: inode %lu: unsupported encryption modes (contents %d, filenames %d)\n",
			inode->i_ino,
			policy->contents_encryption_mode,
			policy->filenames_encryption_mode);
		return false;
	}

	if (policy->flags & ~FSCRYPT_POLICY_FLAGS_VALID) {
		pr_warn("fscrypt: inode %lu: unsupported encryption flags (0x%02x)\n",
			inode->i_ino, policy->flags);
		return false;
	}

	if (memchr_inv(policy->__reserved, 0, sizeof(policy->__reserved))) {
		pr_warn("fscrypt: inode %lu: reserved bits set in encryption policy\n",
			inode->i_ino);
		return false;
	}

	return true;
}

/**
 * fscrypt_supported_policy() - check whether an encryption policy is supported
 * @policy_u: the encryption policy
 * @inode: the inode on which the policy will be used
 *
 * Return: %true if supported, else %false
 */
bool fscrypt_supported_policy(const union fscrypt_policy *policy_u,
			      const struct inode *inode)
{
	switch (policy_u->version) {
	case FSCRYPT_POLICY_V1:
		return fscrypt_supported_v1_policy(&policy_u->v1, inode);
	case FSCRYPT_POLICY_V2:
		return fscrypt_supported_v2_policy(&policy_u->v2, inode);
	}
	return false;
}

/**
 * fscrypt_new_context_from_policy() - create a new fscrypt_context from policy
 * @ctx_u: output context
 * @policy_u: input policy
 *
 * Return: the size of the new context in bytes.
 */
static int fscrypt_new_context_from_policy(union fscrypt_context *ctx_u,
					   const union fscrypt_policy *policy_u)
{
	memset(ctx_u, 0, sizeof(*ctx_u));

	switch (policy_u->version) {
	case FSCRYPT_POLICY_V1: {
		const struct fscrypt_policy_v1 *policy = &policy_u->v1;
		struct fscrypt_context_v1 *ctx = &ctx_u->v1;

		ctx->format = FSCRYPT_CONTEXT_V1;
		ctx->contents_encryption_mode =
			policy->contents_encryption_mode;
		ctx->filenames_encryption_mode =
			policy->filenames_encryption_mode;
		ctx->flags = policy->flags;
		memcpy(ctx->master_key_descriptor,
		       policy->master_key_descriptor,
		       sizeof(ctx->master_key_descriptor));
		get_random_bytes(ctx->nonce, sizeof(ctx->nonce));
		return sizeof(*ctx);
	}
	case FSCRYPT_POLICY_V2: {
		const struct fscrypt_policy_v2 *policy = &policy_u->v2;
		struct fscrypt_context_v2 *ctx = &ctx_u->v2;

		ctx->version = FSCRYPT_CONTEXT_V2;
		ctx->contents_encryption_mode =
			policy->contents_encryption_mode;
		ctx->filenames_encryption_mode =
			policy->filenames_encryption_mode;
		ctx->flags = policy->flags;
		memcpy(ctx->master_key_identifier,
		       policy->master_key_identifier,
		       sizeof(ctx->master_key_identifier));
		get_random_bytes(ctx->nonce, sizeof(ctx->nonce));
		return sizeof(*ctx);
	}
	}
	BUG();
}

/**
 * fscrypt_policy_from_context() - convert an fscrypt_context to fscrypt_policy
 * @policy_u: output policy
 * @ctx_u: input context
 * @ctx_size: size of input context in bytes
 *
 * Return: 0 on success, or -EINVAL if invalid context
 */
int fscrypt_policy_from_context(union fscrypt_policy *policy_u,
				const union fscrypt_context *ctx_u,
				int ctx_size)
{
	memset(policy_u, 0, sizeof(*policy_u));

	if (!fscrypt_context_is_valid(ctx_u, ctx_size))
		return -EINVAL;

	switch (ctx_u->version) {
	case FSCRYPT_CONTEXT_V1: {
		const struct fscrypt_context_v1 *ctx = &ctx_u->v1;
		struct fscrypt_policy_v1 *policy = &policy_u->v1;

		policy->version = FSCRYPT_POLICY_V1;
		policy->contents_encryption_mode =
			ctx->contents_encryption_mode;
		policy->filenames_encryption_mode =
			ctx->filenames_encryption_mode;
		policy->flags = ctx->flags;
		memcpy(policy->master_key_descriptor,
		       ctx->master_key_descriptor,
		       sizeof(policy->master_key_descriptor));
		return 0;
	}
	case FSCRYPT_CONTEXT_V2: {
		const struct fscrypt_context_v2 *ctx = &ctx_u->v2;
		struct fscrypt_policy_v2 *policy = &policy_u->v2;

		policy->version = FSCRYPT_POLICY_V2;
		policy->contents_encryption_mode =
			ctx->contents_encryption_mode;
		policy->filenames_encryption_mode =
			ctx->filenames_encryption_mode;
		policy->flags = ctx->flags;
		memcpy(policy->__reserved, ctx->__reserved,
		       sizeof(policy->__reserved));
		memcpy(policy->master_key_identifier,
		       ctx->master_key_identifier,
		       sizeof(policy->master_key_identifier));
		return 0;
	}
	}
	return -EINVAL;
}

/* Retrieve an inode's encryption policy */
static int fscrypt_get_policy(struct inode *inode, union fscrypt_policy *policy)
{
	union fscrypt_context ctx;
	int ret;

	if (!inode->i_sb->s_cop->get_context)
		return -EOPNOTSUPP;

	ret = inode->i_sb->s_cop->get_context(inode, &ctx, sizeof(ctx));
	if (ret < 0)
		return (ret == -ERANGE) ? -EINVAL : ret;

	return fscrypt_policy_from_context(policy, &ctx, ret);
}

static int set_encryption_policy(struct inode *inode,
				 const union fscrypt_policy *policy)
{
	union fscrypt_context ctx;
	int ctxsize;
	int err;

	if (!fscrypt_supported_policy(policy, inode))
		return -EINVAL;

	switch (policy->version) {
	case FSCRYPT_POLICY_V1:
		break;
	case FSCRYPT_POLICY_V2:
		/*
		 * For v2 policies, verify the key has been added.
		 * This provides a way to verify the correct master key.
		 */
		err = fscrypt_verify_key_added(inode->i_sb,
					       policy->v2.master_key_identifier);
		if (err)
			return err;
		break;
	default:
		WARN_ON(1);
		return -EINVAL;
	}

	ctxsize = fscrypt_new_context_from_policy(&ctx, policy);

	return inode->i_sb->s_cop->set_context(inode, &ctx, ctxsize, NULL);
}

int fscrypt_ioctl_set_policy(struct file *filp, const void __user *arg)
{
	union fscrypt_policy policy;
	union fscrypt_policy existing_policy;
	struct inode *inode = file_inode(filp);
	u8 version;
	int size;
	int ret;

	/* First read just the version byte */
	if (get_user(policy.version, (const u8 __user *)arg))
		return -EFAULT;

	size = fscrypt_policy_size(&policy);
	if (size <= 0)
		return -EINVAL;

	/* Read the full policy */
	version = policy.version;
	if (copy_from_user(&policy, arg, size))
		return -EFAULT;
	policy.version = version;

	if (!inode_owner_or_capable(inode))
		return -EACCES;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	inode_lock(inode);

	ret = fscrypt_get_policy(inode, &existing_policy);
	if (ret == -ENODATA) {
		if (!S_ISDIR(inode->i_mode))
			ret = -ENOTDIR;
		else if (!inode->i_sb->s_cop->empty_dir(inode))
			ret = -ENOTEMPTY;
		else
			ret = set_encryption_policy(inode, &policy);
	} else if (ret == -EINVAL) {
		/* Corrupted or unsupported policy */
		ret = -EINVAL;
	} else if (ret == 0) {
		/* 
		 * Directory already has an encryption policy.
		 * If policies are equal, allow it (idempotent operation).
		 * If policies differ, check if we should allow override.
		 */
		if (fscrypt_policies_equal(&policy, &existing_policy)) {
			/* Same policy - allow idempotent set */
			ret = 0;
		} else {
			/*
			 * Different policy. For robustness after ungraceful shutdown,
			 * if the directory is empty, allow policy change.
			 * This handles the case where init_user0 fails on reboot
			 * because /data/data and /data/system_de/0 have stale policies.
			 */
			if (S_ISDIR(inode->i_mode) && 
			    inode->i_sb->s_cop->empty_dir &&
			    inode->i_sb->s_cop->empty_dir(inode)) {
				/* Empty directory - allow policy override for recovery */
				pr_warn("fscrypt: Overriding encryption policy on empty directory (ino=%lu) after potential unclean shutdown\n",
					inode->i_ino);
				ret = set_encryption_policy(inode, &policy);
			} else {
				/* The file already uses a different encryption policy. */
				ret = -EEXIST;
			}
		}
	}

	inode_unlock(inode);

	mnt_drop_write_file(filp);
	return ret;
}
EXPORT_SYMBOL(fscrypt_ioctl_set_policy);

/* Original ioctl version; can only get the original policy version */
int fscrypt_ioctl_get_policy(struct file *filp, void __user *arg)
{
	union fscrypt_policy policy;
	int err;

	err = fscrypt_get_policy(file_inode(filp), &policy);
	if (err)
		return err;

	if (policy.version != FSCRYPT_POLICY_V1)
		return -EINVAL;

	if (copy_to_user(arg, &policy, sizeof(policy.v1)))
		return -EFAULT;
	return 0;
}
EXPORT_SYMBOL(fscrypt_ioctl_get_policy);

/**
 * fscrypt_has_permitted_context() - is a file's encryption policy permitted
 *				     within its directory?
 * @parent: inode for parent directory
 * @child: inode for file being looked up, opened, or linked into @parent
 *
 * Return: 1 if permitted, 0 if forbidden.
 */
int fscrypt_has_permitted_context(struct inode *parent, struct inode *child)
{
	union fscrypt_policy parent_policy, child_policy;
	int err;

	/* No restrictions on file types which are never encrypted */
	if (!S_ISREG(child->i_mode) && !S_ISDIR(child->i_mode) &&
	    !S_ISLNK(child->i_mode))
		return 1;

	/* No restrictions if the parent directory is unencrypted */
	if (!parent->i_sb->s_cop->is_encrypted(parent))
		return 1;

	/* Encrypted directories must not contain unencrypted files */
	if (!child->i_sb->s_cop->is_encrypted(child))
		return 0;

	/*
	 * Both parent and child are encrypted, so verify they use the same
	 * encryption policy.
	 */
	err = fscrypt_get_policy(parent, &parent_policy);
	if (err)
		return 0;

	err = fscrypt_get_policy(child, &child_policy);
	if (err)
		return 0;

	return fscrypt_policies_equal(&parent_policy, &child_policy);
}
EXPORT_SYMBOL(fscrypt_has_permitted_context);

/**
 * fscrypt_inherit_context() - Sets a child context from its parent
 * @parent: Parent inode from which the context is inherited.
 * @child:  Child inode that inherits the context from @parent.
 * @fs_data:  private data given by FS.
 * @preload:  preload child i_crypt_info if true
 *
 * Return: 0 on success, -errno on failure
 */
int fscrypt_inherit_context(struct inode *parent, struct inode *child,
			    void *fs_data, bool preload)
{
	union fscrypt_context ctx;
	union fscrypt_policy policy;
	int ctxsize;
	int res;

	res = fscrypt_get_policy(parent, &policy);
	if (res < 0)
		return res;

	ctxsize = fscrypt_new_context_from_policy(&ctx, &policy);

	res = parent->i_sb->s_cop->set_context(child, &ctx, ctxsize, fs_data);
	if (res)
		return res;
	return preload ? fscrypt_get_encryption_info(child) : 0;
}
EXPORT_SYMBOL(fscrypt_inherit_context);

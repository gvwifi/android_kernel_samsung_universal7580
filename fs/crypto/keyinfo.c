/*
 * key management facility for FS encryption support.
 *
 * Copyright (C) 2015, Google, Inc.
 *
 * This contains encryption key functions.
 *
 * Written by Michael Halcrow, Ildar Muslukhov, and Uday Savagaonkar, 2015.
 */

#include <keys/user-type.h>
#include <linux/scatterlist.h>
#include <linux/ratelimit.h>
#include <crypto/aes.h>
#include <crypto/sha.h>
#include "fscrypt_private.h"

static struct crypto_shash *essiv_hash_tfm;

static void derive_crypt_complete(struct crypto_async_request *req, int rc)
{
	struct fscrypt_completion_result *ecr = req->data;

	if (rc == -EINPROGRESS)
		return;

	ecr->res = rc;
	complete(&ecr->completion);
}

/**
 * derive_key_aes() - Derive a key using AES-128-ECB
 * @deriving_key: Encryption key used for derivation.
 * @source_key:   Source key to which to apply derivation.
 * @derived_raw_key:  Derived raw key.
 *
 * Return: Zero on success; non-zero otherwise.
 */
static int derive_key_aes(u8 deriving_key[FS_AES_128_ECB_KEY_SIZE],
				const struct fscrypt_key *source_key,
				u8 derived_raw_key[FS_MAX_KEY_SIZE])
{
	int res = 0;
	struct ablkcipher_request *req = NULL;
	DECLARE_FS_COMPLETION_RESULT(ecr);
	struct scatterlist src_sg, dst_sg;
	struct crypto_ablkcipher *tfm = crypto_alloc_ablkcipher("ecb(aes)", 0, 0);

	if (IS_ERR(tfm)) {
		res = PTR_ERR(tfm);
		tfm = NULL;
		goto out;
	}
	crypto_ablkcipher_set_flags(tfm, CRYPTO_TFM_REQ_WEAK_KEY);
	req = ablkcipher_request_alloc(tfm, GFP_NOFS);
	if (!req) {
		res = -ENOMEM;
		goto out;
	}
	ablkcipher_request_set_callback(req,
			CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
			derive_crypt_complete, &ecr);
	res = crypto_ablkcipher_setkey(tfm, deriving_key,
					FS_AES_128_ECB_KEY_SIZE);
	if (res < 0)
		goto out;

	sg_init_one(&src_sg, source_key->raw, source_key->size);
	sg_init_one(&dst_sg, derived_raw_key, source_key->size);
	ablkcipher_request_set_crypt(req, &src_sg, &dst_sg, source_key->size,
				   NULL);
	res = crypto_ablkcipher_encrypt(req);
	if (res == -EINPROGRESS || res == -EBUSY) {
		wait_for_completion(&ecr.completion);
		res = ecr.res;
	}
out:
	ablkcipher_request_free(req);
	crypto_free_ablkcipher(tfm);
	return res;
}

static int validate_user_key(struct fscrypt_info *crypt_info,
			struct fscrypt_context_v1 *ctx, u8 *raw_key,
			const char *prefix, int min_keysize)
{
	char *description;
	struct key *keyring_key;
	struct fscrypt_key *master_key;
	const struct user_key_payload *ukp;
	int prefix_size = strlen(prefix);
	int full_key_len = prefix_size + (FS_KEY_DESCRIPTOR_SIZE * 2) + 1;
	int res;

	/* FIXME: 3.18 causes kernel panic.
	 description = kasprintf(GFP_NOFS, "%s%*phN", prefix,
				FS_KEY_DESCRIPTOR_SIZE,
				ctx->master_key_descriptor);
	 */
	description = kmalloc(full_key_len, GFP_NOFS);
	if (!description)
		return -ENOMEM;

	memcpy(description, prefix, prefix_size);
	sprintf(description + prefix_size,
			"%*phN", FS_KEY_DESCRIPTOR_SIZE,
			ctx->master_key_descriptor);
	description[full_key_len - 1] = '\0';

	keyring_key = request_key(&key_type_logon, description, NULL);
	kfree(description);
	if (IS_ERR(keyring_key))
		return PTR_ERR(keyring_key);
	down_read(&keyring_key->sem);

	if (keyring_key->type != &key_type_logon) {
		printk_once(KERN_WARNING
				"%s: key type must be logon\n", __func__);
		res = -ENOKEY;
		goto out;
	}
	ukp = user_key_payload(keyring_key);
	if (ukp->datalen != sizeof(struct fscrypt_key)) {
		res = -EINVAL;
		goto out;
	}
	master_key = (struct fscrypt_key *)ukp->data;
	BUILD_BUG_ON(FS_AES_128_ECB_KEY_SIZE != FS_KEY_DERIVATION_NONCE_SIZE);

	if (master_key->size < min_keysize || master_key->size > FS_MAX_KEY_SIZE
	    || master_key->size % AES_BLOCK_SIZE != 0) {
		printk_once(KERN_WARNING
				"%s: key size incorrect: %d\n",
				__func__, master_key->size);
		res = -ENOKEY;
		goto out;
	}
	res = derive_key_aes(ctx->nonce, master_key, raw_key);
out:
	up_read(&keyring_key->sem);
	key_put(keyring_key);
	return res;
}

static const struct {
	const char *cipher_str;
	int keysize;
} available_modes[] = {
	[FS_ENCRYPTION_MODE_AES_256_XTS] = { "xts(aes)",
					     FS_AES_256_XTS_KEY_SIZE },
	[FS_ENCRYPTION_MODE_AES_256_CTS] = { "cts(cbc(aes))",
					     FS_AES_256_CTS_KEY_SIZE },
	[FS_ENCRYPTION_MODE_AES_128_CBC] = { "cbc(aes)",
					     FS_AES_128_CBC_KEY_SIZE },
	[FS_ENCRYPTION_MODE_AES_128_CTS] = { "cts(cbc(aes))",
					     FS_AES_128_CTS_KEY_SIZE },
};

static int determine_cipher_type(struct fscrypt_info *ci, struct inode *inode,
				 const char **cipher_str_ret, int *keysize_ret)
{
	u32 mode;

	if (!fscrypt_valid_enc_modes(ci->ci_data_mode, ci->ci_filename_mode)) {
		pr_warn_ratelimited("fscrypt: inode %lu uses unsupported encryption modes (contents mode %d, filenames mode %d)\n",
				    inode->i_ino,
				    ci->ci_data_mode, ci->ci_filename_mode);
		return -EINVAL;
	}

	if (S_ISREG(inode->i_mode)) {
		mode = ci->ci_data_mode;
	} else if (S_ISDIR(inode->i_mode) || S_ISLNK(inode->i_mode)) {
		mode = ci->ci_filename_mode;
	} else {
		WARN_ONCE(1, "fscrypt: filesystem tried to load encryption info for inode %lu, which is not encryptable (file type %d)\n",
			  inode->i_ino, (inode->i_mode & S_IFMT));
		return -EINVAL;
	}

	*cipher_str_ret = available_modes[mode].cipher_str;
	*keysize_ret = available_modes[mode].keysize;
	return 0;
}

static void put_crypt_info(struct fscrypt_info *ci)
{
	if (!ci)
		return;

	crypto_free_ablkcipher(ci->ci_ctfm);
	crypto_free_cipher(ci->ci_essiv_tfm);
	kmem_cache_free(fscrypt_info_cachep, ci);
}

static int derive_essiv_salt(const u8 *key, int keysize, u8 *salt)
{
	struct crypto_shash *tfm = READ_ONCE(essiv_hash_tfm);

	/* init hash transform on demand */
	if (unlikely(!tfm)) {
		struct crypto_shash *prev_tfm;

		tfm = crypto_alloc_shash("sha256", 0, 0);
		if (IS_ERR(tfm)) {
			pr_warn_ratelimited("fscrypt: error allocating SHA-256 transform: %ld\n",
					    PTR_ERR(tfm));
			return PTR_ERR(tfm);
		}
		prev_tfm = cmpxchg(&essiv_hash_tfm, NULL, tfm);
		if (prev_tfm) {
			crypto_free_shash(tfm);
			tfm = prev_tfm;
		}
	}

	{
		SHASH_DESC_ON_STACK(desc, tfm);
		desc->tfm = tfm;
		desc->flags = 0;

		return crypto_shash_digest(desc, key, keysize, salt);
	}
}

static int init_essiv_generator(struct fscrypt_info *ci, const u8 *raw_key,
				int keysize)
{
	int err;
	struct crypto_cipher *essiv_tfm;
	u8 salt[SHA256_DIGEST_SIZE];

	essiv_tfm = crypto_alloc_cipher("aes", 0, 0);
	if (IS_ERR(essiv_tfm))
		return PTR_ERR(essiv_tfm);

	ci->ci_essiv_tfm = essiv_tfm;

	err = derive_essiv_salt(raw_key, keysize, salt);
	if (err)
		goto out;

	/*
	 * Using SHA256 to derive the salt/key will result in AES-256 being
	 * used for IV generation. File contents encryption will still use the
	 * configured keysize (AES-128) nevertheless.
	 */
	err = crypto_cipher_setkey(essiv_tfm, salt, sizeof(salt));
	if (err)
		goto out;

out:
	memzero_explicit(salt, sizeof(salt));
	return err;
}

void __exit fscrypt_essiv_cleanup(void)
{
	crypto_free_shash(essiv_hash_tfm);
}

/*
 * setup_v2_file_key - derive a per-file encryption key for a v2 fscrypt policy
 *
 * For v2 policies the per-file key is derived from the master key stored in
 * the filesystem keyring using HKDF-Expand:
 *   info = (HKDF_CONTEXT_PER_FILE_ENC_KEY || file_nonce)
 */
static int setup_v2_file_key(struct fscrypt_info *crypt_info,
			     const struct fscrypt_context_v2 *ctx,
			     struct inode *inode,
			     u8 *raw_key, int keysize)
{
	struct fscrypt_key_specifier mk_spec;
	struct key *key;
	struct fscrypt_master_key *mk;
	int res;

	mk_spec.type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
	memset(&mk_spec.u, 0, sizeof(mk_spec.u));
	memcpy(mk_spec.u.identifier, ctx->master_key_identifier,
	       FSCRYPT_KEY_IDENTIFIER_SIZE);

	key = fscrypt_find_master_key(inode->i_sb, &mk_spec);
	if (IS_ERR(key)) {
		pr_debug("fscrypt: v2 key not found (inode %lu): %ld\n",
			 inode->i_ino, PTR_ERR(key));
		return PTR_ERR(key);
	}

	mk = (struct fscrypt_master_key *)key->payload.data;
	down_read(&mk->mk_secret_sem);

	if (!is_master_key_secret_present(&mk->mk_secret)) {
		res = -ENOKEY;
		goto out_release;
	}

	if (!mk->mk_secret.hkdf.hmac_tfm) {
		/* Shouldn't happen for v2 keys - HKDF is set at add time */
		pr_warn_ratelimited(
			"fscrypt: v2 master key missing HKDF (inode %lu)\n",
			inode->i_ino);
		res = -EINVAL;
		goto out_release;
	}

	if (mk->mk_secret.size < (u32)keysize) {
		pr_warn_ratelimited(
			"fscrypt: v2 master key too short (%u < %d) for inode %lu\n",
			mk->mk_secret.size, keysize, inode->i_ino);
		res = -ENOKEY;
		goto out_release;
	}

	res = fscrypt_hkdf_expand(&mk->mk_secret.hkdf,
				  HKDF_CONTEXT_PER_FILE_ENC_KEY,
				  ctx->nonce,
				  FS_KEY_DERIVATION_NONCE_SIZE,
				  raw_key, keysize);

out_release:
	up_read(&mk->mk_secret_sem);
	key_put(key);
	return res;
}

int fscrypt_get_encryption_info(struct inode *inode)
{
	struct fscrypt_info *crypt_info;
	union fscrypt_context ctx;
	struct crypto_ablkcipher *ctfm;
	const char *cipher_str;
	int keysize;
	u8 *raw_key = NULL;
	int res;

	if (inode->i_crypt_info)
		return 0;

	res = fscrypt_initialize(inode->i_sb->s_cop->flags);
	if (res)
		return res;

	res = inode->i_sb->s_cop->get_context(inode, &ctx, sizeof(ctx));
	if (res < 0) {
		if (!fscrypt_dummy_context_enabled(inode) ||
		    inode->i_sb->s_cop->is_encrypted(inode))
			return res;
		/* Fake up a v1 context for an unencrypted directory */
		memset(&ctx, 0, sizeof(ctx));
		ctx.v1.format = FS_ENCRYPTION_CONTEXT_FORMAT_V1;
		ctx.v1.contents_encryption_mode =
			FS_ENCRYPTION_MODE_AES_256_XTS;
		ctx.v1.filenames_encryption_mode =
			FS_ENCRYPTION_MODE_AES_256_CTS;
		memset(ctx.v1.master_key_descriptor, 0x42,
		       FS_KEY_DESCRIPTOR_SIZE);
	} else if (!fscrypt_context_is_valid(&ctx, res)) {
		pr_debug("fscrypt: invalid context size %d for inode %lu\n",
			 res, inode->i_ino);
		return -EINVAL;
	}

	crypt_info = kmem_cache_alloc(fscrypt_info_cachep, GFP_NOFS);
	if (!crypt_info)
		return -ENOMEM;

	crypt_info->ci_ctfm = NULL;
	crypt_info->ci_essiv_tfm = NULL;
	crypt_info->ci_master_key_ptr = NULL;
	memset(crypt_info->ci_nonce, 0, sizeof(crypt_info->ci_nonce));
	memset(crypt_info->ci_master_key, 0, sizeof(crypt_info->ci_master_key));

	switch (ctx.version) {
	case FSCRYPT_CONTEXT_V1:
		crypt_info->ci_flags = ctx.v1.flags;
		crypt_info->ci_data_mode = ctx.v1.contents_encryption_mode;
		crypt_info->ci_filename_mode = ctx.v1.filenames_encryption_mode;
		memcpy(crypt_info->ci_master_key, ctx.v1.master_key_descriptor,
		       sizeof(crypt_info->ci_master_key));
		memcpy(crypt_info->ci_nonce, ctx.v1.nonce,
		       FS_KEY_DERIVATION_NONCE_SIZE);
		if (ctx.v1.flags & ~FS_POLICY_FLAGS_VALID) {
			res = -EINVAL;
			goto out;
		}
		break;
	case FSCRYPT_CONTEXT_V2:
		crypt_info->ci_flags = ctx.v2.flags;
		crypt_info->ci_data_mode = ctx.v2.contents_encryption_mode;
		crypt_info->ci_filename_mode = ctx.v2.filenames_encryption_mode;
		memcpy(crypt_info->ci_nonce, ctx.v2.nonce,
		       FS_KEY_DERIVATION_NONCE_SIZE);
		if (ctx.v2.flags & ~FS_POLICY_FLAGS_VALID) {
			res = -EINVAL;
			goto out;
		}
		break;
	default:
		res = -EINVAL;
		goto out;
	}

	res = determine_cipher_type(crypt_info, inode, &cipher_str, &keysize);
	if (res)
		goto out;

	/*
	 * This cannot be a stack buffer because it is passed to the scatterlist
	 * crypto API as part of key derivation.
	 */
	res = -ENOMEM;
	raw_key = kmalloc(FS_MAX_KEY_SIZE, GFP_NOFS);
	if (!raw_key)
		goto out;

	if (ctx.version == FSCRYPT_CONTEXT_V1) {
		/* v1: look up the key by descriptor in user/session keyrings */
		res = validate_user_key(crypt_info, &ctx.v1, raw_key,
					FS_KEY_DESC_PREFIX, keysize);
		if (res && inode->i_sb->s_cop->key_prefix) {
			int res2 = validate_user_key(
					crypt_info, &ctx.v1, raw_key,
					inode->i_sb->s_cop->key_prefix,
					keysize);
			if (res2) {
				if (res2 == -ENOKEY)
					res = -ENOKEY;
				goto out;
			}
		} else if (res) {
			goto out;
		}
	} else {
		/* v2: look up key by identifier in filesystem keyring + HKDF */
		res = setup_v2_file_key(crypt_info, &ctx.v2, inode,
					raw_key, keysize);
		if (res)
			goto out;
	}

	ctfm = crypto_alloc_ablkcipher(cipher_str, 0, 0);
	if (!ctfm || IS_ERR(ctfm)) {
		res = ctfm ? PTR_ERR(ctfm) : -ENOMEM;
		pr_debug("%s: error %d (inode %lu) allocating crypto tfm\n",
			 __func__, res, inode->i_ino);
		goto out;
	}
	crypt_info->ci_ctfm = ctfm;
	crypto_ablkcipher_clear_flags(ctfm, ~0);
	crypto_ablkcipher_set_flags(ctfm, CRYPTO_TFM_REQ_WEAK_KEY);
	/*
	 * if the provided key is longer than keysize, we use the first
	 * keysize bytes of the derived key only
	 */
	res = crypto_ablkcipher_setkey(ctfm, raw_key, keysize);
	if (res)
		goto out;

	if (S_ISREG(inode->i_mode) &&
	    crypt_info->ci_data_mode == FS_ENCRYPTION_MODE_AES_128_CBC) {
		res = init_essiv_generator(crypt_info, raw_key, keysize);
		if (res) {
			pr_debug("%s: error %d (inode %lu) allocating essiv tfm\n",
				 __func__, res, inode->i_ino);
			goto out;
		}
	}
	if (cmpxchg(&inode->i_crypt_info, NULL, crypt_info) == NULL)
		crypt_info = NULL;
out:
	if (res == -ENOKEY)
		res = 0;
	put_crypt_info(crypt_info);
	kzfree(raw_key);
	return res;
}
EXPORT_SYMBOL(fscrypt_get_encryption_info);

void fscrypt_put_encryption_info(struct inode *inode, struct fscrypt_info *ci)
{
	struct fscrypt_info *prev;

	if (ci == NULL)
		ci = ACCESS_ONCE(inode->i_crypt_info);
	if (ci == NULL)
		return;

	prev = cmpxchg(&inode->i_crypt_info, ci, NULL);
	if (prev != ci)
		return;

	put_crypt_info(ci);
}
EXPORT_SYMBOL(fscrypt_put_encryption_info);

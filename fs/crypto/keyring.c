/*
 * Filesystem-level keyring for fscrypt
 *
 * Copyright 2019 Google LLC
 * Backported from Linux 5.4 to 3.10 for Android 16 compatibility.
 */

/*
 * This file implements management of fscrypt master keys in the
 * filesystem-level keyring, including the ioctls:
 *
 * - FS_IOC_ADD_ENCRYPTION_KEY
 * - FS_IOC_REMOVE_ENCRYPTION_KEY
 * - FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS
 * - FS_IOC_GET_ENCRYPTION_KEY_STATUS
 */

#include <linux/key-type.h>
#include <linux/random.h>
#include <linux/seq_file.h>
#include <linux/sched.h>

#include "fscrypt_private.h"

static DEFINE_MUTEX(fscrypt_add_key_mutex);

static void wipe_master_key_secret(struct fscrypt_master_key_secret *secret)
{
	fscrypt_destroy_hkdf(&secret->hkdf);
	memset(secret, 0, sizeof(*secret));
}

static void move_master_key_secret(struct fscrypt_master_key_secret *dst,
				   struct fscrypt_master_key_secret *src)
{
	memcpy(dst, src, sizeof(*dst));
	memset(src, 0, sizeof(*src));
}

static void free_master_key(struct fscrypt_master_key *mk)
{
	size_t i;

	wipe_master_key_secret(&mk->mk_secret);

	for (i = 0; i <= __FSCRYPT_MODE_MAX; i++) {
		if (mk->mk_direct_tfms[i])
			crypto_free_ablkcipher(mk->mk_direct_tfms[i]);
		if (mk->mk_iv_ino_lblk_64_tfms[i])
			crypto_free_ablkcipher(mk->mk_iv_ino_lblk_64_tfms[i]);
	}

	key_put(mk->mk_users);
	kzfree(mk);
}

static inline bool valid_key_spec(const struct fscrypt_key_specifier *spec)
{
	if (spec->__reserved)
		return false;
	return master_key_spec_len(spec) != 0;
}

static int fscrypt_key_instantiate(struct key *key,
				   struct key_preparsed_payload *prep)
{
	key->payload.data = (void *)prep->data;
	return 0;
}

static void fscrypt_key_destroy(struct key *key)
{
	free_master_key(key->payload.data);
}

static void fscrypt_key_describe(const struct key *key, struct seq_file *m)
{
	seq_puts(m, key->description);

	if (key->payload.data) {
		const struct fscrypt_master_key *mk = key->payload.data;

		if (!is_master_key_secret_present(&mk->mk_secret))
			seq_puts(m, ": secret removed");
	}
}

/*
 * Type of key in ->s_master_keys.  Each key of this type represents a master
 * key which has been added to the filesystem.
 */
static struct key_type key_type_fscrypt = {
	.name			= "._fscrypt",
	.instantiate		= fscrypt_key_instantiate,
	.destroy		= fscrypt_key_destroy,
	.describe		= fscrypt_key_describe,
};

static int fscrypt_user_key_instantiate(struct key *key,
					struct key_preparsed_payload *prep)
{
	return key_payload_reserve(key, FSCRYPT_MAX_KEY_SIZE);
}

static void fscrypt_user_key_describe(const struct key *key, struct seq_file *m)
{
	seq_puts(m, key->description);
}

/*
 * Type of key in ->mk_users.  Each key of this type represents a particular
 * user who has added a particular master key.
 */
static struct key_type key_type_fscrypt_user = {
	.name			= ".fscrypt",
	.instantiate		= fscrypt_user_key_instantiate,
	.describe		= fscrypt_user_key_describe,
};

/* Search ->s_master_keys or ->mk_users */
static struct key *search_fscrypt_keyring(struct key *keyring,
					  struct key_type *type,
					  const char *description)
{
	key_ref_t keyref = make_key_ref(keyring, true);

	keyref = keyring_search(keyref, type, description);
	if (IS_ERR(keyref)) {
		if (PTR_ERR(keyref) == -EAGAIN ||
		    PTR_ERR(keyref) == -EKEYREVOKED)
			keyref = ERR_PTR(-ENOKEY);
		return ERR_CAST(keyref);
	}
	return key_ref_to_ptr(keyref);
}

#define FSCRYPT_FS_KEYRING_DESCRIPTION_SIZE	\
	(CONST_STRLEN("fscrypt-") + sizeof(((struct super_block *)0)->s_id))

#define FSCRYPT_MK_DESCRIPTION_SIZE	(2 * FSCRYPT_KEY_IDENTIFIER_SIZE + 1)

#define FSCRYPT_MK_USERS_DESCRIPTION_SIZE	\
	(CONST_STRLEN("fscrypt-") + 2 * FSCRYPT_KEY_IDENTIFIER_SIZE + \
	 CONST_STRLEN("-users") + 1)

#define FSCRYPT_MK_USER_DESCRIPTION_SIZE	\
	(2 * FSCRYPT_KEY_IDENTIFIER_SIZE + CONST_STRLEN(".uid.") + 10 + 1)

static void format_fs_keyring_description(
			char description[FSCRYPT_FS_KEYRING_DESCRIPTION_SIZE],
			const struct super_block *sb)
{
	sprintf(description, "fscrypt-%s", sb->s_id);
}

static void format_mk_description(
			char description[FSCRYPT_MK_DESCRIPTION_SIZE],
			const struct fscrypt_key_specifier *mk_spec)
{
	sprintf(description, "%*phN",
		master_key_spec_len(mk_spec), (u8 *)&mk_spec->u);
}

static void format_mk_users_keyring_description(
			char description[FSCRYPT_MK_USERS_DESCRIPTION_SIZE],
			const u8 mk_identifier[FSCRYPT_KEY_IDENTIFIER_SIZE])
{
	sprintf(description, "fscrypt-%*phN-users",
		FSCRYPT_KEY_IDENTIFIER_SIZE, mk_identifier);
}

static void format_mk_user_description(
			char description[FSCRYPT_MK_USER_DESCRIPTION_SIZE],
			const u8 mk_identifier[FSCRYPT_KEY_IDENTIFIER_SIZE])
{
	sprintf(description, "%*phN.uid.%u", FSCRYPT_KEY_IDENTIFIER_SIZE,
		mk_identifier, from_kuid(&init_user_ns, current_fsuid()));
}

/* Create ->s_master_keys if needed. */
static int allocate_filesystem_keyring(struct super_block *sb)
{
	char description[FSCRYPT_FS_KEYRING_DESCRIPTION_SIZE];
	struct key *keyring;

	if (sb->s_master_keys)
		return 0;

	format_fs_keyring_description(description, sb);
	keyring = keyring_alloc(description, GLOBAL_ROOT_UID, GLOBAL_ROOT_GID,
				current_cred(), KEY_POS_SEARCH |
				  KEY_USR_SEARCH | KEY_USR_READ | KEY_USR_VIEW,
				KEY_ALLOC_NOT_IN_QUOTA, NULL);
	if (IS_ERR(keyring))
		return PTR_ERR(keyring);

	smp_store_release(&sb->s_master_keys, keyring);
	return 0;
}

void fscrypt_sb_free(struct super_block *sb)
{
	key_put(sb->s_master_keys);
	sb->s_master_keys = NULL;
}
EXPORT_SYMBOL(fscrypt_sb_free);

/*
 * Find the specified master key in ->s_master_keys.
 * Returns ERR_PTR(-ENOKEY) if not found.
 */
struct key *fscrypt_find_master_key(struct super_block *sb,
				    const struct fscrypt_key_specifier *mk_spec)
{
	struct key *keyring;
	char description[FSCRYPT_MK_DESCRIPTION_SIZE];

	keyring = READ_ONCE(sb->s_master_keys);
	if (keyring == NULL)
		return ERR_PTR(-ENOKEY);

	format_mk_description(description, mk_spec);
	return search_fscrypt_keyring(keyring, &key_type_fscrypt, description);
}

static int allocate_master_key_users_keyring(struct fscrypt_master_key *mk)
{
	char description[FSCRYPT_MK_USERS_DESCRIPTION_SIZE];
	struct key *keyring;

	format_mk_users_keyring_description(description,
					    mk->mk_spec.u.identifier);
	keyring = keyring_alloc(description, GLOBAL_ROOT_UID, GLOBAL_ROOT_GID,
				current_cred(), KEY_POS_SEARCH |
				  KEY_USR_SEARCH | KEY_USR_READ | KEY_USR_VIEW,
				KEY_ALLOC_NOT_IN_QUOTA, NULL);
	if (IS_ERR(keyring))
		return PTR_ERR(keyring);

	mk->mk_users = keyring;
	return 0;
}

/*
 * Find the current user's "key" in the master key's ->mk_users.
 */
static struct key *find_master_key_user(struct fscrypt_master_key *mk)
{
	char description[FSCRYPT_MK_USER_DESCRIPTION_SIZE];

	format_mk_user_description(description, mk->mk_spec.u.identifier);
	return search_fscrypt_keyring(mk->mk_users, &key_type_fscrypt_user,
				      description);
}

/*
 * Give the current user a "key" in ->mk_users.
 */
static int add_master_key_user(struct fscrypt_master_key *mk)
{
	char description[FSCRYPT_MK_USER_DESCRIPTION_SIZE];
	struct key *mk_user;
	int err;

	format_mk_user_description(description, mk->mk_spec.u.identifier);
	mk_user = key_alloc(&key_type_fscrypt_user, description,
			    current_fsuid(), current_fsgid(), current_cred(),
			    KEY_POS_SEARCH | KEY_USR_VIEW, 0);
	if (IS_ERR(mk_user))
		return PTR_ERR(mk_user);

	err = key_instantiate_and_link(mk_user, NULL, 0, mk->mk_users, NULL);
	key_put(mk_user);
	return err;
}

/*
 * Remove the current user's "key" from ->mk_users.
 */
static int remove_master_key_user(struct fscrypt_master_key *mk)
{
	struct key *mk_user;
	int err;

	mk_user = find_master_key_user(mk);
	if (IS_ERR(mk_user))
		return PTR_ERR(mk_user);
	err = key_unlink(mk->mk_users, mk_user);
	key_put(mk_user);
	return err;
}

/*
 * Allocate a new fscrypt_master_key and link it into the filesystem keyring.
 */
static int add_new_master_key(struct fscrypt_master_key_secret *secret,
			      const struct fscrypt_key_specifier *mk_spec,
			      struct key *keyring)
{
	struct fscrypt_master_key *mk;
	char description[FSCRYPT_MK_DESCRIPTION_SIZE];
	struct key *key;
	int err;

	mk = kzalloc(sizeof(*mk), GFP_KERNEL);
	if (!mk)
		return -ENOMEM;

	mk->mk_spec = *mk_spec;

	move_master_key_secret(&mk->mk_secret, secret);
	init_rwsem(&mk->mk_secret_sem);

	atomic_set(&mk->mk_refcount, 1);
	INIT_LIST_HEAD(&mk->mk_decrypted_inodes);
	spin_lock_init(&mk->mk_decrypted_inodes_lock);

	if (mk_spec->type == FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER) {
		err = allocate_master_key_users_keyring(mk);
		if (err)
			goto out_free_mk;
		err = add_master_key_user(mk);
		if (err)
			goto out_free_mk;
	}

	format_mk_description(description, mk_spec);
	key = key_alloc(&key_type_fscrypt, description,
			GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, current_cred(),
			KEY_POS_SEARCH | KEY_USR_SEARCH | KEY_USR_VIEW,
			KEY_ALLOC_NOT_IN_QUOTA);
	if (IS_ERR(key)) {
		err = PTR_ERR(key);
		goto out_free_mk;
	}
	err = key_instantiate_and_link(key, mk, sizeof(*mk), keyring, NULL);
	key_put(key);
	if (err)
		goto out_free_mk;

	return 0;

out_free_mk:
	free_master_key(mk);
	return err;
}

#define KEY_DEAD	1

static int add_existing_master_key(struct fscrypt_master_key *mk,
				   struct fscrypt_master_key_secret *secret)
{
	struct key *mk_user;
	bool rekey;
	int err;

	if (mk->mk_users) {
		mk_user = find_master_key_user(mk);
		if (mk_user != ERR_PTR(-ENOKEY)) {
			if (IS_ERR(mk_user))
				return PTR_ERR(mk_user);
			key_put(mk_user);
			return 0;
		}
	}

	rekey = !is_master_key_secret_present(&mk->mk_secret);
	if (rekey && !atomic_inc_not_zero(&mk->mk_refcount))
		return KEY_DEAD;

	if (mk->mk_users) {
		err = add_master_key_user(mk);
		if (err) {
			if (rekey && atomic_dec_and_test(&mk->mk_refcount))
				return KEY_DEAD;
			return err;
		}
	}

	if (rekey) {
		down_write(&mk->mk_secret_sem);
		move_master_key_secret(&mk->mk_secret, secret);
		up_write(&mk->mk_secret_sem);
	}
	return 0;
}

static int do_add_master_key(struct super_block *sb,
			     struct fscrypt_master_key_secret *secret,
			     const struct fscrypt_key_specifier *mk_spec)
{
	struct key *key;
	int err;

	mutex_lock(&fscrypt_add_key_mutex);
retry:
	key = fscrypt_find_master_key(sb, mk_spec);
	if (IS_ERR(key)) {
		err = PTR_ERR(key);
		if (err != -ENOKEY)
			goto out_unlock;
		err = allocate_filesystem_keyring(sb);
		if (err)
			goto out_unlock;
		err = add_new_master_key(secret, mk_spec, sb->s_master_keys);
	} else {
		down_write(&key->sem);
		err = add_existing_master_key(key->payload.data, secret);
		up_write(&key->sem);
		if (err == KEY_DEAD) {
			key_invalidate(key);
			key_put(key);
			goto retry;
		}
		key_put(key);
	}
out_unlock:
	mutex_unlock(&fscrypt_add_key_mutex);
	return err;
}

static int add_master_key(struct super_block *sb,
			  struct fscrypt_master_key_secret *secret,
			  struct fscrypt_key_specifier *key_spec)
{
	int err;

	if (key_spec->type == FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER) {
		err = fscrypt_init_hkdf(&secret->hkdf, secret->raw,
					secret->size);
		if (err)
			return err;

		/* Calculate the key identifier */
		err = fscrypt_hkdf_expand(&secret->hkdf,
					  HKDF_CONTEXT_KEY_IDENTIFIER, NULL, 0,
					  key_spec->u.identifier,
					  FSCRYPT_KEY_IDENTIFIER_SIZE);
		if (err)
			return err;
	}
	return do_add_master_key(sb, secret, key_spec);
}

/*
 * Add a master encryption key to the filesystem.
 */
int fscrypt_ioctl_add_key(struct file *filp, void __user *_uarg)
{
	struct super_block *sb = file_inode(filp)->i_sb;
	struct fscrypt_add_key_arg __user *uarg = _uarg;
	struct fscrypt_add_key_arg arg;
	struct fscrypt_master_key_secret secret;
	int err;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;

	if (!valid_key_spec(&arg.key_spec))
		return -EINVAL;

	if (memchr_inv(arg.__reserved, 0, sizeof(arg.__reserved)))
		return -EINVAL;

	/*
	 * Only root can add keys that are identified by an arbitrary descriptor
	 * rather than by a cryptographic hash.
	 */
	if (arg.key_spec.type == FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR &&
	    !capable(CAP_SYS_ADMIN))
		return -EACCES;

	memset(&secret, 0, sizeof(secret));

	if (arg.__flags)
		return -EINVAL;

	if (arg.key_id) {
		/* key_id not supported in this backport */
		return -EINVAL;
	} else {
		if (arg.raw_size < FSCRYPT_MIN_KEY_SIZE ||
		    arg.raw_size > FSCRYPT_MAX_KEY_SIZE)
			return -EINVAL;
		secret.size = arg.raw_size;
		err = -EFAULT;
		if (copy_from_user(secret.raw, uarg->raw, secret.size))
			goto out_wipe_secret;
	}

	err = add_master_key(sb, &secret, &arg.key_spec);
	if (err)
		goto out_wipe_secret;

	/* Return the key identifier to userspace, if applicable */
	err = -EFAULT;
	if (arg.key_spec.type == FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER &&
	    copy_to_user(uarg->key_spec.u.identifier, arg.key_spec.u.identifier,
			 FSCRYPT_KEY_IDENTIFIER_SIZE))
		goto out_wipe_secret;
	err = 0;
out_wipe_secret:
	wipe_master_key_secret(&secret);
	return err;
}
EXPORT_SYMBOL_GPL(fscrypt_ioctl_add_key);

/*
 * Verify that the current user has added a master key.
 */
int fscrypt_verify_key_added(struct super_block *sb,
			     const u8 identifier[FSCRYPT_KEY_IDENTIFIER_SIZE])
{
	struct fscrypt_key_specifier mk_spec;
	struct key *key, *mk_user;
	struct fscrypt_master_key *mk;
	int err;

	mk_spec.type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
	memcpy(mk_spec.u.identifier, identifier, FSCRYPT_KEY_IDENTIFIER_SIZE);

	key = fscrypt_find_master_key(sb, &mk_spec);
	if (IS_ERR(key)) {
		err = PTR_ERR(key);
		goto out;
	}
	mk = key->payload.data;
	mk_user = find_master_key_user(mk);
	if (IS_ERR(mk_user)) {
		err = PTR_ERR(mk_user);
	} else {
		key_put(mk_user);
		err = 0;
	}
	key_put(key);
out:
	if (err == -ENOKEY && capable(CAP_FOWNER))
		err = 0;
	return err;
}

static int try_to_lock_encrypted_files(struct super_block *sb,
				       struct fscrypt_master_key *mk)
{
	struct list_head *pos;
	size_t busy_count = 0;

	spin_lock(&mk->mk_decrypted_inodes_lock);
	list_for_each(pos, &mk->mk_decrypted_inodes)
		busy_count++;
	spin_unlock(&mk->mk_decrypted_inodes_lock);

	if (busy_count == 0)
		return 0;

	fscrypt_warn(NULL,
		     "%s: %zu inode(s) still busy after removing key with %s",
		     sb->s_id, busy_count, master_key_spec_type(&mk->mk_spec));
	return -EBUSY;
}

/*
 * Try to remove an fscrypt master encryption key.
 */
static int do_remove_key(struct file *filp, void __user *_uarg, bool all_users)
{
	struct super_block *sb = file_inode(filp)->i_sb;
	struct fscrypt_remove_key_arg __user *uarg = _uarg;
	struct fscrypt_remove_key_arg arg;
	struct key *key;
	struct fscrypt_master_key *mk;
	u32 status_flags = 0;
	int err;
	bool dead;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;

	if (!valid_key_spec(&arg.key_spec))
		return -EINVAL;

	if (memchr_inv(arg.__reserved, 0, sizeof(arg.__reserved)))
		return -EINVAL;

	if (arg.key_spec.type == FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR &&
	    !capable(CAP_SYS_ADMIN))
		return -EACCES;

	key = fscrypt_find_master_key(sb, &arg.key_spec);
	if (IS_ERR(key))
		return PTR_ERR(key);
	mk = key->payload.data;

	down_write(&key->sem);

	if (mk->mk_users) {
		if (all_users)
			err = keyring_clear(mk->mk_users);
		else
			err = remove_master_key_user(mk);
		if (err) {
			up_write(&key->sem);
			goto out_put_key;
		}
	}

	dead = false;
	if (is_master_key_secret_present(&mk->mk_secret)) {
		down_write(&mk->mk_secret_sem);
		wipe_master_key_secret(&mk->mk_secret);
		dead = atomic_dec_and_test(&mk->mk_refcount);
		up_write(&mk->mk_secret_sem);
	}
	up_write(&key->sem);
	if (dead) {
		key_invalidate(key);
		err = 0;
	} else {
		err = try_to_lock_encrypted_files(sb, mk);
		if (err == -EBUSY) {
			status_flags |=
				FSCRYPT_KEY_REMOVAL_STATUS_FLAG_FILES_BUSY;
			err = 0;
		}
	}
out_put_key:
	key_put(key);
	if (err == 0)
		err = put_user(status_flags, &uarg->removal_status_flags);
	return err;
}

int fscrypt_ioctl_remove_key(struct file *filp, void __user *uarg)
{
	return do_remove_key(filp, uarg, false);
}
EXPORT_SYMBOL_GPL(fscrypt_ioctl_remove_key);

int fscrypt_ioctl_remove_key_all_users(struct file *filp, void __user *uarg)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;
	return do_remove_key(filp, uarg, true);
}
EXPORT_SYMBOL_GPL(fscrypt_ioctl_remove_key_all_users);

/*
 * Retrieve the status of an fscrypt master encryption key.
 */
int fscrypt_ioctl_get_key_status(struct file *filp, void __user *uarg)
{
	struct super_block *sb = file_inode(filp)->i_sb;
	struct fscrypt_get_key_status_arg arg;
	struct key *key;
	struct fscrypt_master_key *mk;
	int err;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;

	if (!valid_key_spec(&arg.key_spec))
		return -EINVAL;

	if (memchr_inv(arg.__reserved, 0, sizeof(arg.__reserved)))
		return -EINVAL;

	arg.status_flags = 0;
	arg.user_count = 0;
	memset(arg.__out_reserved, 0, sizeof(arg.__out_reserved));

	key = fscrypt_find_master_key(sb, &arg.key_spec);
	if (IS_ERR(key)) {
		if (key != ERR_PTR(-ENOKEY))
			return PTR_ERR(key);
		arg.status = FSCRYPT_KEY_STATUS_ABSENT;
		err = 0;
		goto out;
	}
	mk = key->payload.data;
	down_read(&key->sem);

	if (!is_master_key_secret_present(&mk->mk_secret)) {
		arg.status = FSCRYPT_KEY_STATUS_INCOMPLETELY_REMOVED;
		err = 0;
		goto out_release_key;
	}

	arg.status = FSCRYPT_KEY_STATUS_PRESENT;
	if (mk->mk_users) {
		struct key *mk_user;

		mk_user = find_master_key_user(mk);
		if (!IS_ERR(mk_user)) {
			arg.status_flags |=
				FSCRYPT_KEY_STATUS_FLAG_ADDED_BY_SELF;
			key_put(mk_user);
		} else if (mk_user != ERR_PTR(-ENOKEY)) {
			err = PTR_ERR(mk_user);
			goto out_release_key;
		}
	}
	err = 0;
out_release_key:
	up_read(&key->sem);
	key_put(key);
out:
	if (!err && copy_to_user(uarg, &arg, sizeof(arg)))
		err = -EFAULT;
	return err;
}
EXPORT_SYMBOL_GPL(fscrypt_ioctl_get_key_status);

int __init fscrypt_init_keyring(void)
{
	int err;

	err = register_key_type(&key_type_fscrypt);
	if (err)
		return err;

	err = register_key_type(&key_type_fscrypt_user);
	if (err)
		goto err_unregister_fscrypt;

	return 0;

err_unregister_fscrypt:
	unregister_key_type(&key_type_fscrypt);
	return err;
}

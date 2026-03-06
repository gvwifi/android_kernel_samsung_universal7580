#ifndef _F_FS_COMPAT_H_
#define _F_FS_COMPAT_H_

#include <linux/uio.h>
#include <linux/aio.h>
#include <linux/fs.h>
#include <linux/usb/ch9.h>

/* iov_iter compatibility for 3.10 */
#ifndef copy_to_iter
static inline size_t copy_to_iter(const void *addr, size_t bytes, struct iov_iter *i)
{
	size_t copied = 0;

	if (i->count < bytes)
		bytes = i->count;

	while (bytes > 0 && i->nr_segs > 0) {
		const struct iovec *iov = i->iov;
		size_t base = (size_t)iov->iov_base + i->iov_offset;
		size_t len = iov->iov_len - i->iov_offset;
		size_t chunk = min(bytes, len);

		if (copy_to_user((void __user *)base, addr, chunk))
			break;

		addr += chunk;
		bytes -= chunk;
		copied += chunk;
		i->count -= chunk;
		i->iov_offset += chunk;

		if (i->iov_offset == iov->iov_len) {
			i->iov++;
			i->nr_segs--;
			i->iov_offset = 0;
		}
	}
	return copied;
}
#endif

#ifndef copy_from_iter_full
static inline size_t copy_from_iter_full(void *addr, size_t bytes, struct iov_iter *i)
{
	size_t copied = 0;
	size_t wanted = bytes;

	char *kaddr = (char *)addr;

	if (i->count < bytes)
		return 0;

	while (bytes > 0 && i->nr_segs > 0) {
		const struct iovec *iov = i->iov;
		size_t base = (size_t)iov->iov_base + i->iov_offset;
		size_t len = iov->iov_len - i->iov_offset;
		size_t chunk = min(bytes, len);

		if (copy_from_user(kaddr, (const void __user *)base, chunk))
			return 0; /* copy_from_iter_full expects full success */

		kaddr += chunk;
		bytes -= chunk;
		copied += chunk;
		i->count -= chunk;
		i->iov_offset += chunk;

		if (i->iov_offset == iov->iov_len) {
			i->iov++;
			i->nr_segs--;
			i->iov_offset = 0;
		}
	}
	
	if (copied < wanted)
		return 0;

	return copied;
}
#endif

#ifndef dup_iter
static inline void *dup_iter(struct iov_iter *new, struct iov_iter *old, gfp_t flags)
{
	void *copy;
	*new = *old;
	if (new->iov) {
		copy = kmemdup(new->iov,
			       new->nr_segs * sizeof(struct iovec),
			       flags);
		new->iov = (const struct iovec *)copy;
		return copy;
	}
	return NULL;
}
#endif

/* 
 * 4.14 f_fs.c expects this struct to be available, but 3.10 UAPI header 
 * hides it under !__KERNEL__. explicit definition needed.
 */
struct usb_endpoint_descriptor_no_audio {
	__u8  bLength;
	__u8  bDescriptorType;

	__u8  bEndpointAddress;
	__u8  bmAttributes;
	__le16 wMaxPacketSize;
	__u8  bInterval;
} __attribute__((packed));


/* kiocb compatibility */
#ifndef IOCB_EVENTFD
#define IOCB_EVENTFD 1
#endif

/* struct kiocb in 3.10 doesn't have ki_flags or ki_complete */
#define ki_flags private /* Hack: force checking a pointer to be non-null if used as flags */ 
/* Use aio_complete for ki_complete */
#define ki_complete(iocb, res, res2) aio_complete(iocb, res, res2)

#ifndef kiocb_set_cancel_fn
/* 3.10 has kiocb_set_cancel_fn but with different signature, handled in f_fs.c wrapper */
#endif

#endif /* _F_FS_COMPAT_H_ */

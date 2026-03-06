#ifndef _NET_BUSY_POLL_H
#define _NET_BUSY_POLL_H

#include <linux/netdevice.h>
#include <net/ip.h>

static inline bool sk_busy_loop(struct sock *sk, int nonblock)
{
	return false;
}

#endif

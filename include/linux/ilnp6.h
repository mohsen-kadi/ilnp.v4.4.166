//#ifndef _ILNPV6_H
//#define _ILNPV6_H

#include <uapi/linux/ipv6.h>


struct ilnpv6_params {
								__s32 disable_ilnpv6;
								__s32 autoconf;
};
extern struct ilnpv6_params ilnpv6_defaults;
#include <linux/icmpv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <net/inet_sock.h>


static inline const struct in6_addr *inet6_ilnpv6_rcv_saddr(const struct sock *sk)
{
	if (sk->sk_family == AF_ILNP6)
		return &sk->sk_v6_rcv_saddr;
	return NULL;
}

//#endif /* _ILNPV6_H */

#ifndef _UDP6_IMPL_H
#define _UDP6_IMPL_H
#include <net/udp.h>
#include <net/udplite.h>
#include <net/protocol.h>
#include <net/addrconf.h>
#include <net/inet_common.h>
#include <net/transp_v6.h>



// here put your stuff



int udp_ilnp6_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);

#endif	/* _UDP6_IMPL_H */

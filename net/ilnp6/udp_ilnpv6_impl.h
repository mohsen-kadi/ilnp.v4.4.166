#ifndef _UDP6_IMPL_H
#define _UDP6_IMPL_H
#include <net/udp.h>
#include <net/udplite.h>
#include <net/protocol.h>
#include <net/addrconf.h>
#include <net/inet_common.h>
#include <net/transp_v6.h>



// here put your stuff



int udp_ilnpv6_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
int udp_ilnpv6_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int noblock,
		  int flags, int *addr_len);
void udp_ilnpv6_destroy_sock(struct sock *sk);
int udp_ilnpv6_get_port(struct sock *sk, unsigned short snum);
int udp_ilnpv6_setsockopt(struct sock *sk, int level, int optname,
		     char __user *optval, unsigned int optlen);
int udp_ilnpv6_getsockopt(struct sock *sk, int level, int optname,
         	char __user *optval, int __user *optlen);

#ifdef CONFIG_COMPAT
int compat_udp_ilnpv6_setsockopt(struct sock *sk, int level, int optname,
          char __user *optval, unsigned int optlen);
int compat_udp_ilnpv6_getsockopt(struct sock *sk, int level, int optname,
          char __user *optval, int __user *optlen);
#endif


void udp_ilnpv6_clear_sk(struct sock *sk, int size);
#endif	/* _UDP6_IMPL_H */

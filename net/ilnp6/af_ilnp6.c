/*
 *	PF_ILNP6 socket protocol family
 *	Linux ILNP6 implementation
 *
 *	Authors:
 *
 *	Adapted from linux/net/ipv6/af_inet6.c
 *
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#define pr_fmt(fmt) "ILNPv6: " fmt

#include <linux/module.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/fcntl.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/slab.h>

#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/icmpv6.h>
#include <linux/netfilter_ipv6.h>

#include <net/ip.h>
#include <net/ilnp6.h>
#include <net/udp.h>
#include <net/udplite.h>
#include <net/tcp.h>
#include <net/ping.h>
#include <net/protocol.h>
#include <net/inet_common.h>
#include <net/route.h>
#include <net/transp_v6.h>
#include <net/ip6_route.h>
#include <net/addrconf.h>
#include <net/ndisc.h>
#ifdef CONFIG_IPV6_TUNNEL
#include <net/ip6_tunnel.h>
#endif

#include <asm/uaccess.h>
#include <linux/mroute6.h>

MODULE_AUTHOR("HIAST");
MODULE_DESCRIPTION("ILNPv6 protocol stack for Linux");
MODULE_LICENSE("GPL");



//  proto_ops struct for UDP over ILNP
// from ~/net/ipv6/af_inet6.c#L540
// review all functions pointers
const struct proto_ops ilnp6_dgram_ops = {
        .family      = PF_ILNP6,/* here the new family*/
        .owner       = THIS_MODULE,
        .release     = inet6_release,/* quick scan, no changes*/
        .bind      = inet6_bind,/* need modification for checing the family, new function*/
        .connect     = inet_dgram_connect,/* there is a check if (addr_len < sizeof(uaddr->sa_family)) return -EINVAL;		*/
        .socketpair    = sock_no_socketpair,/* a do nothing, ok	*/
        .accept      = sock_no_accept,/* a do nothing, ok	*/
        .getname     = inet6_getname,   /* review, new function*/
        .poll      = udp_poll,/* ok		*/
        .ioctl       = inet6_ioctl,/* postpone  */
        .listen      = sock_no_listen,/* ok		*/
        .shutdown    = inet_shutdown,/* ok		*/
        .setsockopt    = sock_common_setsockopt,/* ok, calls function from  sk->sk_prot->setsockopt which defined in related struct proto*/
        .getsockopt    = sock_common_getsockopt,/* ok, calls function from sk->sk_prot->getsockopt	which defined in related struct proto*/
        .sendmsg     = inet_sendmsg,/* ok, calls function from sk->sk_prot->sendmsg	which defined in related struct proto*/
        .recvmsg     = inet_recvmsg,/* ok, calls sk->sk_prot->recvmsg which defined in related struct proto*/
        .mmap      = sock_no_mmap,/* ok, return error*/
        .sendpage    = sock_no_sendpage,/*wtf, postpone*/
#ifdef CONFIG_COMPAT
        .compat_setsockopt = compat_sock_common_setsockopt, /*ok, calls function from sk->sk_prot->compat_setsockopt which defined in related struct proto*/
        .compat_getsockopt = compat_sock_common_getsockopt, /*ok, calls function from sk->sk_prot->compat_getsockopt which defined in related struct proto*/
#endif
};
/*review version for ilnp*/





/* bind for INET6 API */
int ilnp6_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)uaddr;
        struct sock *sk = sock->sk;
        struct inet_sock *inet = inet_sk(sk);
        struct ipv6_pinfo *np = inet6_sk(sk);
        struct net *net = sock_net(sk);
        __be32 v4addr = 0;
        unsigned short snum;
        int addr_type = 0;
        int err = 0;

        /* If the socket has its own bind function then use it.
           in our case, tcpv6_prot & udpv6_prot  (struct proto)
           do not have..
         */
        if (sk->sk_prot->bind)
                return sk->sk_prot->bind(sk, uaddr, addr_len);
        /*
           Some sanity check on the socket
           address passed as an argument to the function
         */
        if (addr_len < SIN6_LEN_RFC2133)
                return -EINVAL;
        /*
           NOTE: HERE a check for family AF_INET6 ****
         */
        if (addr->sin6_family != AF_ILNP6)
                return -EAFNOSUPPORT;

        /*
           Check the IP address type in the socket address,
           in the case where sysctl_ip_nonlocal_bind is not set,
           we can allow the socket to bind to only those IP addresses
           that fall in the following categories:
            INADDR_ANY = address to accept any incoming message
            RTN_LOCAL = accept locally
            RTN_MULTICAST = multicast route.
            RTN_BROADCAST = accept locally as broadcast and send as broadcast.
         */
        addr_type = ipv6_addr_type(&addr->sin6_addr);
        if ((addr_type & IPV6_ADDR_MULTICAST) && sock->type == SOCK_STREAM)
                return -EINVAL;
        // check port, PROT_SOCK #define PROT_SOCK	1024
        snum = ntohs(addr->sin6_port);
        if (snum && snum < PROT_SOCK && !ns_capable(net->user_ns, CAP_NET_BIND_SERVICE))
                return -EACCES;

        lock_sock(sk);

        /* Check these errors (active socket, double bind). */
        /* Check if we are binding the same socket once again*/
        if (sk->sk_state != TCP_CLOSE || inet->inet_num) {
                err = -EINVAL;
                goto out;
        }

        /* Check if the address belongs to the host. */
        /* for: IPV6_ADDR_MAPPED, IPV6_ADDR_ANY*/
        if (addr_type == IPV6_ADDR_MAPPED) {
                int chk_addr_ret;

                /* Binding to v4-mapped address on a v6-only socket
                 * makes no sense
                 */
                if (sk->sk_ipv6only) {
                        err = -EINVAL;
                        goto out;
                }

                /* Reproduce AF_INET checks to make the bindings consistent */
                v4addr = addr->sin6_addr.s6_addr32[3];
                chk_addr_ret = inet_addr_type(net, v4addr);
                if (!net->ipv4.sysctl_ip_nonlocal_bind &&
                    !(inet->freebind || inet->transparent) &&
                    v4addr != htonl(INADDR_ANY) &&
                    chk_addr_ret != RTN_LOCAL &&
                    chk_addr_ret != RTN_MULTICAST &&
                    chk_addr_ret != RTN_BROADCAST) {
                        err = -EADDRNOTAVAIL;
                        goto out;
                }
        } else {
                if (addr_type != IPV6_ADDR_ANY) {
                        struct net_device *dev = NULL;

                        rcu_read_lock();
                        if (__ipv6_addr_needs_scope_id(addr_type)) {
                                if (addr_len >= sizeof(struct sockaddr_in6) &&
                                    addr->sin6_scope_id) {
                                        /* Override any existing binding, if another one
                                         * is supplied by user.
                                         */
                                        sk->sk_bound_dev_if = addr->sin6_scope_id;
                                }

                                /* Binding to link-local address requires an interface */
                                if (!sk->sk_bound_dev_if) {
                                        err = -EINVAL;
                                        goto out_unlock;
                                }
                                dev = dev_get_by_index_rcu(net, sk->sk_bound_dev_if);
                                if (!dev) {
                                        err = -ENODEV;
                                        goto out_unlock;
                                }
                        }

                        /* ipv4 addr of the socket is invalid.  Only the
                         * unspecified and mapped address have a v4 equivalent.
                         */
                        v4addr = LOOPBACK4_IPV6;
                        if (!(addr_type & IPV6_ADDR_MULTICAST)) {
                                if (!net->ipv6.sysctl.ip_nonlocal_bind &&
                                    !(inet->freebind || inet->transparent) &&
                                    !ipv6_chk_addr(net, &addr->sin6_addr,
                                                   dev, 0)) {
                                        err = -EADDRNOTAVAIL;
                                        goto out_unlock;
                                }
                        }
                        rcu_read_unlock();
                }
        }

        inet->inet_rcv_saddr = v4addr;
        inet->inet_saddr = v4addr;

        sk->sk_v6_rcv_saddr = addr->sin6_addr;

        if (!(addr_type & IPV6_ADDR_MULTICAST))
                np->saddr = addr->sin6_addr;

        /* Make sure we are allowed to bind here. */
        /*
           like address already being used by another socket.
           Call get_port() specific to the protocol sk -> sk_prot -> get_port()
         */
        if ((snum || !inet->bind_address_no_port) &&
            sk->sk_prot->get_port(sk, snum)) {
                inet_reset_saddr(sk);
                err = -EADDRINUSE;
                goto out;
        }

        if (addr_type != IPV6_ADDR_ANY) {
                sk->sk_userlocks |= SOCK_BINDADDR_LOCK;
                if (addr_type != IPV6_ADDR_MAPPED)
                        sk->sk_ipv6only = 1;
        }
        if (snum)
                sk->sk_userlocks |= SOCK_BINDPORT_LOCK;
        inet->inet_sport = htons(inet->inet_num);
        inet->inet_dport = 0;
        inet->inet_daddr = 0;
out:
        release_sock(sk);
        return err;
out_unlock:
        rcu_read_unlock();
        goto out;
}
EXPORT_SYMBOL(ilnp6_bind);

int ilnp6_getname(struct socket *sock, struct sockaddr *uaddr,
                  int *uaddr_len, int peer)
{
        struct sockaddr_in6 *sin = (struct sockaddr_in6 *)uaddr;
        struct sock *sk = sock->sk;
        struct inet_sock *inet = inet_sk(sk);
        struct ipv6_pinfo *np = inet6_sk(sk);
        /* NOTE: set the new family*/
        sin->sin6_family = AF_ILNP6;
        sin->sin6_flowinfo = 0;
        sin->sin6_scope_id = 0;
        if (peer) {
                if (!inet->inet_dport)
                        return -ENOTCONN;
                if (((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_SYN_SENT)) &&
                    peer == 1)
                        return -ENOTCONN;
                sin->sin6_port = inet->inet_dport;
                sin->sin6_addr = sk->sk_v6_daddr;
                if (np->sndflow)
                        sin->sin6_flowinfo = np->flow_label;
        } else {
                if (ipv6_addr_any(&sk->sk_v6_rcv_saddr))
                        sin->sin6_addr = np->saddr;
                else
                        sin->sin6_addr = sk->sk_v6_rcv_saddr;

                sin->sin6_port = inet->inet_sport;
        }
        sin->sin6_scope_id = ipv6_iface_scope_id(&sin->sin6_addr,
                                                 sk->sk_bound_dev_if);
        *uaddr_len = sizeof(*sin);
        return 0;
}

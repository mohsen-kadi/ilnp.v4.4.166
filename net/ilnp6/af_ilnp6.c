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

/* The ilnpsw6 table contains everything that ilnp6_create needs to
 * build a new socket.
 */
static struct list_head ilnpsw6[SOCK_MAX];
static DEFINE_SPINLOCK(ilnpsw6_lock); /*used inregister and unregister*/

struct ilnpv6_params ilnpv6_defaults = {
        .disable_ilnpv6 = 0,
        .autoconf = 1,
};

static int disable_ilnpv6_mod;
module_param_named(disable, disable_ilnpv6_mod, int, 0444);
MODULE_PARM_DESC(disable, "Disable ILNPv6 module such that it is non-functional");

module_param_named(disable_ilnpv6, ilnpv6_defaults.disable_ilnpv6, int, 0444);
MODULE_PARM_DESC(disable_ilnpv6, "Disable ILNPv6 on all interfaces");

module_param_named(autoconf, ilnpv6_defaults.autoconf, int, 0444);
MODULE_PARM_DESC(autoconf, "Enable ILNPv6 address autoconfiguration on all interfaces");

/*review*/
static int ilnp6_create(struct net *net, struct socket *sock, int protocol,
                        int kern)
{
        struct inet_sock *inet;
        struct ipv6_pinfo *np;
        struct sock *sk;
        struct inet_protosw *answer;
        struct proto *answer_prot;
        unsigned char answer_flags;
        int try_loading_module = 0;
        int err;

        if (protocol < 0 || protocol >= IPPROTO_MAX)
                return -EINVAL;

        /* Look for the requested type/protocol pair. */
lookup_protocol:
        err = -ESOCKTNOSUPPORT;
        rcu_read_lock();
        list_for_each_entry_rcu(answer, &ilnpsw6[sock->type], list) {
                err = 0;
                /* Check the non-wild match. */
                if (protocol == answer->protocol) {
                        if (protocol != IPPROTO_IP)
                                break;
                } else {
                        /* Check for the two wild cases. */
                        if (IPPROTO_IP == protocol) {
                                protocol = answer->protocol;
                                break;
                        }
                        if (IPPROTO_IP == answer->protocol)
                                break;
                }
                err = -EPROTONOSUPPORT;
        }
        if (err) {
                if (try_loading_module < 2) {
                        /* MARK: not sure about this..*/
                        rcu_read_unlock();
                        /*
                         * Be more specific, e.g. net-pf-10-proto-132-type-1
                         * (net-pf-PF_ILNP6-proto-IPPROTO_SCTP-type-SOCK_STREAM)
                         */
                        if (++try_loading_module == 1)
                                request_module("net-pf-%d-proto-%d-type-%d",
                                               PF_ILNP6, protocol, sock->type);
                        /*
                         * Fall back to generic, e.g. net-pf-10-proto-132
                         * (net-pf-PF_ILNP6-proto-IPPROTO_SCTP)
                         */
                        else
                                request_module("net-pf-%d-proto-%d",
                                               PF_ILNP6, protocol);
                        goto lookup_protocol;
                } else
                        goto out_rcu_unlock;
        }

        err = -EPERM;
        if (sock->type == SOCK_RAW && !kern &&
            !ns_capable(net->user_ns, CAP_NET_RAW))
                goto out_rcu_unlock;

        sock->ops = answer->ops;
        answer_prot = answer->prot;
        answer_flags = answer->flags;
        rcu_read_unlock();

        WARN_ON(!answer_prot->slab);

        err = -ENOBUFS;
        sk = sk_alloc(net, PF_ILNP6, GFP_KERNEL, answer_prot, kern);
        if (!sk)
                goto out;
        // MARK it calls: lockdep_set_class_and_name??
        sock_init_data(sock, sk);

        err = 0;
        if (INET_PROTOSW_REUSE & answer_flags)
                sk->sk_reuse = SK_CAN_REUSE;

        inet = inet_sk(sk);
        inet->is_icsk = (INET_PROTOSW_ICSK & answer_flags) != 0;

        if (SOCK_RAW == sock->type) {
                inet->inet_num = protocol;
                if (IPPROTO_RAW == protocol)
                        inet->hdrincl = 1;
        }
        sk->sk_destruct   = inet_sock_destruct;
        sk->sk_family   = PF_ILNP6;
        sk->sk_protocol   = protocol;

        sk->sk_backlog_rcv  = answer->prot->backlog_rcv;

        inet_sk(sk)->pinet6 = np = inet6_sk_generic(sk);
        np->hop_limit = -1;
        np->mcast_hops  = IPV6_DEFAULT_MCASTHOPS;
        np->mc_loop = 1;
        np->pmtudisc  = IPV6_PMTUDISC_WANT;
        sk->sk_ipv6only = net->ipv6.sysctl.bindv6only;

        /* Init the ipv4 part of the socket since we can have sockets
         * using v6 API for ipv4.
         */
        inet->uc_ttl  = -1;

        inet->mc_loop = 1;
        inet->mc_ttl  = 1;
        inet->mc_index  = 0;
        inet->mc_list = NULL;
        inet->rcv_tos = 0;

        if (net->ipv4.sysctl_ip_no_pmtu_disc)
                inet->pmtudisc = IP_PMTUDISC_DONT;
        else
                inet->pmtudisc = IP_PMTUDISC_WANT;
        /*
         * Increment only the relevant sk_prot->socks debug field, this changes
         * the previous behaviour of incrementing both the equivalent to
         * answer->prot->socks (inet6_sock_nr) and inet_sock_nr.
         *
         * This allows better debug granularity as we'll know exactly how many
         * UDPv6, TCPv6, etc socks were allocated, not the sum of all IPv6
         * transport protocol socks. -acme
         */
        sk_refcnt_debug_inc(sk);

        if (inet->inet_num) {
                /* It assumes that any protocol which allows
                 * the user to assign a number at socket
                 * creation time automatically shares.
                 */
                inet->inet_sport = htons(inet->inet_num);
                sk->sk_prot->hash(sk);
        }
        if (sk->sk_prot->init) {
                err = sk->sk_prot->init(sk);
                if (err) {
                        sk_common_release(sk);
                        goto out;
                }
        }
out:
        return err;
out_rcu_unlock:
        rcu_read_unlock();
        goto out;
}

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

static const struct net_proto_family ilnp6_family_ops = {
        .family =  PF_ILNP6,
        .create = ilnp6_create,
        .owner  = THIS_MODULE,
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

// NOTE MARK: DEPEND ON INET6 INIT & EXIT..
// static struct pernet_operations ilnp6_net_ops = {
//         .init = inet6_net_init,
//         .exit = inet6_net_exit,
// };

// review proto_register for udp, and the fumction
static int __init ilnp6_init(void)
{
        struct list_head *r;
        int err = 0;

        sock_skb_cb_check_size(sizeof(struct inet6_skb_parm));

        /* Register the socket-side information for ilnp6_create.  */
        for (r = &ilnpsw6[0]; r < &ilnpsw6[SOCK_MAX]; ++r)
                INIT_LIST_HEAD(r);

        if (disable_ilnpv6_mod) {
                pr_info("ILNPv6: Loaded, but administratively disabled, reboot required to enable\n");
                goto out;
        }


        err = proto_register(&udpv6_prot, 1);
        if (err)
                goto out_unregister_tcp_proto;


        /* Register the family here so that the init calls below will
         * be able to create sockets. (?? is this dangerous ??)
         */
        err = sock_register(&ilnp6_family_ops);
        if (err)
                goto out_sock_register_fail;

        /*
         *	ipngwg API draft makes clear that the correct semantics
         *	for TCP and UDP is to consider one TCP and UDP instance
         *	in a host available by both INET and INET6 APIs and
         *	able to communicate via both network protocols.
         */


// all registeration already done with ip6 excluded

        /* Init v6 transport protocols. */
        err = udpv6_init();
        if (err)
                goto udpv6_fail;

        // err = udplitev6_init();
        // if (err)
        //         goto udplitev6_fail;
        //
        // err = tcpv6_init();
        // if (err)
        //         goto tcpv6_fail;
        //
        // err = ipv6_packet_init();
        // if (err)
        //         goto ipv6_packet_fail;
        //
        // err = pingv6_init();
        // if (err)
        //         goto pingv6_fail;

out:
        return err;

#ifdef CONFIG_SYSCTL
sysctl_fail:
        pingv6_exit();
#endif
pingv6_fail:
        ipv6_packet_cleanup();
ipv6_packet_fail:
        tcpv6_exit();
tcpv6_fail:
        udplitev6_exit();
udplitev6_fail:
        udpv6_exit();
udpv6_fail:
        ipv6_frag_exit();
ipv6_frag_fail:
        ipv6_exthdrs_exit();
ipv6_exthdrs_fail:
        addrconf_cleanup();
addrconf_fail:
        ip6_flowlabel_cleanup();
ip6_flowlabel_fail:
        ndisc_late_cleanup();
ndisc_late_fail:
        ip6_route_cleanup();
ip6_route_fail:
#ifdef CONFIG_PROC_FS
        if6_proc_exit();
proc_if6_fail:
        ipv6_misc_proc_exit();
proc_misc6_fail:
        udplite6_proc_exit();
proc_udplite6_fail:
        raw6_proc_exit();
proc_raw6_fail:
#endif
        ipv6_netfilter_fini();
netfilter_fail:
        igmp6_cleanup();
igmp_fail:
        ndisc_cleanup();
ndisc_fail:
        ip6_mr_cleanup();
icmp_fail:
        unregister_pernet_subsys(&inet6_net_ops);
ipmr_fail:
        icmpv6_cleanup();
register_pernet_fail:
        sock_unregister(PF_INET6);
        rtnl_unregister_all(PF_INET6);
out_sock_register_fail:
        rawv6_exit();
out_unregister_ping_proto:
        proto_unregister(&pingv6_prot);
out_unregister_raw_proto:
        proto_unregister(&rawv6_prot);
out_unregister_udplite_proto:
        proto_unregister(&udplitev6_prot);
out_unregister_udp_proto:
        proto_unregister(&udpv6_prot);
out_unregister_tcp_proto:
        proto_unregister(&tcpv6_prot);
        goto out;
}

module_init(ilnp6_init);

MODULE_ALIAS_NETPROTO(PF_ILNP6);

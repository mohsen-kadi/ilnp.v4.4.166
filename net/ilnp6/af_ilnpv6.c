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
#include <linux/bootmem.h>

#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/icmpv6.h>
#include <linux/netfilter_ipv6.h>

#include <net/ip.h>
#include <net/ipv6.h>
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

/*ILCC for ILNP v6*/
struct ilcc_table ilcc_table __read_mostly;
EXPORT_SYMBOL(ilcc_table);

/* The ilnpsw6 table contains everything that ilnp6_create needs to
 * build a new socket.
 */
static struct list_head ilnpsw6[SOCK_MAX];
static DEFINE_SPINLOCK(ilnpsw6_lock); /*used inregister and unregister*/

/* to delete functions*/
void print_l64_value(const struct l64 *locator)
{
        char str[40];
        sprintf(str, "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                (int)locator->locator_addr[0], (int)locator->locator_addr[1],
                (int)locator->locator_addr[2], (int)locator->locator_addr[3],
                (int)locator->locator_addr[4], (int)locator->locator_addr[5],
                (int)locator->locator_addr[6], (int)locator->locator_addr[7]);
        printk("l64: value: %s\n",str);
}

void print_l64(const struct l64 *locator)
{
        print_l64_value(locator);
        printk(KERN_INFO "l64: state: %d \n", locator->state);
        printk(KERN_INFO "l64: ttl: %d \n", locator->ttl);
        printk(KERN_INFO "l64: preference: %d \n", locator->preference);
}
/* to delete functions */


// struct ilnpv6_params ilnpv6_defaults = {
//         .disable_ilnpv6 = 0,
//         .autoconf = 1,
// };

//static int disable_ilnpv6_mod;
// module_param_named(disable, disable_ilnpv6_mod, int, 0444);
// MODULE_PARM_DESC(disable, "Disable ILNPv6 module such that it is non-functional");
//
// module_param_named(disable_ilnpv6, ilnpv6_defaults.disable_ilnpv6, int, 0444);
// MODULE_PARM_DESC(disable_ilnpv6, "Disable ILNPv6 on all interfaces");
//
// module_param_named(autoconf, ilnpv6_defaults.autoconf, int, 0444);
// MODULE_PARM_DESC(autoconf, "Enable ILNPv6 address autoconfiguration on all interfaces");

// repeated from /net/ipv6/af_inet6.c#L93
static __inline__ struct ipv6_pinfo *inet6_sk_generic(struct sock *sk)
{
        const int offset = sk->sk_prot->obj_size - sizeof(struct ipv6_pinfo);

        return (struct ipv6_pinfo *)(((u8 *)sk) + offset);
}

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
        .bind      = ilnp6_bind,
        .connect     = inet_dgram_connect,/* there is a check if (addr_len < sizeof(uaddr->sa_family)) return -EINVAL;		*/
        .socketpair    = sock_no_socketpair,/* a do nothing, ok	*/
        .accept      = sock_no_accept,/* a do nothing, ok	*/
        .getname     = ilnp6_getname,
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

int ilnp6_register_protosw(struct inet_protosw *p)
{
        struct list_head *lh;
        struct inet_protosw *answer;
        struct list_head *last_perm;
        int protocol = p->protocol;
        int ret;

        spin_lock_bh(&ilnpsw6_lock);

        ret = -EINVAL;
        if (p->type >= SOCK_MAX)
                goto out_illegal;

        /* If we are trying to override a permanent protocol, bail. */
        answer = NULL;
        ret = -EPERM;
        last_perm = &ilnpsw6[p->type];
        list_for_each(lh, &ilnpsw6[p->type]) {
                answer = list_entry(lh, struct inet_protosw, list);

                /* Check only the non-wild match. */
                if (INET_PROTOSW_PERMANENT & answer->flags) {
                        if (protocol == answer->protocol)
                                break;
                        last_perm = lh;
                }

                answer = NULL;
        }
        if (answer)
                goto out_permanent;

        /* Add the new entry after the last permanent entry if any, so that
         * the new entry does not override a permanent entry when matched with
         * a wild-card protocol. But it is allowed to override any existing
         * non-permanent entry.  This means that when we remove this entry, the
         * system automatically returns to the old behavior.
         */
        list_add_rcu(&p->list, last_perm);
        ret = 0;
out:
        spin_unlock_bh(&ilnpsw6_lock);
        return ret;

out_permanent:
        pr_err("Attempt to override permanent protocol %d\n", protocol);
        goto out;

out_illegal:
        pr_err("Ignoring attempt to register invalid socket type %d\n",
               p->type);
        goto out;
}
EXPORT_SYMBOL(ilnp6_register_protosw);

void ilnp6_unregister_protosw(struct inet_protosw *p)
{
        if (INET_PROTOSW_PERMANENT & p->flags) {
                pr_err("Attempt to unregister permanent protocol %d\n",
                       p->protocol);
        } else {
                spin_lock_bh(&ilnpsw6_lock);
                list_del_rcu(&p->list);
                spin_unlock_bh(&ilnpsw6_lock);

                synchronize_net();
        }
}
EXPORT_SYMBOL(ilnp6_unregister_protosw);
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
           in our case, tcpv6_prot & udp_ilnp6_proto  (struct proto)
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
EXPORT_SYMBOL(ilnp6_getname);


static __initdata unsigned long ilcc_uhash_entries;
static int __init set_ilnpv6_uhash_entries(char *str)
{
        ssize_t ret;

        if (!str)
                return 0;

        ret = kstrtoul(str, 0, &ilcc_uhash_entries);
        if (ret)
                return 0;

        if (ilcc_uhash_entries && ilcc_uhash_entries < UDP_HTABLE_SIZE_MIN)
                ilcc_uhash_entries = UDP_HTABLE_SIZE_MIN;
        return 1;
}
__setup("ilcc_uhash_entries=", set_ilnpv6_uhash_entries);

void __init ilcc_table_init(struct ilcc_table *table, const char *name)
{
        unsigned int i;

        table->hash = alloc_large_system_hash(name,
                                              sizeof(struct ilcc_table),
                                              ilcc_uhash_entries,
                                              21, /* one slot per 2 MB */
                                              0,
                                              &table->log,
                                              &table->mask,
                                              UDP_HTABLE_SIZE_MIN,
                                              64 * 1024);

        for (i = 0; i <= table->mask; i++) {
                INIT_HLIST_NULLS_HEAD(&table->hash[i].head, i);
                table->hash[i].count = 0;
                spin_lock_init(&table->hash[i].lock);
        }
}

// to do:
// rec, set the struct at ipv6 ext hdrs
int ilnp6_datagram_send_nonce(struct ipv6_txoptions *opt)
{
        // ipv6_opt_hdr is the same as ipv6_destopt_hdr
        struct ipv6_opt_hdr *dstopt;
        struct ipv6_destopt_nonce *nonce  = NULL;
        int err = 0;
        dstopt = kmalloc(sizeof(struct ipv6_opt_hdr), GFP_ATOMIC);
        if (!dstopt) {
                err = -EINVAL;
                goto exit_f;
        }
        dstopt->hdrlen = 0x0;
        nonce = (void *)(dstopt + 1);
        nonce->type= IPV6_TLV_NONCE;
        nonce->length = 0x04;
        nonce->nonce = 0x0007;
        opt->opt_flen += ((dstopt->hdrlen + 1) << 3);
        opt->dst1opt = dstopt;
exit_f:
        return err;
}

// NOTE MARK: DEPEND ON INET6 INIT & EXIT..
// static struct pernet_operations ilnp6_net_ops = {
//         .init = inet6_net_init,
//         .exit = inet6_net_exit,
// };

static int __init ilnp6_init(void)
{
        struct list_head *r;
        int err = 0;

        sock_skb_cb_check_size(sizeof(struct inet6_skb_parm));

        /* Register the socket-side information for ilnp6_create.  */
        for (r = &ilnpsw6[0]; r < &ilnpsw6[SOCK_MAX]; ++r)
                INIT_LIST_HEAD(r);

        // if (disable_ilnpv6_mod) {
        //         pr_info("ILNPv6: Loaded, but administratively disabled, reboot required to enable\n");
        //         goto out;
        // }

        /*NOTE MARK:  review*/
        err = proto_register(&udp_ilnp6_proto, 1);
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
        err = udp_ilnp6_init();
        if (err)
                goto udpv6_fail;
        ilcc_table_init(&ilcc_table, "ILCC");
out:
        return err;

udpv6_fail:
        ipv6_frag_exit();
out_sock_register_fail:
        rawv6_exit();
// out_unregister_udp_proto:
//         /*NOTE MARK:  review*/
//         proto_unregister(&udp_ilnp6_proto);
out_unregister_tcp_proto:
        proto_unregister(&tcpv6_prot);
        goto out;
}



/* ilcc functions*/
struct ilcc_entry *ilcc_nid_lookup(struct nid *nid, __be16 port)
{
        struct ilcc_entry *entry;
        struct hlist_nulls_node *node;
        // go to bucket,
        unsigned short dport = ntohs(port);
        unsigned int slot = ilcc_hashfn(dport, ilcc_table.mask);
        struct ilcc_slot *hslot = &ilcc_table.hash[slot];
        // for each session in the list
        // as in __udp4_lib_lookup
begin:
        hlist_nulls_for_each_entry_rcu(entry, node, &hslot->head, node){
                //check if it equal to the requested one
                if(is_nid_equal(&entry->local_nid, nid) && ( entry->dport == port))
                {
                        return entry;
                }
        }
        if (get_nulls_value(node) != slot)
                goto begin;
        return NULL;
}
EXPORT_SYMBOL_GPL(ilcc_nid_lookup);

int add_entry_to_ilcc(struct ilcc_entry *entry)
{
        unsigned short dport = ntohs(entry->dport);
        unsigned int slot = ilcc_hashfn(dport, ilcc_table.mask);
        struct ilcc_slot *hslot = &ilcc_table.hash[slot];
        int err = 0;
        spin_lock(&hslot->lock);
        hlist_nulls_add_head_rcu(&entry->node,
                                 &hslot->head);
        hslot->count++;
        spin_unlock(&hslot->lock);
        printk(KERN_INFO " New entry added to ilcc \n");
        return err;
}
EXPORT_SYMBOL_GPL(add_entry_to_ilcc);

// review for:
// selecting the best destination locator
// use rfc for l64 state, and state tras=nsition
struct in6_addr *ilnpv6_get_daddr(struct in6_addr *saddr, __be16 sport, int32_t snonce, struct in6_addr *daddr, __be16 dport, int32_t dnonce)
{
        struct nid *snid, *dnid;
        struct l64 *sl64, *dl64, *temp;
        struct ilcc_entry *entry = NULL;
        int err = 0;
        dnid = get_nid_from_in6_addr(daddr);
        dl64 = get_l64_from_in6_addr(daddr);
        // get the cache entry
        entry = ilcc_nid_lookup(dnid, dport);
        if(entry) //existed
        {
                // existed, check the locator status
                // either update the locator or keep it
                // the provided locator is the initial locator,
                // need function to this with the list head pointer
                printk(KERN_INFO " searching for the best remote locator \n");
                temp = get_best_l64(&entry->remote_locators);
                return get_in6_addr_from_ilv(dnid,temp);
        }
        else // not existed, build & add & return
        {
                // build the entry and add it...
                snid = get_nid_from_in6_addr(saddr);
                sl64 = get_l64_from_in6_addr(saddr);
                entry = kmalloc(sizeof(*entry), GFP_KERNEL);
                entry->sport = sport;
                entry->dport = dport;
                entry->local_nid = *snid;
                entry->remote_nid = *dnid;
                entry->local_nonce = snonce;
                entry->remote_nonce = dnonce;
                INIT_LIST_HEAD(&entry->local_locators);
                sl64->state = ILCC_ACTIVE;
                sl64->ttl = 100;
                sl64->preference = 1;
                list_add_tail(&(sl64->node),&(entry->local_locators));
                INIT_LIST_HEAD(&entry->remote_locators);
                dl64->state = ILCC_ACTIVE;
                dl64->ttl = 100;
                dl64->preference = 1;
                list_add_tail(&(dl64->node),&(entry->remote_locators));
                //add entry to ilcc
                err = add_entry_to_ilcc(entry);
                if(err)
                {
                        printk(KERN_INFO " Failed in adding cache entry to ilcc table \n");
                        return NULL;
                }
                // here we need to build sin6_addr
                // and return it, in this path it
                // is the same as daddr
                return daddr;
        }
        return NULL;
}
EXPORT_SYMBOL_GPL(ilnpv6_get_daddr);

// review for:
// where to put the list of local prefix data,
// can you use RA prefix info in setting up preference?
struct in6_addr *ilnpv6_get_saddr(struct in6_addr *saddr, __be16 sport, struct in6_addr *daddr, __be16 dport)
{
        // get the cache entry
        // if null, error must not happen
        // iterate over local locator to get the
        // best prefix to use it
        struct nid *snid, *dnid;
        struct l64 *sl64, *dl64, *temp;
        struct ilcc_entry *entry = NULL;
        snid = get_nid_from_in6_addr(saddr);
        sl64 = get_l64_from_in6_addr(saddr);
        dnid = get_nid_from_in6_addr(daddr);
        dl64 = get_l64_from_in6_addr(daddr);
        // get the cache entry
        entry = ilcc_nid_lookup(dnid, dport);
        if(entry) //existed
        {
                // existed, check the locator status
                // either update the locator or keep it
                // the provided locator is the initial locator,
                printk(KERN_INFO " searching for the best source locator \n");
                temp = get_best_l64(&entry->local_locators);
                return get_in6_addr_from_ilv(snid,temp);
        }
        else // not existed, error
                printk(KERN_INFO " Failed in getting cache entry for locally generated traffic \n");
        return NULL;
}

EXPORT_SYMBOL_GPL(ilnpv6_get_saddr);
/* end of ilcc functions*/
//module_init();
fs_initcall(ilnp6_init);

MODULE_ALIAS_NETPROTO(PF_ILNP6);

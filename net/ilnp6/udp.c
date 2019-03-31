/*
 *	UDP over ILNPv6
 *	Linux INET6 implementation
 *
 *	Authors:
 *
 *	Based on net/ipv6/udp.c
 *
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/in6.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/ipv6.h>
#include <linux/ilnp6.h>
#include <linux/icmpv6.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

#include <net/ndisc.h>
#include <net/protocol.h>
#include <net/transp_v6.h>
#include <net/ip6_route.h>
#include <net/raw.h>
#include <net/tcp_states.h>
#include <net/ip6_checksum.h>
#include <net/xfrm.h>
#include <net/inet6_hashtables.h>
#include <net/busy_poll.h>

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <trace/events/skb.h>
// for build error
#include <net/ilnp6.h>

#include "udp_impl.h"


/**/
// receive, nothing to do
static __inline__ int udp_ilnpv6_rcv(struct sk_buff *skb)
{
        return -1;// __udp6_lib_rcv(skb, &udp_table, IPPROTO_UDP);
}

static __inline__ void udp_ilnpv6_err(struct sk_buff *skb,
                                      struct inet6_skb_parm *opt, u8 type,
                                      u8 code, int offset, __be32 info)
{
        return;//__udp6_lib_err(skb, opt, type, code, offset, info, &udp_table);
}
/**/

static u32 udp_ilnpv6_portaddr_hash(const struct net *net,
                                    const struct in6_addr *addr6,
                                    unsigned int port)
{
        unsigned int hash, mix = net_hash_mix(net);

        if (ipv6_addr_any(addr6))
                hash = jhash_1word(0, mix);
        else if (ipv6_addr_v4mapped(addr6))
                hash = jhash_1word((__force u32)addr6->s6_addr32[3], mix);
        else
                hash = jhash2((__force u32 *)addr6->s6_addr32, 4, mix);

        return hash ^ port;
}

static void udp_ilnpv6_rehash(struct sock *sk)
{
        u16 new_hash = udp_ilnpv6_portaddr_hash(sock_net(sk),
                                                &sk->sk_v6_rcv_saddr,
                                                inet_sk(sk)->inet_num);

        udp_lib_rehash(sk, new_hash);
}

int udp_ilnpv6_get_port(struct sock *sk, unsigned short snum)
{
        unsigned int hash2_nulladdr =
                udp_ilnpv6_portaddr_hash(sock_net(sk), &in6addr_any, snum);
        unsigned int hash2_partial =
                udp_ilnpv6_portaddr_hash(sock_net(sk), &sk->sk_v6_rcv_saddr, 0);

        /* precompute partial secondary hash */
        udp_sk(sk)->udp_portaddr_hash = hash2_partial;
        return udp_lib_get_port(sk, snum, ipv6_rcv_saddr_equal, hash2_nulladdr);
}

/**
 *	udp6_hwcsum_outgoing  -  handle outgoing HW checksumming
 *	@sk:	socket we are sending on
 *	@skb:	sk_buff containing the filled-in UDP header
 *		(checksum field must be zeroed out)
 */
static void udp_ilnp6_hwcsum_outgoing(struct sock *sk, struct sk_buff *skb,
                                      const struct in6_addr *saddr,
                                      const struct in6_addr *daddr, int len)
{
        unsigned int offset;
        struct udphdr *uh = udp_hdr(skb);
        struct sk_buff *frags = skb_shinfo(skb)->frag_list;
        __wsum csum = 0;

        if (!frags) {
                /* Only one fragment on the socket.  */
                skb->csum_start = skb_transport_header(skb) - skb->head;
                skb->csum_offset = offsetof(struct udphdr, check);
                uh->check = ~csum_ipv6_magic(saddr, daddr, len, IPPROTO_UDP, 0);
        } else {
                /*
                 * HW-checksum won't work as there are two or more
                 * fragments on the socket so that all csums of sk_buffs
                 * should be together
                 */
                offset = skb_transport_offset(skb);
                skb->csum = skb_checksum(skb, offset, skb->len - offset, 0);
                csum = skb->csum;

                skb->ip_summed = CHECKSUM_NONE;

                do {
                        csum = csum_add(csum, frags->csum);
                } while ((frags = frags->next));

                uh->check = csum_ipv6_magic(saddr, daddr, len, IPPROTO_UDP,
                                            csum);
                if (uh->check == 0)
                        uh->check = CSUM_MANGLED_0;
        }
}

/*
 *	Sending
 */

static int udp_ilnpv6_send_skb(struct sk_buff *skb, struct flowi6 *fl6)
{
        struct sock *sk = skb->sk;
        struct udphdr *uh;
        int err = 0;
        int is_udplite = IS_UDPLITE(sk);
        __wsum csum = 0;
        int offset = skb_transport_offset(skb);
        int len = skb->len - offset;

        /*
         * Create a UDP header
         */
        uh = udp_hdr(skb);
        uh->source = fl6->fl6_sport;
        uh->dest = fl6->fl6_dport;
        uh->len = htons(len);
        uh->check = 0;

        if (is_udplite)
                csum = udplite_csum(skb);
        else if (udp_sk(sk)->no_check6_tx) { /* UDP csum disabled */
                skb->ip_summed = CHECKSUM_NONE;
                goto send;
        } else if (skb->ip_summed == CHECKSUM_PARTIAL) { /* UDP hardware csum */
                udp_ilnp6_hwcsum_outgoing(sk, skb, &fl6->saddr, &fl6->daddr, len);
                goto send;
        } else
                csum = udp_csum(skb);

        /* add protocol-dependent pseudo-header */
        uh->check = csum_ipv6_magic(&fl6->saddr, &fl6->daddr,
                                    len, fl6->flowi6_proto, csum);
        if (uh->check == 0)
                uh->check = CSUM_MANGLED_0;

send:
        err = ip6_send_skb(skb);
        if (err) {
                if (err == -ENOBUFS && !inet6_sk(sk)->recverr) {
                        UDP6_INC_STATS_USER(sock_net(sk),
                                            UDP_MIB_SNDBUFERRORS, is_udplite);
                        err = 0;
                }
        } else
                UDP6_INC_STATS_USER(sock_net(sk),
                                    UDP_MIB_OUTDATAGRAMS, is_udplite);
        return err;
}

/*
 * Throw away all pending data and cancel the corking. Socket is locked.
 */
static void udp_ilnpv6_flush_pending_frames(struct sock *sk)
{
        struct udp_sock *up = udp_sk(sk);

        if (up->pending == AF_INET)
                udp_flush_pending_frames(sk);
        else if (up->pending) {
                up->len = 0;
                up->pending = 0;
                ip6_flush_pending_frames(sk);
        }
}


static int udp_ilnpv6_push_pending_frames(struct sock *sk)
{
        struct sk_buff *skb;
        struct udp_sock  *up = udp_sk(sk);
        struct flowi6 fl6;
        int err = 0;

        if (up->pending == AF_INET)
                return udp_push_pending_frames(sk);

        /* ip6_finish_skb will release the cork, so make a copy of
         * fl6 here.
         */
        fl6 = inet_sk(sk)->cork.fl.u.ip6;

        skb = ip6_finish_skb(sk);
        if (!skb)
                goto out;

        err = udp_ilnpv6_send_skb(skb, &fl6);

out:
        up->len = 0;
        up->pending = 0;
        return err;
}

int udp_ilnpv6_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
        struct ipv6_txoptions opt_space;
        struct udp_sock *up = udp_sk(sk);
        struct inet_sock *inet = inet_sk(sk);
        struct ipv6_pinfo *np = inet6_sk(sk);
        DECLARE_SOCKADDR(struct sockaddr_in6 *, sin6, msg->msg_name);
        struct in6_addr *daddr, *final_p, final;
        struct ipv6_txoptions *opt = NULL;
        struct ipv6_txoptions *opt_to_free = NULL;
        struct ip6_flowlabel *flowlabel = NULL;
        struct flowi6 fl6;
        struct dst_entry *dst;
        int addr_len = msg->msg_namelen;
        int ulen = len;
        int hlimit = -1;
        int tclass = -1;
        int dontfrag = -1;
        int corkreq = up->corkflag || msg->msg_flags&MSG_MORE;
        int err;
        int connected = 0;
        int is_udplite = IS_UDPLITE(sk);
        int (*getfrag)(void *, char *, int, int, int, struct sk_buff *);

        /* destination address check */
        if (sin6) {
                if (addr_len < offsetof(struct sockaddr, sa_data))
                        return -EINVAL;

                switch (sin6->sin6_family) {
                case  AF_ILNP6:
                        if (addr_len < SIN6_LEN_RFC2133)
                                return -EINVAL;
                        daddr = &sin6->sin6_addr;
                        if (ipv6_addr_any(daddr) &&
                            ipv6_addr_v4mapped(&np->saddr))
                                ipv6_addr_set_v4mapped(htonl(INADDR_LOOPBACK),
                                                       daddr);
                        break;
                case AF_INET:
                        goto do_udp_sendmsg;
                case AF_UNSPEC:
                        msg->msg_name = sin6 = NULL;
                        msg->msg_namelen = addr_len = 0;
                        daddr = NULL;
                        break;
                default:
                        return -EINVAL;
                }
        } else if (!up->pending) {
                if (sk->sk_state != TCP_ESTABLISHED)
                        return -EDESTADDRREQ;
                daddr = &sk->sk_v6_daddr;
        } else
                daddr = NULL;

        if (daddr) {
                if (ipv6_addr_v4mapped(daddr)) {
                        struct sockaddr_in sin;
                        sin.sin_family = AF_INET;
                        sin.sin_port = sin6 ? sin6->sin6_port : inet->inet_dport;
                        sin.sin_addr.s_addr = daddr->s6_addr32[3];
                        msg->msg_name = &sin;
                        msg->msg_namelen = sizeof(sin);
do_udp_sendmsg:
                        if (__ipv6_only_sock(sk))
                                return -ENETUNREACH;
                        return udp_sendmsg(sk, msg, len);
                }
        }

        if (up->pending == AF_INET)
                return udp_sendmsg(sk, msg, len);

        /* Rough check on arithmetic overflow,
           better check is made in ip6_append_data().
         */
        if (len > INT_MAX - sizeof(struct udphdr))
                return -EMSGSIZE;

        getfrag  =  is_udplite ?  udplite_getfrag : ip_generic_getfrag;
        if (up->pending) {
                /*
                 * There are pending frames.
                 * The socket lock must be held while it's corked.
                 */
                lock_sock(sk);
                if (likely(up->pending)) {
                        if (unlikely(up->pending != AF_ILNP6)) {
                                release_sock(sk);
                                return -EAFNOSUPPORT;
                        }
                        dst = NULL;
                        goto do_append_data;
                }
                release_sock(sk);
        }
        ulen += sizeof(struct udphdr);

        memset(&fl6, 0, sizeof(fl6));

        if (sin6) {
                if (sin6->sin6_port == 0)
                        return -EINVAL;

                fl6.fl6_dport = sin6->sin6_port;
                daddr = &sin6->sin6_addr;

                if (np->sndflow) {
                        fl6.flowlabel = sin6->sin6_flowinfo&IPV6_FLOWINFO_MASK;
                        if (fl6.flowlabel&IPV6_FLOWLABEL_MASK) {
                                flowlabel = fl6_sock_lookup(sk, fl6.flowlabel);
                                if (!flowlabel)
                                        return -EINVAL;
                        }
                }

                /*
                 * Otherwise it will be difficult to maintain
                 * sk->sk_dst_cache.
                 */
                if (sk->sk_state == TCP_ESTABLISHED &&
                    ipv6_addr_equal(daddr, &sk->sk_v6_daddr))
                        daddr = &sk->sk_v6_daddr;

                if (addr_len >= sizeof(struct sockaddr_in6) &&
                    sin6->sin6_scope_id &&
                    __ipv6_addr_needs_scope_id(__ipv6_addr_type(daddr)))
                        fl6.flowi6_oif = sin6->sin6_scope_id;
        } else {
                if (sk->sk_state != TCP_ESTABLISHED)
                        return -EDESTADDRREQ;

                fl6.fl6_dport = inet->inet_dport;
                daddr = &sk->sk_v6_daddr;
                fl6.flowlabel = np->flow_label;
                connected = 1;
        }

        if (!fl6.flowi6_oif)
                fl6.flowi6_oif = sk->sk_bound_dev_if;

        if (!fl6.flowi6_oif)
                fl6.flowi6_oif = np->sticky_pktinfo.ipi6_ifindex;

        fl6.flowi6_mark = sk->sk_mark;

        if (msg->msg_controllen) {
                opt = &opt_space;
                memset(opt, 0, sizeof(struct ipv6_txoptions));
                opt->tot_len = sizeof(*opt);

                err = ip6_datagram_send_ctl(sock_net(sk), sk, msg, &fl6, opt,
                                            &hlimit, &tclass, &dontfrag);
                if (err < 0) {
                        fl6_sock_release(flowlabel);
                        return err;
                }
                if ((fl6.flowlabel&IPV6_FLOWLABEL_MASK) && !flowlabel) {
                        flowlabel = fl6_sock_lookup(sk, fl6.flowlabel);
                        if (!flowlabel)
                                return -EINVAL;
                }
                if (!(opt->opt_nflen|opt->opt_flen))
                        opt = NULL;
                connected = 0;
        }
        if (!opt) {
                opt = txopt_get(np);
                opt_to_free = opt;
        }
        if (flowlabel)
                opt = fl6_merge_options(&opt_space, flowlabel, opt);
        opt = ipv6_fixup_options(&opt_space, opt);

        fl6.flowi6_proto = sk->sk_protocol;
        if (!ipv6_addr_any(daddr))
                fl6.daddr = *daddr;
        else
                fl6.daddr.s6_addr[15] = 0x1; /* :: means loopback (BSD'ism) */
        if (ipv6_addr_any(&fl6.saddr) && !ipv6_addr_any(&np->saddr))
                fl6.saddr = np->saddr;
        fl6.fl6_sport = inet->inet_sport;

        final_p = fl6_update_dst(&fl6, opt, &final);
        if (final_p)
                connected = 0;

        if (!fl6.flowi6_oif && ipv6_addr_is_multicast(&fl6.daddr)) {
                fl6.flowi6_oif = np->mcast_oif;
                connected = 0;
        } else if (!fl6.flowi6_oif)
                fl6.flowi6_oif = np->ucast_oif;

        security_sk_classify_flow(sk, flowi6_to_flowi(&fl6));

        dst = ilnp6_sk_dst_lookup_flow(sk, &fl6, final_p);
        if (IS_ERR(dst)) {
                err = PTR_ERR(dst);
                dst = NULL;
                goto out;
        }

        if (hlimit < 0)
                hlimit = ip6_sk_dst_hoplimit(np, &fl6, dst);

        if (tclass < 0)
                tclass = np->tclass;

        if (msg->msg_flags&MSG_CONFIRM)
                goto do_confirm;
back_from_confirm:

        /* Lockless fast path for the non-corking case */
        if (!corkreq) {
                struct sk_buff *skb;

                skb = ip6_make_skb(sk, getfrag, msg, ulen,
                                   sizeof(struct udphdr), hlimit, tclass, opt,
                                   &fl6, (struct rt6_info *)dst,
                                   msg->msg_flags, dontfrag);
                err = PTR_ERR(skb);
                if (!IS_ERR_OR_NULL(skb))
                        err = udp_ilnpv6_send_skb(skb, &fl6);
                goto release_dst;
        }

        lock_sock(sk);
        if (unlikely(up->pending)) {
                /* The socket is already corked while preparing it. */
                /* ... which is an evident application bug. --ANK */
                release_sock(sk);

                net_dbg_ratelimited("udp cork app bug 2\n");
                err = -EINVAL;
                goto out;
        }

        up->pending = AF_ILNP6;

do_append_data:
        if (dontfrag < 0)
                dontfrag = np->dontfrag;
        up->len += ulen;
        err = ip6_append_data(sk, getfrag, msg, ulen,
                              sizeof(struct udphdr), hlimit, tclass, opt, &fl6,
                              (struct rt6_info *)dst,
                              corkreq ? msg->msg_flags|MSG_MORE : msg->msg_flags, dontfrag);
        if (err)
                udp_ilnpv6_flush_pending_frames(sk);
        else if (!corkreq)
                err = udp_ilnpv6_push_pending_frames(sk);
        else if (unlikely(skb_queue_empty(&sk->sk_write_queue)))
                up->pending = 0;

        if (err > 0)
                err = np->recverr ? net_xmit_errno(err) : 0;
        release_sock(sk);

release_dst:
        if (dst) {
                if (connected) {
                        ip6_dst_store(sk, dst,
                                      ipv6_addr_equal(&fl6.daddr, &sk->sk_v6_daddr) ?
                                      &sk->sk_v6_daddr : NULL,
#ifdef CONFIG_IPV6_SUBTREES
                                      ipv6_addr_equal(&fl6.saddr, &np->saddr) ?
                                      &np->saddr :
#endif
                                      NULL);
                } else {
                        dst_release(dst);
                }
                dst = NULL;
        }

out:
        dst_release(dst);
        fl6_sock_release(flowlabel);
        txopt_put(opt_to_free);
        if (!err)
                return len;
        /*
         * ENOBUFS = no kernel mem, SOCK_NOSPACE = no sndbuf space.  Reporting
         * ENOBUFS might not be good (it's not tunable per se), but otherwise
         * we don't have a good statistic (IpOutDiscards but it can be too many
         * things).  We could add another new stat but at least for now that
         * seems like overkill.
         */
        if (err == -ENOBUFS || test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
                UDP6_INC_STATS_USER(sock_net(sk),
                                    UDP_MIB_SNDBUFERRORS, is_udplite);
        }
        return err;

do_confirm:
        dst_confirm(dst);
        if (!(msg->msg_flags&MSG_PROBE) || len)
                goto back_from_confirm;
        err = 0;
        goto out;
}

/*NOTE MARK empty one*/
int udp_ilnpv6_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int noblock,
                       int flags, int *addr_len)
{
        return -1;
}
void udp_ilnpv6_destroy_sock(struct sock *sk)
{
        //struct udp_sock *up = udp_sk(sk);
        lock_sock(sk);
        udp_ilnpv6_flush_pending_frames(sk);
        release_sock(sk);

/*NOTE MARK removed..*/
        // if (static_key_false(&udpv6_encap_needed) && up->encap_type) {
        //         void (*encap_destroy)(struct sock *sk);
        //         encap_destroy = ACCESS_ONCE(up->encap_destroy);
        //         if (encap_destroy)
        //                 encap_destroy(sk);
        // }

        inet6_destroy_sock(sk);
}

/*
 *	Socket option code for UDP
 */
int udp_ilnpv6_setsockopt(struct sock *sk, int level, int optname,
                          char __user *optval, unsigned int optlen)
{
        if (level == SOL_UDP  ||  level == SOL_UDPLITE)
                return udp_lib_setsockopt(sk, level, optname, optval, optlen,
                                          udp_ilnpv6_push_pending_frames);
        return ipv6_setsockopt(sk, level, optname, optval, optlen);
}

int udp_ilnpv6_getsockopt(struct sock *sk, int level, int optname,
                          char __user *optval, int __user *optlen)
{
        if (level == SOL_UDP  ||  level == SOL_UDPLITE)
                return udp_lib_getsockopt(sk, level, optname, optval, optlen);
        return ipv6_getsockopt(sk, level, optname, optval, optlen);
}

static int __udp_ilnpv6_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
        int rc;

        if (!ipv6_addr_any(&sk->sk_v6_daddr)) {
                sock_rps_save_rxhash(sk, skb);
                sk_mark_napi_id(sk, skb);
                sk_incoming_cpu_update(sk);
        }

        rc = sock_queue_rcv_skb(sk, skb);
        if (rc < 0) {
                int is_udplite = IS_UDPLITE(sk);

                /* Note that an ENOMEM error is charged twice */
                if (rc == -ENOMEM)
                        UDP6_INC_STATS_BH(sock_net(sk),
                                          UDP_MIB_RCVBUFERRORS, is_udplite);
                UDP6_INC_STATS_BH(sock_net(sk), UDP_MIB_INERRORS, is_udplite);
                kfree_skb(skb);
                return -1;
        }
        return 0;
}


#ifdef CONFIG_COMPAT
int compat_udp_ilnpv6_setsockopt(struct sock *sk, int level, int optname,
                                 char __user *optval, unsigned int optlen)
{
        if (level == SOL_UDP  ||  level == SOL_UDPLITE)
                return udp_lib_setsockopt(sk, level, optname, optval, optlen,
                                          udp_ilnpv6_push_pending_frames);
        return compat_ipv6_setsockopt(sk, level, optname, optval, optlen);
}
#endif

#ifdef CONFIG_COMPAT
int compat_udp_ilnpv6_getsockopt(struct sock *sk, int level, int optname,
                                 char __user *optval, int __user *optlen)
{
        if (level == SOL_UDP  ||  level == SOL_UDPLITE)
                return udp_lib_getsockopt(sk, level, optname, optval, optlen);
        return compat_ipv6_getsockopt(sk, level, optname, optval, optlen);
}
#endif

void udp_ilnpv6_clear_sk(struct sock *sk, int size)
{
        struct inet_sock *inet = inet_sk(sk);

        /* we do not want to clear pinet6 field, because of RCU lookups */
        sk_prot_clear_portaddr_nulls(sk, offsetof(struct inet_sock, pinet6));

        size -= offsetof(struct inet_sock, pinet6) + sizeof(inet->pinet6);
        memset(&inet->pinet6 + 1, 0, size);
}
// NOTE: MARK now we use udp over ipv6
static const struct inet6_protocol udp_ilnp6_protocol = {
        .handler = udp_ilnpv6_rcv,
        .err_handler = udp_ilnpv6_err,
        .flags   = INET6_PROTO_NOPOLICY|INET6_PROTO_FINAL,
};
/* ------------------------------------------------------------------------ */
/*NOTE: MARK review, the previous struct.. for receive*/
struct proto udp_ilnp6_proto = {
        .name      = "UDPv6",
        .owner       = THIS_MODULE,
        .close       = udp_lib_close, /*ok*/
        .connect     = ilnp6_datagram_connect, // ok til setting dst_cache
        .disconnect    = udp_disconnect, // ok
        .ioctl       = udp_ioctl, // postpone
        .destroy     = udp_ilnpv6_destroy_sock,
        .setsockopt    = udp_ilnpv6_setsockopt, // review, pass  udp_v6_push_pending_frames as parameter
        .getsockopt    = udp_ilnpv6_getsockopt,
        .sendmsg     = udp_ilnpv6_sendmsg, /*hope it is ok*/
        .recvmsg     = udp_ilnpv6_recvmsg, /*empty*/
        .backlog_rcv     = __udp_ilnpv6_queue_rcv_skb,
        .hash      = udp_lib_hash,
        .unhash      = udp_lib_unhash,
        .rehash      = udp_ilnpv6_rehash,
        .get_port    = udp_ilnpv6_get_port,
        .memory_allocated  = &udp_memory_allocated,
        .sysctl_mem    = sysctl_udp_mem,
        .sysctl_wmem     = &sysctl_udp_wmem_min,
        .sysctl_rmem     = &sysctl_udp_rmem_min,
        .obj_size    = sizeof(struct udp6_sock),
        .slab_flags    = SLAB_DESTROY_BY_RCU,
        .h.udp_table     = &udp_table,
#ifdef CONFIG_COMPAT
        .compat_setsockopt = compat_udp_ilnpv6_setsockopt,
        .compat_getsockopt = compat_udp_ilnpv6_getsockopt,
#endif
        .clear_sk    = udp_ilnpv6_clear_sk,
};

static struct inet_protosw udp_ilnpv6_protosw = {
        .type =      SOCK_DGRAM,
        .protocol =  IPPROTO_UDP,
        .prot =      &udp_ilnp6_proto,
        .ops =       &ilnp6_dgram_ops,
        .flags =     INET_PROTOSW_PERMANENT,
};

int __init udp_ilnp6_init(void)
{
        int ret;
        // review
        ret = ilnp6_add_protocol(&udp_ilnp6_protocol, IPPROTO_UDP);
        if (ret)
                goto out;
        // review
        ret = ilnp6_register_protosw(&udp_ilnpv6_protosw);
        if (ret)
                goto out_udpv6_protocol;
out:
        return ret;

out_udpv6_protocol:
        ilnp6_del_protocol(&udp_ilnp6_protocol, IPPROTO_UDP);
        goto out;
}

// review
void udp_ilnp6_exit(void)
{
        inet6_unregister_protosw(&udp_ilnpv6_protosw);
        inet6_del_protocol(&udp_ilnp6_protocol, IPPROTO_UDP);
}

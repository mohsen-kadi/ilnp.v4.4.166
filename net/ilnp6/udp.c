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
#include "udp_impl.h"








int udp_ilnp6_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
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
                        err = udp_v6_send_skb(skb, &fl6);
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
                udp_v6_flush_pending_frames(sk);
        else if (!corkreq)
                err = udp_v6_push_pending_frames(sk);
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

// NOTE: MARK now we use udp over ipv6
static const struct inet6_protocol udp_ilnp6_protocol = {
        .handler = udpv6_rcv,
        .err_handler = udpv6_err,
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
        .destroy     = udpv6_destroy_sock, // calls udp_v6_flush_pending_frames
        .setsockopt    = udpv6_setsockopt, // review, pass  udp_v6_push_pending_frames as parameter
        .getsockopt    = udpv6_getsockopt,
        .sendmsg     = udp_ilnp6_sendmsg, /*hope it is ok*/
        /*note here*/
        .recvmsg     = udpv6_recvmsg,
        .backlog_rcv     = __udpv6_queue_rcv_skb,
        .hash      = udp_lib_hash,
        .unhash      = udp_lib_unhash,
        .rehash      = udp_v6_rehash,
        .get_port    = udp_v6_get_port,
        .memory_allocated  = &udp_memory_allocated,
        .sysctl_mem    = sysctl_udp_mem,
        .sysctl_wmem     = &sysctl_udp_wmem_min,
        .sysctl_rmem     = &sysctl_udp_rmem_min,
        .obj_size    = sizeof(struct udp6_sock),
        .slab_flags    = SLAB_DESTROY_BY_RCU,
        .h.udp_table     = &udp_table,
#ifdef CONFIG_COMPAT
        .compat_setsockopt = compat_udpv6_setsockopt,
        .compat_getsockopt = compat_udpv6_getsockopt,
#endif
        .clear_sk    = udp_v6_clear_sk,
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
        ilnp6_del_protocol(&udpv6_protocol, IPPROTO_UDP);
        goto out;
}

// review
void udp_ilnp6_exit(void)
{
        inet6_unregister_protosw(&udpv6_protosw);
        inet6_del_protocol(&udpv6_protocol, IPPROTO_UDP);
}

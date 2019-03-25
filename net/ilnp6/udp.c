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










/* ------------------------------------------------------------------------ */
/*NOTE: MARK review*/
struct proto udp_ilnp6_proto = {
        .name      = "UDPv6",
        .owner       = THIS_MODULE,
        .close       = udp_lib_close,
        .connect     = ip6_datagram_connect,
        .disconnect    = udp_disconnect,
        .ioctl       = udp_ioctl,
        .destroy     = udpv6_destroy_sock,
        .setsockopt    = udpv6_setsockopt,
        .getsockopt    = udpv6_getsockopt,
        .sendmsg     = udpv6_sendmsg,
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

static struct inet_protosw udpv6_protosw = {
        .type =      SOCK_DGRAM,
        .protocol =  IPPROTO_UDP,
        .prot =      &udp_ilnp6_proto,
        .ops =       &ilnp6_dgram_ops,
        .flags =     INET_PROTOSW_PERMANENT,
};

int __init udpv6_init(void)
{
        int ret;

        ret = inet6_add_protocol(&udpv6_protocol, IPPROTO_UDP);
        if (ret)
                goto out;

        ret = inet6_register_protosw(&udpv6_protosw);
        if (ret)
                goto out_udpv6_protocol;
out:
        return ret;

out_udpv6_protocol:
        inet6_del_protocol(&udpv6_protocol, IPPROTO_UDP);
        goto out;
}

void udpv6_exit(void)
{
        inet6_unregister_protosw(&udpv6_protosw);
        inet6_del_protocol(&udpv6_protocol, IPPROTO_UDP);
}

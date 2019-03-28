// based on /net/ipv6/ip6_output.c

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/in6.h>
#include <linux/tcp.h>
#include <linux/route.h>
#include <linux/module.h>
#include <linux/slab.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>

#include <net/sock.h>
#include <net/snmp.h>

#include <net/ipv6.h>
#include <net/ndisc.h>
#include <net/protocol.h>
#include <net/ip6_route.h>
#include <net/addrconf.h>
#include <net/rawv6.h>
#include <net/icmp.h>
#include <net/xfrm.h>
#include <net/checksum.h>
#include <linux/mroute6.h>
#include <net/l3mdev.h>

#include <net/ilnp6.h>

// for udp: int ip6_send_skb(struct sk_buff *skb)
// for tcp: int ip6_xmit(const struct sock *sk, struct sk_buff *skb, struct flowi6 *fl6,
//                        struct ipv6_txoptions *opt, int tclass)

static struct dst_entry *ilnp6_sk_dst_check(struct sock *sk,
                                            struct dst_entry *dst,
                                            const struct flowi6 *fl6)
{
        struct ipv6_pinfo *np = inet6_sk(sk);
        struct rt6_info *rt;

        if (!dst)
                goto out;

        if (dst->ops->family !=  AF_ILNP6) {
                dst_release(dst);
                return NULL;
        }

        rt = (struct rt6_info *)dst;
        /* Yes, checking route validity in not connected
         * case is not very simple. Take into account,
         * that we do not support routing by source, TOS,
         * and MSG_DONTROUTE		--ANK (980726)
         *
         * 1. ip6_rt_check(): If route was host route,
         *    check that cached destination is current.
         *    If it is network route, we still may
         *    check its validity using saved pointer
         *    to the last used address: daddr_cache.
         *    We do not want to save whole address now,
         *    (because main consumer of this service
         *    is tcp, which has not this problem),
         *    so that the last trick works only on connected
         *    sockets.
         * 2. oif also should be the same.
         */
        if (ip6_rt_check(&rt->rt6i_dst, &fl6->daddr, np->daddr_cache) ||
#ifdef CONFIG_IPV6_SUBTREES
            ip6_rt_check(&rt->rt6i_src, &fl6->saddr, np->saddr_cache) ||
#endif
            (!(fl6->flowi6_flags & FLOWI_FLAG_SKIP_NH_OIF) &&
             (fl6->flowi6_oif && fl6->flowi6_oif != dst->dev->ifindex))) {
                dst_release(dst);
                dst = NULL;
        }

out:
        return dst;
}

/** ilnp6_sk_dst_lookup_flow
 *	based on :ip6_sk_dst_lookup_flow - perform socket cached route lookup on flow
 *	@sk: socket which provides the dst cache and route info
 *	@fl6: flow to lookup
 *	@final_dst: final destination address for ipsec lookup
 *
 *	This function performs a route lookup on the given flow with the
 *	possibility of using the cached route in the socket if it is valid.
 *	It will take the socket dst lock when operating on the dst cache.
 *	As a result, this function can only be used in process context.
 *
 *	It returns a valid dst pointer on success, or a pointer encoded
 *	error code.
 */
struct dst_entry *ilnp6_sk_dst_lookup_flow(struct sock *sk, struct flowi6 *fl6,
                                           const struct in6_addr *final_dst)
{
        struct dst_entry *dst = sk_dst_check(sk, inet6_sk(sk)->dst_cookie);

        dst = ilnp6_sk_dst_check(sk, dst, fl6);
        if (!dst)
                dst = ip6_dst_lookup_flow(sk, fl6, final_dst);

        return dst;
}
EXPORT_SYMBOL_GPL(ip6_sk_dst_lookup_flow);

// check for sending the nonce, after sending using the new family
// check for sending the nonce
int ilnp_send_skb(struct sk_buff *skb)
{
        struct net *net = sock_net(skb->sk);
        struct rt6_info *rt = (struct rt6_info *)skb_dst(skb);
        int err;

        err = ip6_local_out(net, skb->sk, skb);
        if (err) {
                if (err > 0)
                        err = net_xmit_errno(err);
                if (err)
                        ILNP_INC_STATS(net, rt->rt6i_idev,
                                       ILNPSTATS_MIB_OUTDISCARDS);
        }

        return err;
}

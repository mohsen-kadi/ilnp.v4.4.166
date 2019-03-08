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



// for udp: int ip6_send_skb(struct sk_buff *skb)
// for tcp: int ip6_xmit(const struct sock *sk, struct sk_buff *skb, struct flowi6 *fl6,
//                        struct ipv6_txoptions *opt, int tclass)



<<<<<<< HEAD
// check for sending the nonce, after sending using the new family
=======
// check for sending the nonce
>>>>>>> c327a2087b53469fdd969006f8e9b227d06963d3
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

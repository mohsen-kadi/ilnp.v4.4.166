// based on /include/net/ipv6.h

#include <linux/ipv6.h>
#include <linux/hardirq.h>
#include <linux/jhash.h>
#include <net/if_inet6.h>
#include <net/ndisc.h>
#include <net/flow.h>
#include <net/flow_dissector.h>
#include <net/snmp.h>

#include <net/sock.h>

/* MIBs */

#define ILNP_INC_STATS(net, idev,field)		\
		_DEVINC(net, ipv6, 64, idev, field)

extern const struct proto_ops ilnp6_dgram_ops;




/*
 *	rcv function (called from netdevice level)
 */

// not used
// int ilnpv6_rcv(struct sk_buff *skb, struct net_device *dev,
// 	     struct packet_type *pt, struct net_device *orig_dev);

/* more secured version of ipv6_addr_hash() */
static inline u32 __ilnpv6_addr_jhash(const struct in6_addr *a, const u32 initval)
{
	u32 v = 0; // to exclude the prefix
	//(__force u32)a->s6_addr32[0] ^ (__force u32)a->s6_addr32[1];

	return jhash_3words(v,
			    (__force u32)a->s6_addr32[2],
			    (__force u32)a->s6_addr32[3],
			    initval);
}

static inline bool ilnpv6_nid_equal(const struct in6_addr *a1,
				   const struct in6_addr *a2)
{
	// #if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) && BITS_PER_LONG == 64
	// const unsigned long *ul1 = (const unsigned long *)a1;
	// const unsigned long *ul2 = (const unsigned long *)a2;

	// return ((ul1[0] ^ ul2[0]) | (ul1[1] ^ ul2[1])) == 0UL;
	// #else
	// return ((a1->s6_addr32[0] ^ a2->s6_addr32[0]) |
	// 	(a1->s6_addr32[1] ^ a2->s6_addr32[1]) |
	// 	(a1->s6_addr32[2] ^ a2->s6_addr32[2]) |
	// 	(a1->s6_addr32[3] ^ a2->s6_addr32[3])) == 0;

		return ((a1->s6_addr32[2] ^ a2->s6_addr32[2]) |
			(a1->s6_addr32[3] ^ a2->s6_addr32[3])) == 0;
	// #endif
}
/*
 *	upper-layer output functions
 */
struct dst_entry *ilnp6_sk_dst_lookup_flow(struct sock *sk, struct flowi6 *fl6,
							 const struct in6_addr *final_dst);

int ilnp6_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len);
int ilnp6_getname(struct socket *sock, struct sockaddr *uaddr,
                  int *uaddr_len, int peer);



int ilnp6_datagram_connect(struct sock *sk, struct sockaddr *addr, int addr_len);

int ilnp_send_skb(struct sk_buff *skb);

int ilnp6_datagram_send_nonce(struct ipv6_txoptions *opt);

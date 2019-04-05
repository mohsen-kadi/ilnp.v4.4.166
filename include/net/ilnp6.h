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

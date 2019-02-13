// based on /include/net/ip6_output.c

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

int ilnp_send_skb(struct sk_buff *skb);

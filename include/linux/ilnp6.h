//#ifndef _ILNPV6_H
//#define _ILNPV6_H

#include <uapi/linux/ipv6.h>


struct ilnpv6_params {
								__s32 disable_ilnpv6;
								__s32 autoconf;
};
extern struct ilnpv6_params ilnpv6_defaults;
#include <linux/icmpv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <net/inet_sock.h>


/*
	ILNP v6 Identifier Locator Communication Cache's functions
*/
static inline u32 ilcc_hashfn(u32 num, u32 mask)
{
	return (num) & mask;
	/*
	return (num + net_hash_mix(net)) & mask;
	*/
}


//#endif /* _ILNPV6_H */

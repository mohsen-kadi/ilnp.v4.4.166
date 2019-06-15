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

// for ilcc strcuts
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/hashtable.h>
#include <linux/types.h>
#include <linux/timer.h>

/* MIBs */

#define ILNP_INC_STATS(net, idev,field)  \
								_DEVINC(net, ipv6, 64, idev, field)

extern const struct proto_ops ilnp6_dgram_ops;

// represent a prefix, note: device info not listed
struct l64
{
								union {
																__u8 u6_addr8[8];
																__be16 u6_addr16[4];
																__be32 u6_addr32[2];
								} l64_u;
								#define  locator_addr      l64_u.u6_addr8
				#define  locator_addr16      l64_u.u6_addr16
				#define  locator_addr32      l64_u.u6_addr32
/* active, valid, aged, expired*/
								int32_t state;
/* duration that this L64 stay valid*/
								int32_t ttl;
/* preference 16 bit*/
								int16_t preference;
/* locator timer ???*/
								struct timer_list l64_timer;
/*for doubly linked list*/
								struct list_head node;
/*may we need for device associated with this prefix*/
};

// represent a node identifier
struct nid
{
								union {
																__u8 u6_addr8[8];
																__be16 u6_addr16[4];
																__be32 u6_addr32[2];
								} nid_u;
								#define  nid_addr      nid_u.u6_addr8
				#define  nid_addr16      nid_u.u6_addr16
				#define  nid_addr32      nid_u.u6_addr32
};

// represent a session in ILNP
struct ilcc_entry
{
								// ports, source port will be used as hash key
								__be16 source;
								__be16 dest;
								// local nid
								union {
																__u8 u6_addr8[8];
																__be16 u6_addr16[4];
																__be32 u6_addr32[2];
								} local_nid_u;
								#define local_nid      local_nid_u.u6_addr8
				#define local_nid16      local_nid_u.u6_addr16
				#define local_nid32      local_nid_u.u6_addr32

								int32_t local_nonce;
								// remote data
								int32_t remote_nonce;
								/* remote nid*/
								union {
																__u8 u6_addr8[8];
																__be16 u6_addr16[4];
																__be32 u6_addr32[2];
								} remote_nid_u;
				#define remote_nid      remote_nid_u.u6_addr8
				#define remote_nid16      remote_nid_u.u6_addr16
				#define remote_nid32      remote_nid_u.u6_addr32

								// list for local and remote locator
								// local locator will present at ilcc table also,
								// its existence here for future use in increasing granularity
								struct list_head local_locators;
								struct list_head remote_locators;

								// session timer, clear nonce values after session timeout
								struct timer_list ilnp_timer;
								// for hash
								struct hlist_nulls_node node;
};

// based on udp_table, the ilcc table & slot2
/**
 *	struct ilcc_slot - ILCC hash slot
 *
 *	@head:	head of list of ilcc_entry
 *	@count:	number of ilcc_entry in 'head' list
 *	@lock:	spinlock protecting changes to head/count
 */
struct ilcc_slot {
								struct hlist_nulls_head head;
								int count;
								spinlock_t lock;
} __attribute__((aligned(2 * sizeof(long))));

/**
 *	struct ilcc_table - ILCC table
 *
 *	@hash:	hash table, sockets are hashed on (local port)
 *  @local_locators: list of local locators at the host
 *	@mask:	number of slots in hash tables, minus 1
 *	@log:	log2(number of slots in hash table)
 */
struct ilcc_table {
								struct ilcc_slot *hash;
								struct list_head local_locators;
								unsigned int mask;
								unsigned int log;
};

void ilcc_table_init(struct ilcc_table *, const char *);

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

struct l64 *get_l64_from_in6_addr(struct in6_addr *source){
	struct l64 *l64;
	l64 = kmalloc(sizeof(*l64), GFP_KERNEL);
	l64->s6_addr32[0] = source->s6_addr32[0];
	l64->s6_addr32[1] = source->s6_addr32[1];
	return l64;
}

struct nid *get_nid_from_in6_addr(struct in6_addr *source){
	struct nid *nid;
	nid = kmalloc(sizeof(*nid), GFP_KERNEL);
	nid->s6_addr32[0] = source->s6_addr32[2];
	nid->s6_addr32[1] = source->s6_addr32[3];
	return nid;
}
/*
 *	rcv function (called from netdevice level)
 */

// not used
// int ilnpv6_rcv(struct sk_buff *skb, struct net_device *dev,
//       struct packet_type *pt, struct net_device *orig_dev);

struct sk_buff *__ilnpv6_make_skb(struct sock *sk, struct sk_buff_head *queue,
																																		struct inet_cork_full *cork,
																																		struct inet6_cork *v6_cork);

struct sk_buff *ilnpv6_make_skb(struct sock *sk,
																													int getfrag(void *from, char *to, int offset,
																																									int len, int odd, struct sk_buff *skb),
																													void *from, int length, int transhdrlen,
																													int hlimit, int tclass, struct ipv6_txoptions *opt,
																													struct flowi6 *fl6, struct rt6_info *rt,
																													unsigned int flags, int dontfrag);




static inline struct sk_buff *ilnpv6_finish_skb(struct sock *sk)
{
								return __ip6_make_skb(sk, &sk->sk_write_queue, &inet_sk(sk)->cork,
																														&inet6_sk(sk)->cork);
}

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
								//  (a1->s6_addr32[1] ^ a2->s6_addr32[1]) |
								//  (a1->s6_addr32[2] ^ a2->s6_addr32[2]) |
								//  (a1->s6_addr32[3] ^ a2->s6_addr32[3])) == 0;

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

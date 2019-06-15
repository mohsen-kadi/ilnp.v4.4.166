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


// copied from /net/ipv6/ip6_output.c#L863
static inline int ip6_rt_check(const struct rt6key *rt_key,
                               const struct in6_addr *fl_addr,
                               const struct in6_addr *addr_cache)
{
        return (rt_key->plen != 128 || !ipv6_addr_equal(fl_addr, &rt_key->addr)) &&
               (!addr_cache || !ipv6_addr_equal(fl_addr, addr_cache));
}

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
EXPORT_SYMBOL_GPL(ilnp6_sk_dst_lookup_flow);

static inline int ilnpv6_ufo_append_data(struct sock *sk,
                                         struct sk_buff_head *queue,
                                         int getfrag(void *from, char *to, int offset, int len,
                                                     int odd, struct sk_buff *skb),
                                         void *from, int length, int hh_len, int fragheaderlen,
                                         int exthdrlen, int transhdrlen, int mtu,
                                         unsigned int flags, const struct flowi6 *fl6)

{
        struct sk_buff *skb;
        int err;

        /* There is support for UDP large send offload by network
         * device, so create one single skb packet containing complete
         * udp datagram
         */
        skb = skb_peek_tail(queue);
        if (!skb) {
                skb = sock_alloc_send_skb(sk,
                                          hh_len + fragheaderlen + transhdrlen + 20,
                                          (flags & MSG_DONTWAIT), &err);
                if (!skb)
                        return err;

                /* reserve space for Hardware header */
                skb_reserve(skb, hh_len);

                /* create space for UDP/IP header */
                skb_put(skb, fragheaderlen + transhdrlen);

                /* initialize network header pointer */
                skb_set_network_header(skb, exthdrlen);

                /* initialize protocol header pointer */
                skb->transport_header = skb->network_header + fragheaderlen;

                skb->protocol = htons(ETH_P_IPV6);
                skb->csum = 0;

                __skb_queue_tail(queue, skb);
        } else if (skb_is_gso(skb)) {
                goto append;
        }

        skb->ip_summed = CHECKSUM_PARTIAL;
        /* Specify the length of each IPv6 datagram fragment.
         * It has to be a multiple of 8.
         */
        skb_shinfo(skb)->gso_size = (mtu - fragheaderlen -
                                     sizeof(struct frag_hdr)) & ~7;
        skb_shinfo(skb)->gso_type = SKB_GSO_UDP;
        skb_shinfo(skb)->ip6_frag_id = ipv6_select_ident(sock_net(sk),
                                                         &fl6->daddr,
                                                         &fl6->saddr);

append:
        return skb_append_datato_frags(sk, skb, getfrag, from,
                                       (length - transhdrlen));
}


static inline struct ipv6_opt_hdr *ilnpv6_opt_dup(struct ipv6_opt_hdr *src,
                                                  gfp_t gfp)
{
        return src ? kmemdup(src, (src->hdrlen + 1) * 8, gfp) : NULL;
}

static inline struct ipv6_rt_hdr *ilnpv6_rthdr_dup(struct ipv6_rt_hdr *src,
                                                   gfp_t gfp)
{
        return src ? kmemdup(src, (src->hdrlen + 1) * 8, gfp) : NULL;
}

static void ilnpv6_append_data_mtu(unsigned int *mtu,
                                   int *maxfraglen,
                                   unsigned int fragheaderlen,
                                   struct sk_buff *skb,
                                   struct rt6_info *rt,
                                   unsigned int orig_mtu)
{
        if (!(rt->dst.flags & DST_XFRM_TUNNEL)) {
                if (!skb) {
                        /* first fragment, reserve header_len */
                        *mtu = orig_mtu - rt->dst.header_len;

                } else {
                        /*
                         * this fragment is not first, the headers
                         * space is regarded as data space.
                         */
                        *mtu = orig_mtu;
                }
                *maxfraglen = ((*mtu - fragheaderlen) & ~7)
                              + fragheaderlen - sizeof(struct frag_hdr);
        }
}

static int ilnpv6_setup_cork(struct sock *sk, struct inet_cork_full *cork,
                             struct inet6_cork *v6_cork,
                             int hlimit, int tclass, struct ipv6_txoptions *opt,
                             struct rt6_info *rt, struct flowi6 *fl6)
{
        struct ipv6_pinfo *np = inet6_sk(sk);
        unsigned int mtu;

        /*
         * setup for corking
         */
        if (opt) {
                if (WARN_ON(v6_cork->opt))
                        return -EINVAL;

                v6_cork->opt = kzalloc(sizeof(*opt), sk->sk_allocation);
                if (unlikely(!v6_cork->opt))
                        return -ENOBUFS;

                v6_cork->opt->tot_len = sizeof(*opt);
                v6_cork->opt->opt_flen = opt->opt_flen;
                v6_cork->opt->opt_nflen = opt->opt_nflen;

                v6_cork->opt->dst0opt = ilnpv6_opt_dup(opt->dst0opt,
                                                       sk->sk_allocation);
                if (opt->dst0opt && !v6_cork->opt->dst0opt)
                        return -ENOBUFS;

                v6_cork->opt->dst1opt = ilnpv6_opt_dup(opt->dst1opt,
                                                       sk->sk_allocation);
                if (opt->dst1opt && !v6_cork->opt->dst1opt)
                        return -ENOBUFS;

                v6_cork->opt->hopopt = ilnpv6_opt_dup(opt->hopopt,
                                                      sk->sk_allocation);
                if (opt->hopopt && !v6_cork->opt->hopopt)
                        return -ENOBUFS;

                v6_cork->opt->srcrt = ilnpv6_rthdr_dup(opt->srcrt,
                                                       sk->sk_allocation);
                if (opt->srcrt && !v6_cork->opt->srcrt)
                        return -ENOBUFS;

                /* need source address above miyazawa*/
        }
        dst_hold(&rt->dst);
        cork->base.dst = &rt->dst;
        cork->fl.u.ip6 = *fl6;
        v6_cork->hop_limit = hlimit;
        v6_cork->tclass = tclass;
        if (rt->dst.flags & DST_XFRM_TUNNEL)
                mtu = np->pmtudisc >= IPV6_PMTUDISC_PROBE ?
                      READ_ONCE(rt->dst.dev->mtu) : dst_mtu(&rt->dst);
        else
                mtu = np->pmtudisc >= IPV6_PMTUDISC_PROBE ?
                      READ_ONCE(rt->dst.dev->mtu) : dst_mtu(rt->dst.path);
        if (np->frag_size < mtu) {
                if (np->frag_size)
                        mtu = np->frag_size;
        }
        if (mtu < IPV6_MIN_MTU)
                return -EINVAL;
        cork->base.fragsize = mtu;
        if (dst_allfrag(rt->dst.path))
                cork->base.flags |= IPCORK_ALLFRAG;
        cork->base.length = 0;

        return 0;
}

static int __ilnpv6_append_data(struct sock *sk,
                                struct flowi6 *fl6,
                                struct sk_buff_head *queue,
                                struct inet_cork *cork,
                                struct inet6_cork *v6_cork,
                                struct page_frag *pfrag,
                                int getfrag(void *from, char *to, int offset,
                                            int len, int odd, struct sk_buff *skb),
                                void *from, int length, int transhdrlen,
                                unsigned int flags, int dontfrag)
{
        struct sk_buff *skb, *skb_prev = NULL;
        unsigned int maxfraglen, fragheaderlen, mtu, orig_mtu, pmtu;
        int exthdrlen = 0;
        int dst_exthdrlen = 0;
        int hh_len;
        int copy;
        int err;
        int offset = 0;
        __u8 tx_flags = 0;
        u32 tskey = 0;
        struct rt6_info *rt = (struct rt6_info *)cork->dst;
        struct ipv6_txoptions *opt = v6_cork->opt;
        int csummode = CHECKSUM_NONE;
        unsigned int maxnonfragsize, headersize;

        skb = skb_peek_tail(queue);
        if (!skb) {
                exthdrlen = opt ? opt->opt_flen : 0;
                dst_exthdrlen = rt->dst.header_len - rt->rt6i_nfheader_len;
        }

        mtu = cork->fragsize;
        orig_mtu = mtu;

        hh_len = LL_RESERVED_SPACE(rt->dst.dev);

        fragheaderlen = sizeof(struct ipv6hdr) + rt->rt6i_nfheader_len +
                        (opt ? opt->opt_nflen : 0);
        maxfraglen = ((mtu - fragheaderlen) & ~7) + fragheaderlen -
                     sizeof(struct frag_hdr);

        headersize = sizeof(struct ipv6hdr) +
                     (opt ? opt->opt_flen + opt->opt_nflen : 0) +
                     (dst_allfrag(&rt->dst) ?
                      sizeof(struct frag_hdr) : 0) +
                     rt->rt6i_nfheader_len;

        /* as per RFC 7112 section 5, the entire IPv6 Header Chain must fit
         * the first fragment
         */
        if (headersize + transhdrlen > mtu)
                goto emsgsize;

        if (cork->length + length > mtu - headersize && dontfrag &&
            (sk->sk_protocol == IPPROTO_UDP ||
             sk->sk_protocol == IPPROTO_RAW)) {
                ipv6_local_rxpmtu(sk, fl6, mtu - headersize +
                                  sizeof(struct ipv6hdr));
                goto emsgsize;
        }

        if (ip6_sk_ignore_df(sk))
                maxnonfragsize = sizeof(struct ipv6hdr) + IPV6_MAXPLEN;
        else
                maxnonfragsize = mtu;

        if (cork->length + length > maxnonfragsize - headersize) {
emsgsize:
                pmtu = max_t(int, mtu - headersize + sizeof(struct ipv6hdr), 0);
                ipv6_local_error(sk, EMSGSIZE, fl6, pmtu);
                return -EMSGSIZE;
        }

        /* CHECKSUM_PARTIAL only with no extension headers and when
         * we are not going to fragment
         */
        if (transhdrlen && sk->sk_protocol == IPPROTO_UDP &&
            headersize == sizeof(struct ipv6hdr) &&
            length < mtu - headersize &&
            !(flags & MSG_MORE) &&
            rt->dst.dev->features & NETIF_F_V6_CSUM)
                csummode = CHECKSUM_PARTIAL;

        if (sk->sk_type == SOCK_DGRAM || sk->sk_type == SOCK_RAW) {
                sock_tx_timestamp(sk, &tx_flags);
                if (tx_flags & SKBTX_ANY_SW_TSTAMP &&
                    sk->sk_tsflags & SOF_TIMESTAMPING_OPT_ID)
                        tskey = sk->sk_tskey++;
        }

        /*
         * Let's try using as much space as possible.
         * Use MTU if total length of the message fits into the MTU.
         * Otherwise, we need to reserve fragment header and
         * fragment alignment (= 8-15 octects, in total).
         *
         * Note that we may need to "move" the data from the tail of
         * of the buffer to the new fragment when we split
         * the message.
         *
         * FIXME: It may be fragmented into multiple chunks
         *        at once if non-fragmentable extension headers
         *        are too large.
         * --yoshfuji
         */

        cork->length += length;
        if ((skb && skb_is_gso(skb)) ||
            (((length + (skb ? skb->len : headersize)) > mtu) &&
             (skb_queue_len(queue) <= 1) &&
             (sk->sk_protocol == IPPROTO_UDP) &&
             (rt->dst.dev->features & NETIF_F_UFO) &&
             (sk->sk_type == SOCK_DGRAM) && !udp_get_no_check6_tx(sk))) {
                err = ilnpv6_ufo_append_data(sk, queue, getfrag, from, length,
                                             hh_len, fragheaderlen, exthdrlen,
                                             transhdrlen, mtu, flags, fl6);
                if (err)
                        goto error;
                return 0;
        }

        if (!skb)
                goto alloc_new_skb;

        while (length > 0) {
                /* Check if the remaining data fits into current packet. */
                copy = (cork->length <= mtu && !(cork->flags & IPCORK_ALLFRAG) ? mtu : maxfraglen) - skb->len;
                if (copy < length)
                        copy = maxfraglen - skb->len;

                if (copy <= 0) {
                        char *data;
                        unsigned int datalen;
                        unsigned int fraglen;
                        unsigned int fraggap;
                        unsigned int alloclen;
alloc_new_skb:
                        /* There's no room in the current skb */
                        if (skb)
                                fraggap = skb->len - maxfraglen;
                        else
                                fraggap = 0;
                        /* update mtu and maxfraglen if necessary */
                        if (!skb || !skb_prev)
                                ilnpv6_append_data_mtu(&mtu, &maxfraglen,
                                                       fragheaderlen, skb, rt,
                                                       orig_mtu);

                        skb_prev = skb;

                        /*
                         * If remaining data exceeds the mtu,
                         * we know we need more fragment(s).
                         */
                        datalen = length + fraggap;

                        if (datalen > (cork->length <= mtu && !(cork->flags & IPCORK_ALLFRAG) ? mtu : maxfraglen) - fragheaderlen)
                                datalen = maxfraglen - fragheaderlen - rt->dst.trailer_len;
                        if ((flags & MSG_MORE) &&
                            !(rt->dst.dev->features&NETIF_F_SG))
                                alloclen = mtu;
                        else
                                alloclen = datalen + fragheaderlen;

                        alloclen += dst_exthdrlen;

                        if (datalen != length + fraggap) {
                                /*
                                 * this is not the last fragment, the trailer
                                 * space is regarded as data space.
                                 */
                                datalen += rt->dst.trailer_len;
                        }

                        alloclen += rt->dst.trailer_len;
                        fraglen = datalen + fragheaderlen;

                        /*
                         * We just reserve space for fragment header.
                         * Note: this may be overallocation if the message
                         * (without MSG_MORE) fits into the MTU.
                         */
                        alloclen += sizeof(struct frag_hdr);

                        copy = datalen - transhdrlen - fraggap;
                        if (copy < 0) {
                                err = -EINVAL;
                                goto error;
                        }
                        if (transhdrlen) {
                                skb = sock_alloc_send_skb(sk,
                                                          alloclen + hh_len,
                                                          (flags & MSG_DONTWAIT), &err);
                        } else {
                                skb = NULL;
                                if (atomic_read(&sk->sk_wmem_alloc) <=
                                    2 * sk->sk_sndbuf)
                                        skb = sock_wmalloc(sk,
                                                           alloclen + hh_len, 1,
                                                           sk->sk_allocation);
                                if (unlikely(!skb))
                                        err = -ENOBUFS;
                        }
                        if (!skb)
                                goto error;
                        /*
                         *	Fill in the control structures
                         */
                        skb->protocol = htons(ETH_P_IPV6);
                        skb->ip_summed = csummode;
                        skb->csum = 0;
                        /* reserve for fragmentation and ipsec header */
                        skb_reserve(skb, hh_len + sizeof(struct frag_hdr) +
                                    dst_exthdrlen);

                        /* Only the initial fragment is time stamped */
                        skb_shinfo(skb)->tx_flags = tx_flags;
                        tx_flags = 0;
                        skb_shinfo(skb)->tskey = tskey;
                        tskey = 0;

                        /*
                         *	Find where to start putting bytes
                         */
                        data = skb_put(skb, fraglen);
                        skb_set_network_header(skb, exthdrlen);
                        data += fragheaderlen;
                        skb->transport_header = (skb->network_header +
                                                 fragheaderlen);
                        if (fraggap) {
                                skb->csum = skb_copy_and_csum_bits(
                                        skb_prev, maxfraglen,
                                        data + transhdrlen, fraggap, 0);
                                skb_prev->csum = csum_sub(skb_prev->csum,
                                                          skb->csum);
                                data += fraggap;
                                pskb_trim_unique(skb_prev, maxfraglen);
                        }
                        if (copy > 0 &&
                            getfrag(from, data + transhdrlen, offset,
                                    copy, fraggap, skb) < 0) {
                                err = -EFAULT;
                                kfree_skb(skb);
                                goto error;
                        }

                        offset += copy;
                        length -= datalen - fraggap;
                        transhdrlen = 0;
                        exthdrlen = 0;
                        dst_exthdrlen = 0;

                        /*
                         * Put the packet on the pending queue
                         */
                        __skb_queue_tail(queue, skb);
                        continue;
                }

                if (copy > length)
                        copy = length;

                if (!(rt->dst.dev->features&NETIF_F_SG) &&
                    skb_tailroom(skb) >= copy) {
                        unsigned int off;

                        off = skb->len;
                        if (getfrag(from, skb_put(skb, copy),
                                    offset, copy, off, skb) < 0) {
                                __skb_trim(skb, off);
                                err = -EFAULT;
                                goto error;
                        }
                } else {
                        int i = skb_shinfo(skb)->nr_frags;

                        err = -ENOMEM;
                        if (!sk_page_frag_refill(sk, pfrag))
                                goto error;

                        if (!skb_can_coalesce(skb, i, pfrag->page,
                                              pfrag->offset)) {
                                err = -EMSGSIZE;
                                if (i == MAX_SKB_FRAGS)
                                        goto error;

                                __skb_fill_page_desc(skb, i, pfrag->page,
                                                     pfrag->offset, 0);
                                skb_shinfo(skb)->nr_frags = ++i;
                                get_page(pfrag->page);
                        }
                        copy = min_t(int, copy, pfrag->size - pfrag->offset);
                        if (getfrag(from,
                                    page_address(pfrag->page) + pfrag->offset,
                                    offset, copy, skb->len, skb) < 0)
                                goto error_efault;

                        pfrag->offset += copy;
                        skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
                        skb->len += copy;
                        skb->data_len += copy;
                        skb->truesize += copy;
                        atomic_add(copy, &sk->sk_wmem_alloc);
                }
                offset += copy;
                length -= copy;
        }

        return 0;

error_efault:
        err = -EFAULT;
error:
        cork->length -= length;
        IP6_INC_STATS(sock_net(sk), rt->rt6i_idev, IPSTATS_MIB_OUTDISCARDS);
        return err;
}

static void ilnpv6_cork_release(struct inet_cork_full *cork,
                                struct inet6_cork *v6_cork)
{
        if (v6_cork->opt) {
                kfree(v6_cork->opt->dst0opt);
                kfree(v6_cork->opt->dst1opt);
                kfree(v6_cork->opt->hopopt);
                kfree(v6_cork->opt->srcrt);
                kfree(v6_cork->opt);
                v6_cork->opt = NULL;
        }

        if (cork->base.dst) {
                dst_release(cork->base.dst);
                cork->base.dst = NULL;
                cork->base.flags &= ~IPCORK_ALLFRAG;
        }
        memset(&cork->fl, 0, sizeof(cork->fl));
}

struct sk_buff *__ilnpv6_make_skb(struct sock *sk,
                                  struct sk_buff_head *queue,
                                  struct inet_cork_full *cork,
                                  struct inet6_cork *v6_cork)
{
        struct sk_buff *skb, *tmp_skb;
        struct sk_buff **tail_skb;
        struct in6_addr final_dst_buf, *final_dst = &final_dst_buf;
        struct ipv6_pinfo *np = inet6_sk(sk);
        struct net *net = sock_net(sk);
        struct ipv6hdr *hdr;
        struct ipv6_txoptions *opt = v6_cork->opt;
        struct rt6_info *rt = (struct rt6_info *)cork->base.dst;
        struct flowi6 *fl6 = &cork->fl.u.ip6;
        unsigned char proto = fl6->flowi6_proto;

        skb = __skb_dequeue(queue);
        if (!skb)
                goto out;
        tail_skb = &(skb_shinfo(skb)->frag_list);

        /* move skb->data to ip header from ext header */
        if (skb->data < skb_network_header(skb))
                __skb_pull(skb, skb_network_offset(skb));
        while ((tmp_skb = __skb_dequeue(queue)) != NULL) {
                __skb_pull(tmp_skb, skb_network_header_len(skb));
                *tail_skb = tmp_skb;
                tail_skb = &(tmp_skb->next);
                skb->len += tmp_skb->len;
                skb->data_len += tmp_skb->len;
                skb->truesize += tmp_skb->truesize;
                tmp_skb->destructor = NULL;
                tmp_skb->sk = NULL;
        }

        /* Allow local fragmentation. */
        skb->ignore_df = ip6_sk_ignore_df(sk);

        *final_dst = fl6->daddr;
        __skb_pull(skb, skb_network_header_len(skb));
        if (opt && opt->opt_flen)
                ipv6_push_frag_opts(skb, opt, &proto);
        if (opt && opt->opt_nflen)
                ipv6_push_nfrag_opts(skb, opt, &proto, &final_dst);

        skb_push(skb, sizeof(struct ipv6hdr));
        skb_reset_network_header(skb);
        hdr = ipv6_hdr(skb);

        ip6_flow_hdr(hdr, v6_cork->tclass,
                     ip6_make_flowlabel(net, skb, fl6->flowlabel,
                                        ip6_autoflowlabel(net, np), fl6));
        hdr->hop_limit = v6_cork->hop_limit;
        hdr->nexthdr = proto;
        hdr->saddr = fl6->saddr;
        hdr->daddr = *final_dst;

        skb->priority = sk->sk_priority;
        skb->mark = sk->sk_mark;

        skb_dst_set(skb, dst_clone(&rt->dst));
        IP6_UPD_PO_STATS(net, rt->rt6i_idev, IPSTATS_MIB_OUT, skb->len);
        if (proto == IPPROTO_ICMPV6) {
                struct inet6_dev *idev = ip6_dst_idev(skb_dst(skb));

                ICMP6MSGOUT_INC_STATS(net, idev, icmp6_hdr(skb)->icmp6_type);
                ICMP6_INC_STATS(net, idev, ICMP6_MIB_OUTMSGS);
        }

        ilnpv6_cork_release(cork, v6_cork);
out:
        return skb;
}

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

static void __ilnpv6_flush_pending_frames(struct sock *sk,
                                          struct sk_buff_head *queue,
                                          struct inet_cork_full *cork,
                                          struct inet6_cork *v6_cork)
{
        struct sk_buff *skb;

        while ((skb = __skb_dequeue_tail(queue)) != NULL) {
                if (skb_dst(skb))
                        IP6_INC_STATS(sock_net(sk), ip6_dst_idev(skb_dst(skb)),
                                      IPSTATS_MIB_OUTDISCARDS);
                kfree_skb(skb);
        }

        ilnpv6_cork_release(cork, v6_cork);
}

struct sk_buff *ilnpv6_make_skb(struct sock *sk,
                                int getfrag(void *from, char *to, int offset,
                                            int len, int odd, struct sk_buff *skb),
                                void *from, int length, int transhdrlen,
                                int hlimit, int tclass,
                                struct ipv6_txoptions *opt, struct flowi6 *fl6,
                                struct rt6_info *rt, unsigned int flags,
                                int dontfrag)
{
        struct inet_cork_full cork;
        struct inet6_cork v6_cork;
        struct sk_buff_head queue;
        int exthdrlen = (opt ? opt->opt_flen : 0);
        int err;

        if (flags & MSG_PROBE)
                return NULL;

        __skb_queue_head_init(&queue);

        cork.base.flags = 0;
        cork.base.addr = 0;
        cork.base.opt = NULL;
        cork.base.dst = NULL;
        v6_cork.opt = NULL;
        err = ilnpv6_setup_cork(sk, &cork, &v6_cork, hlimit, tclass, opt, rt, fl6);
        if (err) {
                ilnpv6_cork_release(&cork, &v6_cork);
                return ERR_PTR(err);
        }

        if (dontfrag < 0)
                dontfrag = inet6_sk(sk)->dontfrag;

        err = __ilnpv6_append_data(sk, fl6, &queue, &cork.base, &v6_cork,
                                   &current->task_frag, getfrag, from,
                                   length + exthdrlen, transhdrlen + exthdrlen,
                                   flags, dontfrag);
        if (err) {
                __ilnpv6_flush_pending_frames(sk, &queue, &cork, &v6_cork);
                return ERR_PTR(err);
        }

        return __ilnpv6_make_skb(sk, &queue, &cork, &v6_cork);
}

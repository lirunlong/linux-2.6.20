/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for inet_sock
 *
 * Authors:	Many, reorganised here by
 * 		Arnaldo Carvalho de Melo <acme@mandriva.com>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _INET_SOCK_H
#define _INET_SOCK_H


#include <linux/string.h>
#include <linux/types.h>

#include <net/flow.h>
#include <net/sock.h>
#include <net/request_sock.h>

/** struct ip_options - IP Options
 *
 * @faddr - Saved first hop address
 * @is_data - Options in __data, rather than skb
 * @is_strictroute - Strict source route
 * @srr_is_hit - Packet destination addr was our one
 * @is_changed - IP checksum more not valid
 * @rr_needaddr - Need to record addr of outgoing dev
 * @ts_needtime - Need to record timestamp
 * @ts_needaddr - Need to record addr of outgoing dev
 */
struct ip_options {
	__be32		faddr;
	unsigned char	optlen;
	unsigned char	srr;
	unsigned char	rr;
	unsigned char	ts;
	unsigned char	is_data:1,
			is_strictroute:1,
			srr_is_hit:1,
			is_changed:1,
			rr_needaddr:1,
			ts_needtime:1,
			ts_needaddr:1;
	unsigned char	router_alert;
	unsigned char	cipso;
	unsigned char	__pad2;
	unsigned char	__data[0];
};

#define optlength(opt) (sizeof(struct ip_options) + opt->optlen)

struct inet_request_sock {
	struct request_sock	req;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	u16			inet6_rsk_offset;
	/* 2 bytes hole, try to pack */
#endif
	__be32			loc_addr;
	__be32			rmt_addr;
	__be16			rmt_port;
	u16			snd_wscale : 4, 
				rcv_wscale : 4, 
				tstamp_ok  : 1,
				sack_ok	   : 1,
				wscale_ok  : 1,
				ecn_ok	   : 1,
				acked	   : 1;
	struct ip_options	*opt;
};

static inline struct inet_request_sock *inet_rsk(const struct request_sock *sk)
{
	return (struct inet_request_sock *)sk;
}

struct ip_mc_socklist;
struct ipv6_pinfo;
struct rtable;

/** struct inet_sock - representation of INET sockets
 *
 * @sk - ancestor class
 * @pinet6 - pointer to IPv6 control block
 * @daddr - Foreign IPv4 addr
 * @rcv_saddr - Bound local IPv4 addr
 * @dport - Destination port
 * @num - Local port
 * @saddr - Sending source
 * @uc_ttl - Unicast TTL
 * @sport - Source port
 * @id - ID counter for DF pkts
 * @tos - TOS
 * @mc_ttl - Multicasting TTL
 * @is_icsk - is this an inet_connection_sock?
 * @mc_index - Multicast device index
 * @mc_list - Group array
 * @cork - info to build ip hdr on each ip frag while socket is corked
 */
struct inet_sock {
	/* sk and pinet6 has to be the first two members of inet_sock */
	struct sock		sk;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	/*如果支持ipv6，pinet6指向ipv6控制块*/
	struct ipv6_pinfo	*pinet6;
#endif
	/* Socket demultiplex comparisons on incoming packets. */
	/*目的ip地址*/
	__be32			daddr;
	/*已绑定的本地ip地址,接受数据时，作为条件的一部分，查找所属的传输控制块*/
	__be32			rcv_saddr;
	/*目的端口*/
	__be16			dport;
	/*主机字节序存储的本地端口*/
	__u16			num;
	/*标识本地ip地址，在发送数据时使用。saddr和rcv_addr都标识本地ip地址，用途不同*/
	__be32			saddr;
	/*单播报文的TTL，默认值是-1，表示使用默认的TTL值，在输出数据包时，TTL值先从这里获取，如果没有设置，则从路由缓存的metric获取*/
	__s16			uc_ttl;
	/*存放一些IPPROTO_IP级别的选项值，可能的取值为IP_CMSG_PKTINFO等*/
	__u16			cmsg_flags;
	/*指向ip数据包选项的指针*/
	struct ip_options	*opt;
	/*由num转换的网络字节需的源端口*/
	__be16			sport;
	/*一个单调递增的值，用来赋给ip首部的id域*/
	__u16			id;
	/*用于设置ip数据包首部的tos域*/
	__u8			tos;
	/*用于设置多播数据包的ttl*/
	__u8			mc_ttl;
	/*标识套接口是否启用路径MTU发现功能，初始值是根据系统控制参数ip_no_pmtu_disc来确定*/
	__u8			pmtudisc;
	/*标识是否允许接收扩展的可靠错误信息*/
	__u8			recverr:1,
					/*是否是链接套接字*/
				is_icsk:1,
				/*标识是否允许绑定非主机地址*/
				freebind:1,
				/*标识ip首部是否由用户数据构建*/
				hdrincl:1,
				/*标识组播是否发向回路*/
				mc_loop:1;
	/*发送组播报文的网络设备索引号，如果为0 ，则可以从任何接口发送*/
	int			mc_index;
	/*发送组播报文的源地址*/
	__be32			mc_addr;
	/*所在的套接口加入的组播地址列表*/
	struct ip_mc_socklist	*mc_list;
	/*udp或原始ip在每次发送时缓存的一些临时信息，如udp和原始ip数据包分片的大小*/
	struct {
		/*IPCORK_OPT:标识ip选项是否已在cork的opt成员中
		 *IPCORK_ALLFRAG:总是分片*/
		unsigned int		flags;
		/*udp数据包和原始ip数据包分片的大小*/
		unsigned int		fragsize;
		/*指向此次发送数据包的ip选项*/
		struct ip_options	*opt;
		/*发送数据包使用的输出路由缓存项*/
		struct rtable		*rt;
		/*当前发送的数据包的数据长度*/
		int			length; /* Total length of all frames */
		/*输出ip数据包的目的地址*/
		__be32			addr;
		/*拥flowi来缓存目的地址，目的端口，源地址，源端口，构造udp报文时，有关信息就取自这里*/
		struct flowi		fl;
	} cork;
};

#define IPCORK_OPT	1	/* ip-options has been held in ipcork.opt */
#define IPCORK_ALLFRAG	2	/* always fragment (for ipv6 for now) */

static inline struct inet_sock *inet_sk(const struct sock *sk)
{
	return (struct inet_sock *)sk;
}

static inline void __inet_sk_copy_descendant(struct sock *sk_to,
					     const struct sock *sk_from,
					     const int ancestor_size)
{
	memcpy(inet_sk(sk_to) + 1, inet_sk(sk_from) + 1,
	       sk_from->sk_prot->obj_size - ancestor_size);
}
#if !(defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE))
static inline void inet_sk_copy_descendant(struct sock *sk_to,
					   const struct sock *sk_from)
{
	__inet_sk_copy_descendant(sk_to, sk_from, sizeof(struct inet_sock));
}
#endif

extern int inet_sk_rebuild_header(struct sock *sk);

static inline unsigned int inet_ehashfn(const __be32 laddr, const __u16 lport,
					const __be32 faddr, const __be16 fport)
{
	unsigned int h = ((__force __u32)laddr ^ lport) ^ ((__force __u32)faddr ^ (__force __u32)fport);
	h ^= h >> 16;
	h ^= h >> 8;
	return h;
}

static inline int inet_sk_ehashfn(const struct sock *sk)
{
	const struct inet_sock *inet = inet_sk(sk);
	const __be32 laddr = inet->rcv_saddr;
	const __u16 lport = inet->num;
	const __be32 faddr = inet->daddr;
	const __be16 fport = inet->dport;

	return inet_ehashfn(laddr, lport, faddr, fport);
}

#endif	/* _INET_SOCK_H */

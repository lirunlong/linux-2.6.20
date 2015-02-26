/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the protocol dispatcher.
 *
 * Version:	@(#)protocol.h	1.0.2	05/07/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *	Changes:
 *		Alan Cox	:	Added a name field and a frag handler
 *					field for later.
 *		Alan Cox	:	Cleaned up, and sorted types.
 *		Pedro Roque	:	inet6 protocols
 */
 
#ifndef _PROTOCOL_H
#define _PROTOCOL_H

#include <linux/in6.h>
#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
#include <linux/ipv6.h>
#endif

#define MAX_INET_PROTOS	256		/* Must be a power of 2		*/


/* This is used to register protocols. */
/*网络层向上投递数据包时，会调用这个接口的历程，udp,tcp icmp,igmp*/
struct net_protocol {
	/*传输层协议数据包处理函数，当网络层接受ip数据包后，会根据ip数据包中的传输层协议，调用对应的传输层的net_protocol实例
	 *tcp:tcp_v4_rcv
	 *udp:udp_rcv
	 *icmp:icmp_rcv
	 *igmp:igmp_rcv
	 */
	int			(*handler)(struct sk_buff *skb);
	/*
	 *当icmp模块接受到差错报文后，解析差错报文，根据差错报文中原始的ip首部，调用对应的传输层异常处理函数
	 *tcp:tcp_v4_err()
	 *udp: udp_err()
	 */
	void			(*err_handler)(struct sk_buff *skb, u32 info);
	/*
	 *gso是网络设备支持传输层的一个功能。
	 *当gso数据包输出时到达网络设备，如果网络设备不支持gso的情况，则需要传输层对输出的数据包重新进行gso分段和校验和的计算，
	 * 因此需要网络层提供给设备层，能够访问传输层的gso分段和能够计算校验和的功能，对输出的数据包进行分段和执行校验和
	 * gso_send_check:分段之前对伪首部进行校验和的计算
	 * gso_segment:对大段进行分段
	 * tcp实现函数为：tcp_v4_gso_send_check(skb)  tcp_tso_segment(skb,features)  
	 * udp 不支持gso
	 */
	int			(*gso_send_check)(struct sk_buff *skb);
	struct sk_buff	       *(*gso_segment)(struct sk_buff *skb,
					       int features);
	/*在路由时，是否进行策略路由，tcp和udp默认不进行策略路由*/
	int			no_policy;
};

#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
struct inet6_protocol 
{
	int	(*handler)(struct sk_buff **skb);

	void	(*err_handler)(struct sk_buff *skb,
			       struct inet6_skb_parm *opt,
			       int type, int code, int offset,
			       __be32 info);

	int	(*gso_send_check)(struct sk_buff *skb);
	struct sk_buff *(*gso_segment)(struct sk_buff *skb,
				       int features);

	unsigned int	flags;	/* INET6_PROTO_xxx */
};

#define INET6_PROTO_NOPOLICY	0x1
#define INET6_PROTO_FINAL	0x2
/* This should be set for any extension header which is compatible with GSO. */
#define INET6_PROTO_GSO_EXTHDR	0x4
#endif

/* This is used to register socket interfaces for IP protocols.  */
struct inet_protosw {
	struct list_head list;

        /* These two fields form the lookup key.  */
	unsigned short	 type;	   /* This is the 2nd argument to socket(2). */
	/*IPPROTO_TCP  IPPROTO_UDP*/
	unsigned short	 protocol; /* This is the L4 protocol number.  */

	/*与网络层接口*/
	struct proto	 *prot;
	/*与传输层接口*/
	const struct proto_ops *ops;
  
	/*当>0时，需要检查是否由权能，tcp,udp 均为-1 代表不需要检查*/
	int              capability; /* Which (if any) capability do
				      * we need to use this socket
				      * interface?
                                      */
	/*
	 * tcp为0  需要执行校验和
	 * raw和udp值为：
	 * UDP_CSUM_NOXMIT: 表示在发送时不做校验和
	 * UDP_CSUM_NORCV: 表示在接收时不做校验和
	 * UDP_CSUM_DEFAULT:表示进行正常的校验和操作
	 **/
	char             no_check;   /* checksum on rcv/xmit/none? */
	/*
	 * 初始化传输控制块的is_icsk成员
	 * INET_PROTOSW_REUSE:标识端口是否能被重用
	 * INET_PROTOSW_PERMANENT:标识此协议不能替换和卸载
	 * INET_PROTOSW_ICSK:标识是否是连接类型的套接口
	 * */
	unsigned char	 flags;      /* See INET_PROTOSW_* below.  */
};
#define INET_PROTOSW_REUSE 0x01	     /* Are ports automatically reusable? */
#define INET_PROTOSW_PERMANENT 0x02  /* Permanent protocols are unremovable. */
#define INET_PROTOSW_ICSK      0x04  /* Is this an inet_connection_sock? */

extern struct net_protocol *inet_protocol_base;
extern struct net_protocol *inet_protos[MAX_INET_PROTOS];

#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
extern struct inet6_protocol *inet6_protos[MAX_INET_PROTOS];
#endif

extern int	inet_add_protocol(struct net_protocol *prot, unsigned char num);
extern int	inet_del_protocol(struct net_protocol *prot, unsigned char num);
extern void	inet_register_protosw(struct inet_protosw *p);
extern void	inet_unregister_protosw(struct inet_protosw *p);

#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
extern int	inet6_add_protocol(struct inet6_protocol *prot, unsigned char num);
extern int	inet6_del_protocol(struct inet6_protocol *prot, unsigned char num);
extern void	inet6_register_protosw(struct inet_protosw *p);
extern void	inet6_unregister_protosw(struct inet_protosw *p);
#endif

#endif	/* _PROTOCOL_H */

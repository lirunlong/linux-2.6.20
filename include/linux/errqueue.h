#ifndef _LINUX_ERRQUEUE_H
#define _LINUX_ERRQUEUE_H 1

struct sock_extended_err
{
	/*出错信息的错误码*/
	__u32	ee_errno;	
	/*标识出错信息的来源，
	 * SO_EE_ORIGIN_LOCAL:出错信息来自本地
	 * SO_EE_ORIGIN_ICMP:出错信息来自icmp消息
	 * */
	__u8	ee_origin;
	/*在出错信息来自icmp消息情况下，标识icmp差错消息的类型，其他情况均为0*/
	__u8	ee_type;
	/*在出错信息来自icmp消息情况下，标识icmp差错消息的编码，其他来源均为0*/
	__u8	ee_code;
	/*reseverd 0*/
	__u8	ee_pad;
	/*出错信息的扩展信息，其意义随出错信息的错误码具体而定。例如：当接受到目的不可达需要分片差错信息时，则为吓一跳的MTU*/
	__u32   ee_info;
	/*未使用，填充为0*/
	__u32   ee_data;
};

#define SO_EE_ORIGIN_NONE	0
#define SO_EE_ORIGIN_LOCAL	1
#define SO_EE_ORIGIN_ICMP	2
#define SO_EE_ORIGIN_ICMP6	3

#define SO_EE_OFFENDER(ee)	((struct sockaddr*)((ee)+1))

#ifdef __KERNEL__

#include <net/ip.h>
#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
#include <linux/ipv6.h>
#endif

#define SKB_EXT_ERR(skb) ((struct sock_exterr_skb *) ((skb)->cb))

struct sock_exterr_skb
{
	union {
		struct inet_skb_parm	h4;
#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
		struct inet6_skb_parm	h6;
#endif
	} header;
	struct sock_extended_err	ee;
	/*导致出错的原始数据包的目的地址在负载的icmp报文的ip数据包中的偏移量*/
	u16				addr_offset;
	/*对于udp  是出错报文的目的端口，其他情况则为0*/
	__be16				port;
};

#endif

#endif

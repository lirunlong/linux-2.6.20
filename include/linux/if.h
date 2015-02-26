/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Global definitions for the INET interface module.
 *
 * Version:	@(#)if.h	1.0.2	04/18/93
 *
 * Authors:	Original taken from Berkeley UNIX 4.3, (c) UCB 1982-1988
 *		Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_IF_H
#define _LINUX_IF_H

#include <linux/types.h>		/* for "__kernel_caddr_t" et al	*/
#include <linux/socket.h>		/* for "struct sockaddr" et al	*/
#include <linux/compiler.h>		/* for "__user" et al           */

#define	IFNAMSIZ	16
#include <linux/hdlc/ioctl.h>

/* Standard interface flags (netdevice->flags). */
/*该接口激活并且可以传输数据包*/
#define	IFF_UP		0x1		/* interface is up		*/
/*表示该接口允许广播*/
#define	IFF_BROADCAST	0x2		/* broadcast address valid	*/
/*该标志可以用来控制用于调试目的的大量printk调用，用户程序可以通过ioctl设置次标志*/
#define	IFF_DEBUG	0x4		/* turn on debugging		*/
/*根据次标志判断是否是回环设备，而不是根据"lo"名称来判断*/
#define	IFF_LOOPBACK	0x8		/* is a loopback net		*/
/*表明设备连接到点对点链路，此标志可有驱动程序设置，或者ifconfig设置， 如果ppp驱动程序设置该标志*/
#define	IFF_POINTOPOINT	0x10		/* interface is has p-p link	*/
/*linux未使用该标志， 兼容bsd*/
#define	IFF_NOTRAILERS	0x20		/* avoid use of trailers	*/
#define	IFF_RUNNING	0x40		/* interface RFC2863 OPER_UP	*/
/*表明该接口不支持arp协议，例如点对点接口，如果运行arp 不但不能获得有用信息，反而增加网络传输量*/
#define	IFF_NOARP	0x80		/* no ARP protocol		*/
#define	IFF_PROMISC	0x100		/* receive all packets		*/
/*告诉接口接受所有的组播数据包，仅在设置IFF_MULTICAST设置时，内核在主机执行组播路由时设置该标志，对接口来讲 这个标志是只读的 */
#define	IFF_ALLMULTI	0x200		/* receive all multicast packets*/

/*主负载均衡群*/
#define IFF_MASTER	0x400		/* master of a load balancer 	*/
/*负载均衡代码使用，接口驱动程序无需了解该标志*/
#define IFF_SLAVE	0x800		/* slave of a load balancer	*/

/*该标志由驱动程序设置，表明该接口支持组播发送,ether_setup默认设置此标志，如果驱动程序不支持组播，需要在初始化时清除该标志*/
#define IFF_MULTICAST	0x1000		/* Supports multicast		*/

/*通过ifmap选择介质类型*/
#define IFF_PORTSEL	0x2000          /* can set media type		*/
/*设备能够在多种介质类型之间切换,例如非屏蔽双绞线或同轴电缆以太网之间，
 * 如果IFF_AUTOMEDIA标志设置，设备会自动选择介质类型，实际情况中貌似未用该标志*/
#define IFF_AUTOMEDIA	0x4000		/* auto media select active	*/
/*该标志由驱动程序使用，表示接口可改变地址，这标志没有被使用，接口关闭时丢弃地址。*/
#define IFF_DYNAMIC	0x8000		/* dialup device with changing addresses*/

/*该标志表示接口接口已经启动并正在运行*/
#define IFF_LOWER_UP	0x10000		/* driver signals L1 up		*/
#define IFF_DORMANT	0x20000		/* driver signals dormant	*/

#define IFF_VOLATILE	(IFF_LOOPBACK|IFF_POINTOPOINT|IFF_BROADCAST|\
		IFF_MASTER|IFF_SLAVE|IFF_RUNNING|IFF_LOWER_UP|IFF_DORMANT)

/* Private (from user) interface flags (netdevice->priv_flags). */
/*标识一个802.1q VLAN设备*/
#define IFF_802_1Q_VLAN 0x1             /* 802.1Q VLAN device.          */
/*以太网桥设备*/
#define IFF_EBRIDGE	0x2		/* Ethernet bridging device.	*/
/*标识bonding的slave设备当前未激活*/
#define IFF_SLAVE_INACTIVE	0x4	/* bonding slave not the curr. active */
/*表示bonding的802.3ad模式*/
#define IFF_MASTER_8023AD	0x8	/* bonding master, 802.3ad. 	*/
/*表示bonding的balance-alb模式*/
#define IFF_MASTER_ALB	0x10		/* bonding master, balance-alb.	*/
/*标识是bonding的master或slave设备*/
#define IFF_BONDING	0x20		/* bonding master or slave	*/
/*表示bonding的slave设备支持arp*/
#define IFF_SLAVE_NEEDARP 0x40		/* need ARPs for validation	*/

#define IF_GET_IFACE	0x0001		/* for querying only */
#define IF_GET_PROTO	0x0002

/* For definitions see hdlc.h */
#define IF_IFACE_V35	0x1000		/* V.35 serial interface	*/
#define IF_IFACE_V24	0x1001		/* V.24 serial interface	*/
#define IF_IFACE_X21	0x1002		/* X.21 serial interface	*/
#define IF_IFACE_T1	0x1003		/* T1 telco serial interface	*/
#define IF_IFACE_E1	0x1004		/* E1 telco serial interface	*/
#define IF_IFACE_SYNC_SERIAL 0x1005	/* can't be set by software	*/
#define IF_IFACE_X21D   0x1006          /* X.21 Dual Clocking (FarSite) */

/* For definitions see hdlc.h */
#define IF_PROTO_HDLC	0x2000		/* raw HDLC protocol		*/
#define IF_PROTO_PPP	0x2001		/* PPP protocol			*/
#define IF_PROTO_CISCO	0x2002		/* Cisco HDLC protocol		*/
#define IF_PROTO_FR	0x2003		/* Frame Relay protocol		*/
#define IF_PROTO_FR_ADD_PVC 0x2004	/*    Create FR PVC		*/
#define IF_PROTO_FR_DEL_PVC 0x2005	/*    Delete FR PVC		*/
#define IF_PROTO_X25	0x2006		/* X.25				*/
#define IF_PROTO_HDLC_ETH 0x2007	/* raw HDLC, Ethernet emulation	*/
#define IF_PROTO_FR_ADD_ETH_PVC 0x2008	/*  Create FR Ethernet-bridged PVC */
#define IF_PROTO_FR_DEL_ETH_PVC 0x2009	/*  Delete FR Ethernet-bridged PVC */
#define IF_PROTO_FR_PVC	0x200A		/* for reading PVC status	*/
#define IF_PROTO_FR_ETH_PVC 0x200B
#define IF_PROTO_RAW    0x200C          /* RAW Socket                   */

/* RFC 2863 operational status */
enum {
	IF_OPER_UNKNOWN,
	IF_OPER_NOTPRESENT,
	IF_OPER_DOWN,
	IF_OPER_LOWERLAYERDOWN,
	IF_OPER_TESTING,
	IF_OPER_DORMANT,
	IF_OPER_UP,
};

/* link modes */
enum {
	IF_LINK_MODE_DEFAULT,
	IF_LINK_MODE_DORMANT,	/* limit upward transition to dormant */
};

/*
 *	Device mapping structure. I'd just gone off and designed a 
 *	beautiful scheme using only loadable modules with arguments
 *	for driver options and along come the PCMCIA people 8)
 *
 *	Ah well. The get() side of this is good for WDSETUP, and it'll
 *	be handy for debugging things. The set side is fine for now and
 *	being very small might be worth keeping for clean configuration.
 */

struct ifmap 
{
	unsigned long mem_start;
	unsigned long mem_end;
	unsigned short base_addr; 
	unsigned char irq;
	unsigned char dma;
	unsigned char port;
	/* 3 bytes spare */
};

struct if_settings
{
	unsigned int type;	/* Type of physical device or protocol */
	unsigned int size;	/* Size of the data allocated by the caller */
	union {
		/* {atm/eth/dsl}_settings anyone ? */
		raw_hdlc_proto		__user *raw_hdlc;
		cisco_proto		__user *cisco;
		fr_proto		__user *fr;
		fr_proto_pvc		__user *fr_pvc;
		fr_proto_pvc_info	__user *fr_pvc_info;

		/* interface settings */
		sync_serial_settings	__user *sync;
		te1_settings		__user *te1;
	} ifs_ifsu;
};

/*
 * Interface request structure used for socket
 * ioctl's.  All interface ioctl's must have parameter
 * definitions which begin with ifr_name.  The
 * remainder may be interface specific.
 */

struct ifreq 
{
#define IFHWADDRLEN	6
	union
	{
		char	ifrn_name[IFNAMSIZ];		/* if name, e.g. "en0" */
	} ifr_ifrn;
	
	union {
		/*用来获取或设置网络设备的广播地址，点对点对端地址，本地地址，以及网络掩码*/
		struct	sockaddr ifru_addr;
		/*下面3个字段目前未使用*/
		struct	sockaddr ifru_dstaddr;
		struct	sockaddr ifru_broadaddr;
		struct	sockaddr ifru_netmask;
		/*用来获取或设置网络设备的硬件地址*/
		struct  sockaddr ifru_hwaddr;
		/*用来获取或设置网络设备的标志*/
		short	ifru_flags;
		/*通过ioctl()获取或设置网络设备的操作时，标识网络设备的索引号，网络设备输出队列的长度*/
		int	ifru_ivalue;
		/*用来获取或设置网络设备的MTU*/
		int	ifru_mtu;
		/*用来获取网络设备的硬件参数，与net_device的mem_start,mem_end,base_addr,irq,dma,if_port相对应*/
		struct  ifmap ifru_map;
		char	ifru_slave[IFNAMSIZ];	/* Just fits the size */
		/*用于设置网络设备新的名称*/
		char	ifru_newname[IFNAMSIZ];
		/*在执行SIOCETHTOOL命令时，根据不同的子命令对应不同的结构*/
		void __user *	ifru_data;
		/*用来设置相关设备及协议，如高级链路控制(HDLC)等*/
		struct	if_settings ifru_settings;
	} ifr_ifru;
};

#define ifr_name	ifr_ifrn.ifrn_name	/* interface name 	*/
#define ifr_hwaddr	ifr_ifru.ifru_hwaddr	/* MAC address 		*/
#define	ifr_addr	ifr_ifru.ifru_addr	/* address		*/
#define	ifr_dstaddr	ifr_ifru.ifru_dstaddr	/* other end of p-p lnk	*/
#define	ifr_broadaddr	ifr_ifru.ifru_broadaddr	/* broadcast address	*/
#define	ifr_netmask	ifr_ifru.ifru_netmask	/* interface net mask	*/
#define	ifr_flags	ifr_ifru.ifru_flags	/* flags		*/
#define	ifr_metric	ifr_ifru.ifru_ivalue	/* metric		*/
#define	ifr_mtu		ifr_ifru.ifru_mtu	/* mtu			*/
#define ifr_map		ifr_ifru.ifru_map	/* device map		*/
#define ifr_slave	ifr_ifru.ifru_slave	/* slave device		*/
#define	ifr_data	ifr_ifru.ifru_data	/* for use by interface	*/
#define ifr_ifindex	ifr_ifru.ifru_ivalue	/* interface index	*/
#define ifr_bandwidth	ifr_ifru.ifru_ivalue    /* link bandwidth	*/
#define ifr_qlen	ifr_ifru.ifru_ivalue	/* Queue length 	*/
#define ifr_newname	ifr_ifru.ifru_newname	/* New name		*/
#define ifr_settings	ifr_ifru.ifru_settings	/* Device/proto settings*/

/*
 * Structure used in SIOCGIFCONF request.
 * Used to retrieve interface configuration
 * for machine (useful for programs which
 * must know all networks accessible).
 */

struct ifconf 
{
	int	ifc_len;			/* size of buffer	*/
	union 
	{
		char __user *ifcu_buf;
		struct ifreq __user *ifcu_req;
	} ifc_ifcu;
};
#define	ifc_buf	ifc_ifcu.ifcu_buf		/* buffer address	*/
#define	ifc_req	ifc_ifcu.ifcu_req		/* array of structures	*/

#endif /* _LINUX_IF_H */

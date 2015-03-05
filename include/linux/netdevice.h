/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the Interfaces handler.
 *
 * Version:	@(#)dev.h	1.0.10	08/12/93
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Donald J. Becker, <becker@cesdis.gsfc.nasa.gov>
 *		Alan Cox, <Alan.Cox@linux.org>
 *		Bjorn Ekwall. <bj0rn@blox.se>
 *              Pekka Riikonen <priikone@poseidon.pspt.fi>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *		Moved to /usr/include/linux for NET3
 */
#ifndef _LINUX_NETDEVICE_H
#define _LINUX_NETDEVICE_H

#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#ifdef __KERNEL__
#include <linux/timer.h>
#include <asm/atomic.h>
#include <asm/cache.h>
#include <asm/byteorder.h>

#include <linux/device.h>
#include <linux/percpu.h>
#include <linux/dmaengine.h>

struct vlan_group;
struct ethtool_ops;
struct netpoll_info;
					/* source back-compat hooks */
#define SET_ETHTOOL_OPS(netdev,ops) \
	( (netdev)->ethtool_ops = (ops) )

#define HAVE_ALLOC_NETDEV		/* feature macro: alloc_xxxdev
					   functions are available. */
#define HAVE_FREE_NETDEV		/* free_netdev() */
#define HAVE_NETDEV_PRIV		/* netdev_priv() */

#define NET_XMIT_SUCCESS	0
#define NET_XMIT_DROP		1	/* skb dropped			*/
#define NET_XMIT_CN		2	/* congestion notification	*/
#define NET_XMIT_POLICED	3	/* skb is shot by police	*/
#define NET_XMIT_BYPASS		4	/* packet does not leave via dequeue;
					   (TC use only - dev_queue_xmit
					   returns this as NET_XMIT_SUCCESS) */

/* Backlog congestion levels */
#define NET_RX_SUCCESS		0   /* keep 'em coming, baby */
#define NET_RX_DROP		1  /* packet dropped */
#define NET_RX_CN_LOW		2   /* storm alert, just in case */
#define NET_RX_CN_MOD		3   /* Storm on its way! */
#define NET_RX_CN_HIGH		4   /* The storm is here */
#define NET_RX_BAD		5  /* packet dropped due to kernel error */

/* NET_XMIT_CN is special. It does not guarantee that this packet is lost. It
 * indicates that the device will soon be dropping packets, or already drops
 * some packets of the same priority; prompting us to send less aggressively. */
#define net_xmit_eval(e)	((e) == NET_XMIT_CN? 0 : (e))
#define net_xmit_errno(e)	((e) != NET_XMIT_CN ? -ENOBUFS : 0)

#endif

#define MAX_ADDR_LEN	32		/* Largest hardware address length */

/* Driver transmit return codes */
#define NETDEV_TX_OK 0		/* driver took care of packet */
#define NETDEV_TX_BUSY 1	/* driver tx path was busy*/
#define NETDEV_TX_LOCKED -1	/* driver tx lock was already taken */

/*
 *	Compute the worst case header length according to the protocols
 *	used.
 */
 
#if !defined(CONFIG_AX25) && !defined(CONFIG_AX25_MODULE) && !defined(CONFIG_TR)
#define LL_MAX_HEADER	32
#else
#if defined(CONFIG_AX25) || defined(CONFIG_AX25_MODULE)
#define LL_MAX_HEADER	96
#else
#define LL_MAX_HEADER	48
#endif
#endif

#if !defined(CONFIG_NET_IPIP) && !defined(CONFIG_NET_IPIP_MODULE) && \
    !defined(CONFIG_NET_IPGRE) &&  !defined(CONFIG_NET_IPGRE_MODULE) && \
    !defined(CONFIG_IPV6_SIT) && !defined(CONFIG_IPV6_SIT_MODULE) && \
    !defined(CONFIG_IPV6_TUNNEL) && !defined(CONFIG_IPV6_TUNNEL_MODULE)
#define MAX_HEADER LL_MAX_HEADER
#else
#define MAX_HEADER (LL_MAX_HEADER + 48)
#endif

/*
 *	Network device statistics. Akin to the 2.0 ether stats but
 *	with byte counters.
 */
 
struct net_device_stats
{
	unsigned long	rx_packets;		/* total packets received	*/
	unsigned long	tx_packets;		/* total packets transmitted	*/
	unsigned long	rx_bytes;		/* total bytes received 	*/
	unsigned long	tx_bytes;		/* total bytes transmitted	*/
	unsigned long	rx_errors;		/* bad packets received		*/
	unsigned long	tx_errors;		/* packet transmit problems	*/
	unsigned long	rx_dropped;		/* no space in linux buffers	*/
	unsigned long	tx_dropped;		/* no space available in linux	*/
	unsigned long	multicast;		/* multicast packets received	*/
	unsigned long	collisions;

	/* detailed rx_errors: */
	unsigned long	rx_length_errors;
	unsigned long	rx_over_errors;		/* receiver ring buff overflow	*/
	unsigned long	rx_crc_errors;		/* recved pkt with crc error	*/
	unsigned long	rx_frame_errors;	/* recv'd frame alignment error */
	unsigned long	rx_fifo_errors;		/* recv'r fifo overrun		*/
	unsigned long	rx_missed_errors;	/* receiver missed packet	*/

	/* detailed tx_errors */
	unsigned long	tx_aborted_errors;
	unsigned long	tx_carrier_errors;
	unsigned long	tx_fifo_errors;
	unsigned long	tx_heartbeat_errors;
	unsigned long	tx_window_errors;
	
	/* for cslip etc */
	unsigned long	rx_compressed;
	unsigned long	tx_compressed;
};


/* Media selection options. */
enum {
        IF_PORT_UNKNOWN = 0,
        IF_PORT_10BASE2,
        IF_PORT_10BASET,
        IF_PORT_AUI,
        IF_PORT_100BASET,
        IF_PORT_100BASETX,
        IF_PORT_100BASEFX
};

#ifdef __KERNEL__

#include <linux/cache.h>
#include <linux/skbuff.h>

struct neighbour;
struct neigh_parms;
struct sk_buff;

struct netif_rx_stats
{
	unsigned total;
	unsigned dropped;
	unsigned time_squeeze;
	unsigned cpu_collision;
};

DECLARE_PER_CPU(struct netif_rx_stats, netdev_rx_stat);


/*
 *	We tag multicasts with these structures.
 */
 
struct dev_mc_list
{	
	struct dev_mc_list	*next;
	/*用来存储组播硬件地址*/
	__u8			dmi_addr[MAX_ADDR_LEN];
	/*组播硬件地址长度*/
	unsigned char		dmi_addrlen;
	/*不同的组播转换为组播硬件地址的数目*/
	int			dmi_users;
	/*标识是否通过SIOCADDMULTI选项添加的*/
	int			dmi_gusers;
};

/*缓存2层首部*/
struct hh_cache
{
	/*将同属于一个邻居项的多个hh_cache 实例链接起来，neigh_hh_init*/
	struct hh_cache *hh_next;	/* Next entry			     */
	/*引用计数*/
	atomic_t	hh_refcnt;	/* number of users                   */
/*
 * We want hh_output, hh_len, hh_lock and hh_data be a in a separate
 * cache line on SMP.
 * They are mostly read, but hh_refcnt may be changed quite frequently,
 * incurring cache line ping pongs.
 */
	/*缓存的硬件首部中指明的三层协议类型*/
	__be16		hh_type ____cacheline_aligned_in_smp;
					/* protocol identifier, f.e ETH_P_IP
                                         *  NOTE:  For VLANs, this will be the
                                         *  encapuslated type. --BLG
                                         */
	/*缓存的2层首部长度*/
	u16		hh_len;		/* length of header */
	/*报文输出函数，如果neigh结构中的output一样 由neigh_ops中的某个输出函数初始化*/
	int		(*hh_output)(struct sk_buff *skb);
	/*用于保存hh_cache的自旋锁*/
	seqlock_t	hh_lock;

	/* cached hardware header; allow for machine alignment needs.        */
#define HH_DATA_MOD	16
#define HH_DATA_OFF(__len) \
	(HH_DATA_MOD - (((__len - 1) & (HH_DATA_MOD - 1)) + 1))
#define HH_DATA_ALIGN(__len) \
	(((__len)+(HH_DATA_MOD-1))&~(HH_DATA_MOD - 1))
	/*存放2层首部，对于以太网，则是以太网帧的首部*/
	unsigned long	hh_data[HH_DATA_ALIGN(LL_MAX_HEADER) / sizeof(long)];
};

/* Reserve HH_DATA_MOD byte aligned hard_header_len, but at least that much.
 * Alternative is:
 *   dev->hard_header_len ? (dev->hard_header_len +
 *                           (HH_DATA_MOD - 1)) & ~(HH_DATA_MOD - 1) : 0
 *
 * We could use other alignment values, but we must maintain the
 * relationship HH alignment <= LL alignment.
 */
#define LL_RESERVED_SPACE(dev) \
	(((dev)->hard_header_len&~(HH_DATA_MOD - 1)) + HH_DATA_MOD)
#define LL_RESERVED_SPACE_EXTRA(dev,extra) \
	((((dev)->hard_header_len+extra)&~(HH_DATA_MOD - 1)) + HH_DATA_MOD)

/* These flag bits are private to the generic network queueing
 * layer, they may not be explicitly referenced by any other
 * code.
 */

enum netdev_state_t
{
	/*由于热插拔网络设备，缓存不够，网络设备硬件错误或关闭或禁止硬件，从而关闭排队功能*/
	__LINK_STATE_XOFF=0,
	/*网络设备处于激活状态*/
	__LINK_STATE_START,
	/*在电源管理中，当系统处于待机时，需要挂起各个设备，同时要记录各设备的待机前的状态
	 * 标识网络设备对系统是可用的，借用此标记来记录待机前的设备状态，以便在系统恢复时
	 * 是否需要启用该设备
	 */
	__LINK_STATE_PRESENT,
	/*标识网络驱动的数据发送是否在流量控制的调度中*/
	__LINK_STATE_SCHED,
	/*标识网络设备是否可传递状态，当网络设备不能传递数据时设置，例如，网线被拔出，此标志可由netif_carrier_ok检测*/
	__LINK_STATE_NOCARRIER,
	/*数据包到达而触发中断时，则isr中会设置该状态，标识进入数据包接受状态，
	 * 然后激活数据包接受软中断，结合poll方式接受数据包，直至此次数据包接受完成。在此状态中，即便有新的中断产生，也不会调度软中断*/
	__LINK_STATE_RX_SCHED,
	/*网络设备的连接状态发生改变，正在处理改变过程*/
	__LINK_STATE_LINKWATCH_PENDING,
	__LINK_STATE_DORMANT,
	/*进行流量控制，正在调度队列过程中*/
	__LINK_STATE_QDISC_RUNNING,
};


/*
 * This structure holds at boot time configured netdevice settings. They
 * are then used in the device probing. 
 */
struct netdev_boot_setup {
	char name[IFNAMSIZ];
	struct ifmap map;
};
#define NETDEV_BOOT_SETUP_MAX 8

extern int __init netdev_boot_setup(char *str);

/*
 *	The DEVICE structure.
 *	Actually, this whole structure is a big mistake.  It mixes I/O
 *	data with strictly "high-level" data, and it has to know about
 *	almost every data structure used in the INET module.
 *
 *	FIXME: cleanup struct net_device such that network protocol info
 *	moves out.
 */

struct net_device
{

	/*
	 * This is the first field of the "visible" part of this structure
	 * (i.e. as seen by users in the "Space.c" file).  It is the name
	 * the interface.
	 */
	/*网络设备名*/
	char			name[IFNAMSIZ];
	/* device name hash chain */
	/*根据网络设备名以散列表的形式组织到dev_name_head散列表中*/
	struct hlist_node	name_hlist;

	/*
	 *	I/O specific fields
	 *	FIXME: Merge these and struct ifmap into one
	 */
	unsigned long		mem_end;	/* shared mem end	*/
	unsigned long		mem_start;	/* shared mem start	*/
	unsigned long		base_addr;	/* device I/O address	*/
	unsigned int		irq;		/* device IRQ number	*/

	/*
	 *	Some hardware also needs these fields, but they are not
	 *	part of the usual set specified in Space.c.
	 */

	unsigned char		if_port;	/* Selectable AUI, TP,..*/
	unsigned char		dma;		/* DMA channel		*/

	/*设备状态标志，其中包含若干状态和Qos排队规则状态*/
	unsigned long		state;

	/*将所有的设备连接起来*/
	struct net_device	*next;
	
	/* The device initialization function. Called only once. */
	int			(*init)(struct net_device *dev);

	/* ------- Fields preinitialized in Space.c finish here ------- */

	/* Net device features */
	unsigned long		features;
	/*SG类型的聚合分散I/O标志，当一个数据包被分成多个独立的内存段，并且接口又能传输这样的包，则要设置该标志*/
#define NETIF_F_SG		1	/* Scatter/gather IO. */
	/*接口仅能校验IP数据包*/
#define NETIF_F_IP_CSUM		2	/* Can checksum only TCP/UDP over IPv4. */
#define NETIF_F_NO_CSUM		4	/* Does not require checksum. F.e. loopack. */
	/*由硬件进行校验*/
#define NETIF_F_HW_CSUM		8	/* Can checksum all the packets. */
	/*如果设备可以在高端内存使用DMA，则设置该标志，反之，所有为驱动程序提供的数据包缓存全在低端内存*/
#define NETIF_F_HIGHDMA		32	/* Can DMA to high memory. */
	/*表明设备可以处理SG数据包，在linux2.6中 只有loopback设备可以*/
#define NETIF_F_FRAGLIST	64	/* Scatter/gather IO. */
	/*支持802.1q VLAN数据包的硬件加速等处理*/
#define NETIF_F_HW_VLAN_TX	128	/* Transmit VLAN hw acceleration */
#define NETIF_F_HW_VLAN_RX	256	/* Receive VLAN hw acceleration */
#define NETIF_F_HW_VLAN_FILTER	512	/* Receive filtering on VLAN */
	/*标识设备不支持硬件，支持802.1q Vlan数据包*/
#define NETIF_F_VLAN_CHALLENGED	1024	/* Device cannot handle VLAN packets */
	/*标识设备支持某种GSO，在输出数据包时，会得到输出网络设备的特性，这样传输曾可以根据输出网络设备的GSO特性来处理输出的数据*/
#define NETIF_F_GSO		2048	/* Enable software GSO. */
	/*标识通过输出网络数据包时是否需要上锁，设置时，不需要上锁*/
#define NETIF_F_LLTX		4096	/* LockLess TX */

	/* Segmentation offload features */
#define NETIF_F_GSO_SHIFT	16
#define NETIF_F_GSO_MASK	0xffff0000
	/*标识设备支持TCP段卸载*/
#define NETIF_F_TSO		(SKB_GSO_TCPV4 << NETIF_F_GSO_SHIFT)
	/*标识设备支持UDP分片卸载*/
#define NETIF_F_UFO		(SKB_GSO_UDP << NETIF_F_GSO_SHIFT)
	/*标识设备支持从一个不可信赖源发出数据包进行段卸载*/
#define NETIF_F_GSO_ROBUST	(SKB_GSO_DODGY << NETIF_F_GSO_SHIFT)
	/*IPV4的tcp段卸载，当设置tcp首部的cwr时，使用此gso_type*/
#define NETIF_F_TSO_ECN		(SKB_GSO_TCP_ECN << NETIF_F_GSO_SHIFT)
	/*标识设备支持ipv6的tcp段卸载*/
#define NETIF_F_TSO6		(SKB_GSO_TCPV6 << NETIF_F_GSO_SHIFT)

	/* List of features with software fallbacks. */
#define NETIF_F_GSO_SOFTWARE	(NETIF_F_TSO | NETIF_F_TSO_ECN | NETIF_F_TSO6)

#define NETIF_F_GEN_CSUM	(NETIF_F_NO_CSUM | NETIF_F_HW_CSUM)
#define NETIF_F_ALL_CSUM	(NETIF_F_IP_CSUM | NETIF_F_GEN_CSUM)

	/*用于链接那些已调度有数据包输出的网络设备的指针*/
	struct net_device	*next_sched;

	/* Interface index. Unique device identifier	*/
	/*网络接口索引*/
	int			ifindex;
	/*网络设备的唯一标识，主要用于虚拟隧道设备*/
	int			iflink;


	/*提供给应用程序获取网络设备统计信息，如ifconfig输出会调用此函数*/
	struct net_device_stats* (*get_stats)(struct net_device *dev);

	/* List of functions to handle Wireless Extensions (instead of ioctl).
	 * See <net/iw_handler.h> for details. Jean II */
	const struct iw_handler_def *	wireless_handlers;
	/* Instance data managed by the core of Wireless Extensions. */
	struct iw_public_data *	wireless_data;

	const struct ethtool_ops *ethtool_ops;

	/*
	 * This marks the end of the "visible" part of the structure. All
	 * fields hereafter are internal to the system, and may change at
	 * will (read: may be cleaned up at will).
	 */


	/*表示接口的一组标志,IFF_UP等*/
	unsigned int		flags;	/* interface flags (a la BSD)	*/
	/*记录当前设备的IFF_PROMISC 和IFF_ALLMULTI状态，用来配合flags使用*/
	unsigned short		gflags;
	/*与flags相似
	 * IFF_802_1Q_VLAN等*/
        unsigned short          priv_flags; /* Like 'flags' but invisible to userspace. */
		/*net_device 32字节对其， 如果分配一个空间p  则dev动与align(p,32)  padded=dev-p,  返回dev 所以 padded 释放时候会用到
		 * free(dev-padded)*/
	unsigned short		padded;	/* How much padding added by alloc_netdev() */

	unsigned char		operstate; /* RFC2863 operstate */
	unsigned char		link_mode; /* mapping policy to operstate */

	unsigned		mtu;	/* interface MTU value		*/
	/*接口的硬件类型,arp模块中，用type来判断接口的硬件地址类型，对以太网接口 值为ARPHDR_ETHER.
	 *note:arp协议首部需要填写硬件地址类型*/
	unsigned short		type;	/* interface hardware type	*/
	/*硬件首部长度，以太网为14B*/
	unsigned short		hard_header_len;	/* hardware hdr length	*/

	/*在启用bonding的网络负载均衡后，指向bonding的虚拟网络设备*/
	struct net_device	*master; /* Pointer to master device of a group,
					  * which this device is member of.
					  */

	/* Interface address info. */
	/*硬件地址，通常初始化时，从设备中读取*/
	unsigned char		perm_addr[MAX_ADDR_LEN]; /* permanent hw address */
	unsigned char		addr_len;	/* hardware address length	*/
	unsigned short          dev_id;		/* for shared network cards */

	/*存储到接口的组播地址链表*/
	struct dev_mc_list	*mc_list;	/* Multicast mac addresses	*/
	/*mc_list所包含的项数,链表的节点数*/
	int			mc_count;	/* Number of installed mcasts	*/
	/*设置网络设备混杂模式计数器，每次设置退出就会+1 或-1  只有为0 才真正退出混杂模式*/
	int			promiscuity;
	/*设置网络设备接受所有组播包的计数器，每次设置退出就会相应+1 -1,只有为0 才真正不接受组播包*/
	int			allmulti;


	/* Protocol specific pointers */
	
	void 			*atalk_ptr;	/* AppleTalk link 	*/
	void			*ip_ptr;	/* IPv4 specific data	指向in_device*/  
	void                    *dn_ptr;        /* DECnet specific data */
	void                    *ip6_ptr;       /* IPv6 specific data */
	void			*ec_ptr;	/* Econet specific data	*/
	void			*ax25_ptr;	/* AX.25 specific data */

/*
 * Cache line mostly used on receive path (including eth_type_trans())
 */
	/*net_device设备通过该字段链接到softnet_data的poll_list成员*/
	struct list_head	poll_list ____cacheline_aligned_in_smp;
					/* Link to poll list	*/

	/*NAPI兼容驱动程序提供该方法，用来以轮徇模式接受数据，中断结合poll能显著提高性能*/
	int			(*poll) (struct net_device *dev, int *quota);
	/*读取数据包的配额，动态变化，由netdev_budget初始化，每次从网络设备读取数据包后，
	 * 减去本次读取的数据包，当<=0时，结束本次轮循,等待下次轮循,这样即使某个网络设备有大量数据包输入，
	 * 也能保证其他网络设备能接受数据包*/
	int			quota;
	/*数据包输入软中断中，单个网络设备读取数据包的配额*/
	int			weight;
	/*最近一次接受数据包的时间,jiffies*/
	unsigned long		last_rx;	/* Time of last Rx	*/
	/* Interface address info used in eth_type_trans() */
	unsigned char		dev_addr[MAX_ADDR_LEN];	/* hw address, (before bcast 
							because most packets are unicast) */

	unsigned char		broadcast[MAX_ADDR_LEN];	/* hw bcast add	*/

/*
 * Cache line mostly used on queue transmit path (qdisc)
 */
	/* device queue lock */
	spinlock_t		queue_lock ____cacheline_aligned_in_smp;
	/*当前使用的根排队规则，配置的排队规则生效时由qdisk_sleeping设置*/
	struct Qdisc		*qdisc;
	/*当前的排队规则，生效时，设置到qdisc*/
	struct Qdisc		*qdisc_sleeping;
	/*通过链表方式，记录配置在所在网络设备的所有排队规则，例如，使用里分类规则时，网络设备就会配置多个排队规则*/
	struct list_head	qdisc_list;
	/*所在设备发送队列的最大长度,以太网默认设置为1000， 如ifconfig eth0 txqueuelen 2000设置为2000*/
	unsigned long		tx_queue_len;	/* Max frames per queue allowed */

	/* Partially transmitted GSO packet. */
	/*经软分割的GSO数据包,在控制流量输出过程的数据包输出软中断中，输出第一个数据包时，
	 * 后续数据包暂时缓存到gso_skb中，在下次数据包输出软中断时，再从gso_skb中取出输出*/
	struct sk_buff		*gso_skb;

	/* ingress path synchronizer */
	/*防止多cpu并发排入输入排队规则的自旋锁*/
	spinlock_t		ingress_lock;
	/*数据包输入的排队规则*/
	struct Qdisc		*qdisc_ingress;

/*
 * One part is mostly used on xmit path (device)
 */
	/* hard_start_xmit synchronizer */
	/*发送数据包的自旋锁，防止多cpu的并发操作*/
	spinlock_t		_xmit_lock ____cacheline_aligned_in_smp;
	/* cpu id of processor entered to hard_start_xmit or -1,
	   if nobody entered there.
	 */
	/*正在通过该网络设备发送数据包的cpu  当为-1时，没有cpu通过该设备发送数据包*/
	int			xmit_lock_owner;
	/*私有数据，通过alloc_netdev设置，最好通过netdev_priv()进行访问*/
	void			*priv;	/* pointer to private data	*/
	/*驱动提供给上一层发送数据包的接口，在发送数据包时必定会调用该接口*/
	int			(*hard_start_xmit) (struct sk_buff *skb,
						    struct net_device *dev);
	/* These may be needed for future network-power-down code. */
	/*最近一次发送数据包的时间，jiffies*/
	unsigned long		trans_start;	/* Time (in jiffies) of last Tx	*/

	/*网络层确定发送数据包已超时，调用驱动程序的tx_timeout的最短时间*/
	int			watchdog_timeo; /* used by dev_watchdog() */
	/*网络设备的软件狗，用于检测网络设备处于正常的工作状态时，是否存在由于关闭排队功能而导致发送超时的情况，
	 * 一旦发送上述情况，就调用驱动的tx_timeout处理*/
	struct timer_list	watchdog_timer;

/*
 * refcnt is a very hot point, so align it on SMP
 */
	/* Number of references to this device */
	/*网络设备的引用计数*/
	atomic_t		refcnt ____cacheline_aligned_in_smp;

	/* delayed register/unregister */
	/*用来连接到net_todo_list上
	 *net_todo_list包含已注销  已经结束的网络设备,在调用unregister_netdevice()注销设备后，会调用
	 *net_set_todo()将注销的设备连接到net_todo_list链表上，然后调用rtnl_unlock()释放锁，并调用
	 *netdev_run_todo()完成对网络设备的注销操作
	 */
	struct list_head	todo_list;
	/* device index hash chain */
	/*根据网络设备的索引，已三列表的形式组织到dev_index_head哈希表上*/
	struct hlist_node	index_hlist;

	/* register/unregister state machine */
	enum { 
		/*处于初始化未注册状态*/
		NETREG_UNINITIALIZED=0,
		/*完成网络设备的注册状态*/
	       NETREG_REGISTERED,	/* completed register_netdevice */
		   /*正在注销网络设备，正在从链表中移除*/
	       NETREG_UNREGISTERING,	/* called unregister_netdevice */
		   /*完成网络设备的注销（包括移除/sys文件系统入口），已从链表中移除，但是net_device还没有释放
			* 在netdev_run_todo函数中  从net_todo_list链表中取出设备，设置该状态*/
	       NETREG_UNREGISTERED,	/* completed unregister todo */
		   /*即将释放net_device*/
	       NETREG_RELEASED,		/* called free_netdev */
	} reg_state;

	/* Called after device is detached from network. */
	/*驱动程序销毁指针，如果设置了该函数，则unregister_netdevice()会调用该函数 执行与init相反的操作*/
	void			(*uninit)(struct net_device *dev);
	/* Called after last user reference disappears. */
	/*一般不会被初始化，部分网络设备驱动会初始化为free_netdev()
	 * 大部分网络设备驱动会在unregister_netdev()函数后直接调用free_netdev()*/
	void			(*destructor)(struct net_device *dev);

	/* Pointers to interface service routines.	*/
	/*启动设备函数指针，完成注册所需的系统资源，打开硬件及其所有设置，可用ifconfig 启用网络设备*/
	int			(*open)(struct net_device *dev);
	/*关闭网络设备，执行与启用相反的操作， ifconfig*/
	int			(*stop)(struct net_device *dev);
#define HAVE_NETDEV_POLL
	/*根据先前检索到的源和目标硬件地址创建硬件首部，以太网对应的接口为eth_header()*/
	int			(*hard_header) (struct sk_buff *skb,
						struct net_device *dev,
						unsigned short type,
						void *daddr,
						void *saddr,
						unsigned len);
	/*用来在完成传输数据包之前，arp解析之后，重新创建硬件首部*/
	int			(*rebuild_header)(struct sk_buff *skb);
#define HAVE_MULTICAST			 
	/*将组播地址列表更新到网络设备中，当设备的组播地址列表或标志发生变化时，调用此函数*/
	void			(*set_multicast_list)(struct net_device *dev);
#define HAVE_SET_MAC_ADDR  		 
	/*修改网络设备mac地址接口，需要网络设备支持*/
	int			(*set_mac_address)(struct net_device *dev,
						   void *addr);
#define HAVE_PRIVATE_IOCTL
	/*ioctl接口功能，如果设备不支持相关操作，则为NULL*/
	int			(*do_ioctl)(struct net_device *dev,
					    struct ifreq *ifr, int cmd);
#define HAVE_SET_CONFIG
	/*修改设备接口配置接口,不过目前很多驱动程序提供其他接口,如ethtool接口*/
	int			(*set_config)(struct net_device *dev,
					      struct ifmap *map);
#define HAVE_HEADER_CACHE
	/*通过arp查询结果填充hh_cache结构，通常驱动程序使用默认的eth_header_cache()接口*/
	int			(*hard_header_cache)(struct neighbour *neigh,
						     struct hh_cache *hh);
	/*更新hh_cache结构，通常驱动程序时候eth_header_cache_update()接口*/
	void			(*header_cache_update)(struct hh_cache *hh,
						       struct net_device *dev,
						       unsigned char *  haddr);
#define HAVE_CHANGE_MTU
	/*如果驱动程序修改mtu需要做某些特定操作，则需要实现这个函数，否则默认函数即可正确实现相关处理*/
	int			(*change_mtu)(struct net_device *dev, int new_mtu);

#define HAVE_TX_TIMEOUT
	/*如果数据包在指定时间内发送失败(如数据包丢失或上锁),这时会调用此接口，负责解决问题 并重新开始数据包发送*/
	void			(*tx_timeout) (struct net_device *dev);

	void			(*vlan_rx_register)(struct net_device *dev,
						    struct vlan_group *grp);
	void			(*vlan_rx_add_vid)(struct net_device *dev,
						   unsigned short vid);
	void			(*vlan_rx_kill_vid)(struct net_device *dev,
						    unsigned short vid);

	/*从skb数据包中获取mac原地只，并将复制到haddr缓冲区中，返回值为地址长度，以太网使用eth_header_parse()*/
	int			(*hard_header_parse)(struct sk_buff *skb,
						     unsigned char *haddr);
	/*用于设置与邻居子系统相关的函数，在创建邻居项时被回调，可以被实现*/
	int			(*neigh_setup)(struct net_device *dev, struct neigh_parms *);
#ifdef CONFIG_NETPOLL
	/*网络设备的netpoll信息块，存储与netpoll_info相关的信息,由netpoll_setup设置
	 * 当支持netpoll时，必须实现npinfo的成员
	 * */
	struct netpoll_info	*npinfo;
#endif
#ifdef CONFIG_NET_POLL_CONTROLLER
	/*该函数在禁止中断的情况下，要求驱动程序以轮寻模式在接口上查询事件,通常用于特定的内核网络任务中,
	 *例如：远程控制台和内核网络调试，模拟网络设备发生中断，从而进行中断处理*/
	void                    (*poll_controller)(struct net_device *dev);
#endif

	/* bridge stuff */
	/*创建一个桥设备时，指向net_bridge_port实例*/
	struct net_bridge_port	*br_port;

	/* class/net/name entry */
	/*网络设备注册在/sys/class/net/中的实例*/
	struct class_device	class_dev;
	/* space for optional statistics and wireless sysfs groups */
	struct attribute_group  *sysfs_groups[3];
};

#define	NETDEV_ALIGN		32
#define	NETDEV_ALIGN_CONST	(NETDEV_ALIGN - 1)

static inline void *netdev_priv(struct net_device *dev)
{
	return (char *)dev + ((sizeof(struct net_device)
					+ NETDEV_ALIGN_CONST)
				& ~NETDEV_ALIGN_CONST);
}

#define SET_MODULE_OWNER(dev) do { } while (0)
/* Set the sysfs physical device reference for the network logical device
 * if set prior to registration will cause a symlink during initialization.
 */
#define SET_NETDEV_DEV(net, pdev)	((net)->class_dev.dev = (pdev))

struct packet_type {
	/*标识以太网帧或其他链路层报文承载的网络成协议号*/
	__be16			type;	/* This is really htons(ether_type). */
	/*接受从指定网络接口的数据包，如果为NULL，则接受所有接口的数据包*/
	struct net_device	*dev;	/* NULL is wildcarded here	     */
	/*
	 * 协议入口处理函数。第一个参数 待处理报文，第2个参数，当前处理该报文的网络设备，第三个为报文类型，第四个为原始的报文输入网络设备
	 * 通常情况下 当前处理的网络设备  与原始的网络设备是相同的设备，但在某些情况下是不同的(如启用里bonding来实现负载均衡和失效保护),
	 * 此时，原始的输入设备是物理设备，当前处理的设备是虚拟网络设备
	 */
	int			(*func) (struct sk_buff *,
					 struct net_device *,
					 struct packet_type *,
					 struct net_device *);
	/*
	 * gso是网络设备支持传输层的一个功能。
	 * 当gso数据输出时到达网络设备，如果网络设备不支持gso的情况，则需要传输曾对输出的数据包重新进行gso分段和计算校验和，
	 * 因此需要网络层提供接口给设备层，能够访问到传输层的gso分段和校验和的计算功能，对输出的数据包进行分段和计算校验和
	 * gso_segment 回调传输层gso分段方法给大段进行分段，ipv4 实现的函数为inet_gso_segment()
	 */
	struct sk_buff		*(*gso_segment)(struct sk_buff *skb,
						int features);
	/*回调传输层在分段之前堆伪首部进行校验和计算，ipv4中实现函数为inet_gso_send_check()*/
	int			(*gso_send_check)(struct sk_buff *skb);
	/*用来存储各协议族的私有数据，在原始套接口中，用于标识是原始套接口的传输控制块*/
	void			*af_packet_priv;
	/*链接不同协议族报文接受历程的链表*/
	struct list_head	list;
};

#include <linux/interrupt.h>
#include <linux/notifier.h>

extern struct net_device		loopback_dev;		/* The loopback */
extern struct net_device		*dev_base;		/* All devices */
extern rwlock_t				dev_base_lock;		/* Device list lock */

extern int 			netdev_boot_setup_check(struct net_device *dev);
extern unsigned long		netdev_boot_base(const char *prefix, int unit);
extern struct net_device    *dev_getbyhwaddr(unsigned short type, char *hwaddr);
extern struct net_device *dev_getfirstbyhwtype(unsigned short type);
extern void		dev_add_pack(struct packet_type *pt);
extern void		dev_remove_pack(struct packet_type *pt);
extern void		__dev_remove_pack(struct packet_type *pt);

extern struct net_device	*dev_get_by_flags(unsigned short flags,
						  unsigned short mask);
extern struct net_device	*dev_get_by_name(const char *name);
extern struct net_device	*__dev_get_by_name(const char *name);
extern int		dev_alloc_name(struct net_device *dev, const char *name);
extern int		dev_open(struct net_device *dev);
extern int		dev_close(struct net_device *dev);
extern int		dev_queue_xmit(struct sk_buff *skb);
extern int		register_netdevice(struct net_device *dev);
extern int		unregister_netdevice(struct net_device *dev);
extern void		free_netdev(struct net_device *dev);
extern void		synchronize_net(void);
extern int 		register_netdevice_notifier(struct notifier_block *nb);
extern int		unregister_netdevice_notifier(struct notifier_block *nb);
extern int		call_netdevice_notifiers(unsigned long val, void *v);
extern struct net_device	*dev_get_by_index(int ifindex);
extern struct net_device	*__dev_get_by_index(int ifindex);
extern int		dev_restart(struct net_device *dev);
#ifdef CONFIG_NETPOLL_TRAP
extern int		netpoll_trap(void);
#endif

typedef int gifconf_func_t(struct net_device * dev, char __user * bufptr, int len);
extern int		register_gifconf(unsigned int family, gifconf_func_t * gifconf);
static inline int unregister_gifconf(unsigned int family)
{
	return register_gifconf(family, NULL);
}

/*
 * Incoming packets are placed on per-cpu queues so that
 * no locking is needed.
 */

struct softnet_data
{
	/*
	 *数据包输出软中断中，输出数据包的网络设备队列,
	 *处于网络输出报文状态的网络设备添加到该队列上，在数据包输出软中断中，会遍历该队列
	 *从网络设备的排队规则中获取数据包并输出
	 */
	struct net_device	*output_queue;
	/*
	 * 非NAPI的接口层缓存队列，对于非NAPI驱动，通常在硬中断中或通过轮循读取报文后，调用netif_rx()将报文上传到上层，
	 * 即现将报文上传到input_pkt_queue队列中，然后产生一个数据包输入软中断，由软终端报文将数据包上传到上层，这在接口数据包接受的速率
	 * 比协议站和应用成快时非常有用，队列长度上线参数netdev_max_backlog
	 */
	struct sk_buff_head	input_pkt_queue;
	/*
	 * 网络设备轮循队列。
	 * 处于报文接受状态的设备链接到该队列，在数据包输入软中断中会遍历该队列，通过轮寻方式接受报文
	 */
	struct list_head	poll_list;
	/*
	 * 完成发送数据包的等待释放队列。需要在适当时机释放发送完成的数据包，在发送报文软中断中会检测该队列,
	 * 是否将完成发送的数据包添加到该队列，与具体的执行环境有关，发送完成后调用dev_kfree_skb_any(),如果正处于中断处理过程中或中断禁止状态，
	 * 则会等待释放的skb添加到该队列，否则直接将其释放。
	 */
	struct sk_buff		*completion_queue;

	/*
	 * 用于非NAPI网络驱动的虚拟网络设备，不代表具体的网络设备，用来兼容非NAPI驱动，
	 * 通过该虚拟网络设备的poll回调函数在接受报文软中断中，从非NAPI的接口层缓存队列input_pkt_queue获取报文像上层传递
	 */
	struct net_device	backlog_dev;	/* Sorry. 8) */
#ifdef CONFIG_NET_DMA
	struct dma_chan		*net_dma;
#endif
};

DECLARE_PER_CPU(struct softnet_data,softnet_data);

#define HAVE_NETIF_QUEUE

extern void __netif_schedule(struct net_device *dev);

static inline void netif_schedule(struct net_device *dev)
{
	if (!test_bit(__LINK_STATE_XOFF, &dev->state))
		__netif_schedule(dev);
}

static inline void netif_start_queue(struct net_device *dev)
{
	clear_bit(__LINK_STATE_XOFF, &dev->state);
}

static inline void netif_wake_queue(struct net_device *dev)
{
#ifdef CONFIG_NETPOLL_TRAP
	if (netpoll_trap())
		return;
#endif
	if (test_and_clear_bit(__LINK_STATE_XOFF, &dev->state))
		__netif_schedule(dev);
}

static inline void netif_stop_queue(struct net_device *dev)
{
#ifdef CONFIG_NETPOLL_TRAP
	if (netpoll_trap())
		return;
#endif
	set_bit(__LINK_STATE_XOFF, &dev->state);
}

static inline int netif_queue_stopped(const struct net_device *dev)
{
	return test_bit(__LINK_STATE_XOFF, &dev->state);
}

static inline int netif_running(const struct net_device *dev)
{
	return test_bit(__LINK_STATE_START, &dev->state);
}


/* Use this variant when it is known for sure that it
 * is executing from interrupt context.
 */
static inline void dev_kfree_skb_irq(struct sk_buff *skb)
{
	if (atomic_dec_and_test(&skb->users)) {
		struct softnet_data *sd;
		unsigned long flags;

		local_irq_save(flags);
		sd = &__get_cpu_var(softnet_data);
		skb->next = sd->completion_queue;
		sd->completion_queue = skb;
		raise_softirq_irqoff(NET_TX_SOFTIRQ);
		local_irq_restore(flags);
	}
}

/* Use this variant in places where it could be invoked
 * either from interrupt or non-interrupt context.
 */
extern void dev_kfree_skb_any(struct sk_buff *skb);

#define HAVE_NETIF_RX 1
extern int		netif_rx(struct sk_buff *skb);
extern int		netif_rx_ni(struct sk_buff *skb);
#define HAVE_NETIF_RECEIVE_SKB 1
extern int		netif_receive_skb(struct sk_buff *skb);
extern int		dev_valid_name(const char *name);
extern int		dev_ioctl(unsigned int cmd, void __user *);
extern int		dev_ethtool(struct ifreq *);
extern unsigned		dev_get_flags(const struct net_device *);
extern int		dev_change_flags(struct net_device *, unsigned);
extern int		dev_change_name(struct net_device *, char *);
extern int		dev_set_mtu(struct net_device *, int);
extern int		dev_set_mac_address(struct net_device *,
					    struct sockaddr *);
extern int		dev_hard_start_xmit(struct sk_buff *skb,
					    struct net_device *dev);

extern void		dev_init(void);

extern int		netdev_budget;

/* Called by rtnetlink.c:rtnl_unlock() */
extern void netdev_run_todo(void);

static inline void dev_put(struct net_device *dev)
{
	atomic_dec(&dev->refcnt);
}

static inline void dev_hold(struct net_device *dev)
{
	atomic_inc(&dev->refcnt);
}

/* Carrier loss detection, dial on demand. The functions netif_carrier_on
 * and _off may be called from IRQ context, but it is caller
 * who is responsible for serialization of these calls.
 *
 * The name carrier is inappropriate, these functions should really be
 * called netif_lowerlayer_*() because they represent the state of any
 * kind of lower layer not just hardware media.
 */

extern void linkwatch_fire_event(struct net_device *dev);

static inline int netif_carrier_ok(const struct net_device *dev)
{
	return !test_bit(__LINK_STATE_NOCARRIER, &dev->state);
}

extern void __netdev_watchdog_up(struct net_device *dev);

extern void netif_carrier_on(struct net_device *dev);

extern void netif_carrier_off(struct net_device *dev);

static inline void netif_dormant_on(struct net_device *dev)
{
	if (!test_and_set_bit(__LINK_STATE_DORMANT, &dev->state))
		linkwatch_fire_event(dev);
}

static inline void netif_dormant_off(struct net_device *dev)
{
	if (test_and_clear_bit(__LINK_STATE_DORMANT, &dev->state))
		linkwatch_fire_event(dev);
}

static inline int netif_dormant(const struct net_device *dev)
{
	return test_bit(__LINK_STATE_DORMANT, &dev->state);
}


static inline int netif_oper_up(const struct net_device *dev) {
	return (dev->operstate == IF_OPER_UP ||
		dev->operstate == IF_OPER_UNKNOWN /* backward compat */);
}

/* Hot-plugging. */
static inline int netif_device_present(struct net_device *dev)
{
	return test_bit(__LINK_STATE_PRESENT, &dev->state);
}

extern void netif_device_detach(struct net_device *dev);

extern void netif_device_attach(struct net_device *dev);

/*
 * Network interface message level settings
 */
#define HAVE_NETIF_MSG 1

enum {
	NETIF_MSG_DRV		= 0x0001,
	NETIF_MSG_PROBE		= 0x0002,
	NETIF_MSG_LINK		= 0x0004,
	NETIF_MSG_TIMER		= 0x0008,
	NETIF_MSG_IFDOWN	= 0x0010,
	NETIF_MSG_IFUP		= 0x0020,
	NETIF_MSG_RX_ERR	= 0x0040,
	NETIF_MSG_TX_ERR	= 0x0080,
	NETIF_MSG_TX_QUEUED	= 0x0100,
	NETIF_MSG_INTR		= 0x0200,
	NETIF_MSG_TX_DONE	= 0x0400,
	NETIF_MSG_RX_STATUS	= 0x0800,
	NETIF_MSG_PKTDATA	= 0x1000,
	NETIF_MSG_HW		= 0x2000,
	NETIF_MSG_WOL		= 0x4000,
};

#define netif_msg_drv(p)	((p)->msg_enable & NETIF_MSG_DRV)
#define netif_msg_probe(p)	((p)->msg_enable & NETIF_MSG_PROBE)
#define netif_msg_link(p)	((p)->msg_enable & NETIF_MSG_LINK)
#define netif_msg_timer(p)	((p)->msg_enable & NETIF_MSG_TIMER)
#define netif_msg_ifdown(p)	((p)->msg_enable & NETIF_MSG_IFDOWN)
#define netif_msg_ifup(p)	((p)->msg_enable & NETIF_MSG_IFUP)
#define netif_msg_rx_err(p)	((p)->msg_enable & NETIF_MSG_RX_ERR)
#define netif_msg_tx_err(p)	((p)->msg_enable & NETIF_MSG_TX_ERR)
#define netif_msg_tx_queued(p)	((p)->msg_enable & NETIF_MSG_TX_QUEUED)
#define netif_msg_intr(p)	((p)->msg_enable & NETIF_MSG_INTR)
#define netif_msg_tx_done(p)	((p)->msg_enable & NETIF_MSG_TX_DONE)
#define netif_msg_rx_status(p)	((p)->msg_enable & NETIF_MSG_RX_STATUS)
#define netif_msg_pktdata(p)	((p)->msg_enable & NETIF_MSG_PKTDATA)
#define netif_msg_hw(p)		((p)->msg_enable & NETIF_MSG_HW)
#define netif_msg_wol(p)	((p)->msg_enable & NETIF_MSG_WOL)

static inline u32 netif_msg_init(int debug_value, int default_msg_enable_bits)
{
	/* use default */
	if (debug_value < 0 || debug_value >= (sizeof(u32) * 8))
		return default_msg_enable_bits;
	if (debug_value == 0)	/* no output */
		return 0;
	/* set low N bits */
	return (1 << debug_value) - 1;
}

/* Test if receive needs to be scheduled */
static inline int __netif_rx_schedule_prep(struct net_device *dev)
{
	return !test_and_set_bit(__LINK_STATE_RX_SCHED, &dev->state);
}

/* Test if receive needs to be scheduled but only if up */
static inline int netif_rx_schedule_prep(struct net_device *dev)
{
	return netif_running(dev) && __netif_rx_schedule_prep(dev);
}

/* Add interface to tail of rx poll list. This assumes that _prep has
 * already been called and returned 1.
 */

extern void __netif_rx_schedule(struct net_device *dev);

/* Try to reschedule poll. Called by irq handler. */

static inline void netif_rx_schedule(struct net_device *dev)
{
	if (netif_rx_schedule_prep(dev))
		__netif_rx_schedule(dev);
}

/* Try to reschedule poll. Called by dev->poll() after netif_rx_complete().
 * Do not inline this?
 */
static inline int netif_rx_reschedule(struct net_device *dev, int undo)
{
	if (netif_rx_schedule_prep(dev)) {
		unsigned long flags;

		dev->quota += undo;

		local_irq_save(flags);
		list_add_tail(&dev->poll_list, &__get_cpu_var(softnet_data).poll_list);
		__raise_softirq_irqoff(NET_RX_SOFTIRQ);
		local_irq_restore(flags);
		return 1;
	}
	return 0;
}

/* Remove interface from poll list: it must be in the poll list
 * on current cpu. This primitive is called by dev->poll(), when
 * it completes the work. The device cannot be out of poll list at this
 * moment, it is BUG().
 */
static inline void netif_rx_complete(struct net_device *dev)
{
	unsigned long flags;

	local_irq_save(flags);
	BUG_ON(!test_bit(__LINK_STATE_RX_SCHED, &dev->state));
	list_del(&dev->poll_list);
	smp_mb__before_clear_bit();
	clear_bit(__LINK_STATE_RX_SCHED, &dev->state);
	local_irq_restore(flags);
}

static inline void netif_poll_disable(struct net_device *dev)
{
	while (test_and_set_bit(__LINK_STATE_RX_SCHED, &dev->state))
		/* No hurry. */
		schedule_timeout_interruptible(1);
}

static inline void netif_poll_enable(struct net_device *dev)
{
	smp_mb__before_clear_bit();
	clear_bit(__LINK_STATE_RX_SCHED, &dev->state);
}

/* same as netif_rx_complete, except that local_irq_save(flags)
 * has already been issued
 */
static inline void __netif_rx_complete(struct net_device *dev)
{
	BUG_ON(!test_bit(__LINK_STATE_RX_SCHED, &dev->state));
	list_del(&dev->poll_list);
	smp_mb__before_clear_bit();
	clear_bit(__LINK_STATE_RX_SCHED, &dev->state);
}

static inline void netif_tx_lock(struct net_device *dev)
{
	spin_lock(&dev->_xmit_lock);
	dev->xmit_lock_owner = smp_processor_id();
}

static inline void netif_tx_lock_bh(struct net_device *dev)
{
	spin_lock_bh(&dev->_xmit_lock);
	dev->xmit_lock_owner = smp_processor_id();
}

static inline int netif_tx_trylock(struct net_device *dev)
{
	int ok = spin_trylock(&dev->_xmit_lock);
	if (likely(ok))
		dev->xmit_lock_owner = smp_processor_id();
	return ok;
}

static inline void netif_tx_unlock(struct net_device *dev)
{
	dev->xmit_lock_owner = -1;
	spin_unlock(&dev->_xmit_lock);
}

static inline void netif_tx_unlock_bh(struct net_device *dev)
{
	dev->xmit_lock_owner = -1;
	spin_unlock_bh(&dev->_xmit_lock);
}

static inline void netif_tx_disable(struct net_device *dev)
{
	netif_tx_lock_bh(dev);
	netif_stop_queue(dev);
	netif_tx_unlock_bh(dev);
}

/* These functions live elsewhere (drivers/net/net_init.c, but related) */

extern void		ether_setup(struct net_device *dev);

/* Support for loadable net-drivers */
extern struct net_device *alloc_netdev(int sizeof_priv, const char *name,
				       void (*setup)(struct net_device *));
extern int		register_netdev(struct net_device *dev);
extern void		unregister_netdev(struct net_device *dev);
/* Functions used for multicast support */
extern void		dev_mc_upload(struct net_device *dev);
extern int 		dev_mc_delete(struct net_device *dev, void *addr, int alen, int all);
extern int		dev_mc_add(struct net_device *dev, void *addr, int alen, int newonly);
extern void		dev_mc_discard(struct net_device *dev);
extern void		dev_set_promiscuity(struct net_device *dev, int inc);
extern void		dev_set_allmulti(struct net_device *dev, int inc);
extern void		netdev_state_change(struct net_device *dev);
extern void		netdev_features_change(struct net_device *dev);
/* Load a device via the kmod */
extern void		dev_load(const char *name);
extern void		dev_mcast_init(void);
extern int		netdev_max_backlog;
extern int		weight_p;
extern int		netdev_set_master(struct net_device *dev, struct net_device *master);
extern int skb_checksum_help(struct sk_buff *skb);
extern struct sk_buff *skb_gso_segment(struct sk_buff *skb, int features);
#ifdef CONFIG_BUG
extern void netdev_rx_csum_fault(struct net_device *dev);
#else
static inline void netdev_rx_csum_fault(struct net_device *dev)
{
}
#endif
/* rx skb timestamps */
extern void		net_enable_timestamp(void);
extern void		net_disable_timestamp(void);

#ifdef CONFIG_PROC_FS
extern void *dev_seq_start(struct seq_file *seq, loff_t *pos);
extern void *dev_seq_next(struct seq_file *seq, void *v, loff_t *pos);
extern void dev_seq_stop(struct seq_file *seq, void *v);
#endif

extern void linkwatch_run_queue(void);

static inline int net_gso_ok(int features, int gso_type)
{
	int feature = gso_type << NETIF_F_GSO_SHIFT;
	return (features & feature) == feature;
}

static inline int skb_gso_ok(struct sk_buff *skb, int features)
{
	return net_gso_ok(features, skb_shinfo(skb)->gso_type);
}

static inline int netif_needs_gso(struct net_device *dev, struct sk_buff *skb)
{
	return skb_is_gso(skb) &&
	       (!skb_gso_ok(skb, dev->features) ||
		unlikely(skb->ip_summed != CHECKSUM_PARTIAL));
}

/* On bonding slaves other than the currently active slave, suppress
 * duplicates except for 802.3ad ETH_P_SLOW, alb non-mcast/bcast, and
 * ARP on active-backup slaves with arp_validate enabled.
 */
static inline int skb_bond_should_drop(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct net_device *master = dev->master;

	if (master &&
	    (dev->priv_flags & IFF_SLAVE_INACTIVE)) {
		if ((dev->priv_flags & IFF_SLAVE_NEEDARP) &&
		    skb->protocol == __constant_htons(ETH_P_ARP))
			return 0;

		if (master->priv_flags & IFF_MASTER_ALB) {
			if (skb->pkt_type != PACKET_BROADCAST &&
			    skb->pkt_type != PACKET_MULTICAST)
				return 0;
		}
		if (master->priv_flags & IFF_MASTER_8023AD &&
		    skb->protocol == __constant_htons(ETH_P_SLOW))
			return 0;

		return 1;
	}
	return 0;
}

#endif /* __KERNEL__ */

#endif	/* _LINUX_DEV_H */

/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the AF_INET socket handler.
 *
 * Version:	@(#)sock.h	1.0.4	05/13/93
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche <flla@stud.uni-sb.de>
 *
 * Fixes:
 *		Alan Cox	:	Volatiles in skbuff pointers. See
 *					skbuff comments. May be overdone,
 *					better to prove they can be removed
 *					than the reverse.
 *		Alan Cox	:	Added a zapped field for tcp to note
 *					a socket is reset and must stay shut up
 *		Alan Cox	:	New fields for options
 *	Pauline Middelink	:	identd support
 *		Alan Cox	:	Eliminate low level recv/recvfrom
 *		David S. Miller	:	New socket lookup architecture.
 *              Steve Whitehouse:       Default routines for sock_ops
 *              Arnaldo C. Melo :	removed net_pinfo, tp_pinfo and made
 *              			protinfo be just a void pointer, as the
 *              			protocol specific parts were moved to
 *              			respective headers and ipv4/v6, etc now
 *              			use private slabcaches for its socks
 *              Pedro Hortas	:	New flags field for socket options
 *
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _SOCK_H
#define _SOCK_H

#include <linux/list.h>
#include <linux/timer.h>
#include <linux/cache.h>
#include <linux/module.h>
#include <linux/lockdep.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>	/* struct sk_buff */
#include <linux/mm.h>
#include <linux/security.h>

#include <linux/filter.h>

#include <asm/atomic.h>
#include <net/dst.h>
#include <net/checksum.h>

/*
 * This structure really needs to be cleaned up.
 * Most of it is for TCP, and not used by any of
 * the other protocols.
 */

/* Define this to get the SOCK_DBG debugging facility. */
#define SOCK_DEBUGGING
#ifdef SOCK_DEBUGGING
#define SOCK_DEBUG(sk, msg...) do { if ((sk) && sock_flag((sk), SOCK_DBG)) \
					printk(KERN_DEBUG msg); } while (0)
#else
#define SOCK_DEBUG(sk, msg...) do { } while (0)
#endif

/* This is the per-socket lock.  The spinlock provides a synchronization
 * between user contexts and software interrupt processing, whereas the
 * mini-semaphore synchronizes multiple users amongst themselves.
 */
struct sock_iocb;
typedef struct {
	/*用来实现下半部间的同步锁，同时也用与保护对owner的操作*/
	spinlock_t		slock;
	/*
	 * 虽然owner为sock_iocb 类型，实际上只拥0，1标识
	 * 0：未被用户进程锁定
	 * 1：被用户进程锁定
	 * */
	struct sock_iocb	*owner;
	/*等待队列，当进程调用lock_soc()对传输控制块进行上锁时，如果此时传输控制块已被软中断锁定，则此时进程只能睡眠，并将进程添加到此队列
	 * 当中断解锁传输控制块时，会唤醒此队列上的进程
	 * */
	wait_queue_head_t	wq;
	/*
	 * We express the mutex-alike socket_lock semantics
	 * to the lock validator by explicitly managing
	 * the slock as a lock variant (in addition to
	 * the slock itself):
	 */
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map dep_map;
#endif
} socket_lock_t;

struct sock;
struct proto;

/**
 *	struct sock_common - minimal network layer representation of sockets
 *	@skc_family: network address family
 *	@skc_state: Connection state
 *	@skc_reuse: %SO_REUSEADDR setting
 *	@skc_bound_dev_if: bound device index if != 0
 *	@skc_node: main hash linkage for various protocol lookup tables
 *	@skc_bind_node: bind hash linkage for various protocol lookup tables
 *	@skc_refcnt: reference count
 *	@skc_hash: hash value used with various protocol lookup tables
 *	@skc_prot: protocol handlers inside a network family
 *
 *	This is the minimal network layer representation of sockets, the header
 *	for struct sock and struct inet_timewait_sock.
 */
struct sock_common {
	unsigned short		skc_family;
	/*等同与tcp的状态*/
	volatile unsigned char	skc_state;
	/*SO_REUSEADDR*/
	unsigned char		skc_reuse;
	/*if不为0  为输出设备的网络接口的索引*/
	int			skc_bound_dev_if;
	/*
	 *tcp维护一个所有tcp传输控制块的一个散列表tcp_hashinfo,skc_node 用来将所属的tcp传输控制块链接到散列表
	 *udp维护一个所有udp传输控制块的一个散列表udp_hash,skc用来将所属的传输控制块链接到散列表上
	 */
	struct hlist_node	skc_node;
	/*
	 * 已绑定端口的传输控制块利用该字段插入到与之绑定端口信息结构为头节点的链表中。释放端口时，从中删除，
	 * 仅用于基于链接的传输控制块，如TCP
	 */
	struct hlist_node	skc_bind_node;
	atomic_t		skc_refcnt;
	/*存储tcp状态为establish时 加入到散列表的关键字的值*/
	unsigned int		skc_hash;
	struct proto		*skc_prot;
};

/**
  *	struct sock - network layer representation of sockets
  *	@__sk_common: shared layout with inet_timewait_sock
  *	@sk_shutdown: mask of %SEND_SHUTDOWN and/or %RCV_SHUTDOWN
  *	@sk_userlocks: %SO_SNDBUF and %SO_RCVBUF settings
  *	@sk_lock:	synchronizer
  *	@sk_rcvbuf: size of receive buffer in bytes
  *	@sk_sleep: sock wait queue
  *	@sk_dst_cache: destination cache
  *	@sk_dst_lock: destination cache lock
  *	@sk_policy: flow policy
  *	@sk_rmem_alloc: receive queue bytes committed
  *	@sk_receive_queue: incoming packets
  *	@sk_wmem_alloc: transmit queue bytes committed
  *	@sk_write_queue: Packet sending queue
  *	@sk_async_wait_queue: DMA copied packets
  *	@sk_omem_alloc: "o" is "option" or "other"
  *	@sk_wmem_queued: persistent queue size
  *	@sk_forward_alloc: space allocated forward
  *	@sk_allocation: allocation mode
  *	@sk_sndbuf: size of send buffer in bytes
  *	@sk_flags: %SO_LINGER (l_onoff), %SO_BROADCAST, %SO_KEEPALIVE, %SO_OOBINLINE settings
  *	@sk_no_check: %SO_NO_CHECK setting, wether or not checkup packets
  *	@sk_route_caps: route capabilities (e.g. %NETIF_F_TSO)
  *	@sk_gso_type: GSO type (e.g. %SKB_GSO_TCPV4)
  *	@sk_lingertime: %SO_LINGER l_linger setting
  *	@sk_backlog: always used with the per-socket spinlock held
  *	@sk_callback_lock: used with the callbacks in the end of this struct
  *	@sk_error_queue: rarely used
  *	@sk_prot_creator: sk_prot of original sock creator (see ipv6_setsockopt, IPV6_ADDRFORM for instance)
  *	@sk_err: last error
  *	@sk_err_soft: errors that don't cause failure but are the cause of a persistent failure not just 'timed out'
  *	@sk_ack_backlog: current listen backlog
  *	@sk_max_ack_backlog: listen backlog set in listen()
  *	@sk_priority: %SO_PRIORITY setting
  *	@sk_type: socket type (%SOCK_STREAM, etc)
  *	@sk_protocol: which protocol this socket belongs in this network family
  *	@sk_peercred: %SO_PEERCRED setting
  *	@sk_rcvlowat: %SO_RCVLOWAT setting
  *	@sk_rcvtimeo: %SO_RCVTIMEO setting
  *	@sk_sndtimeo: %SO_SNDTIMEO setting
  *	@sk_filter: socket filtering instructions
  *	@sk_protinfo: private area, net family specific, when not using slab
  *	@sk_timer: sock cleanup timer
  *	@sk_stamp: time stamp of last packet received
  *	@sk_socket: Identd and reporting IO signals
  *	@sk_user_data: RPC layer private data
  *	@sk_sndmsg_page: cached page for sendmsg
  *	@sk_sndmsg_off: cached offset for sendmsg
  *	@sk_send_head: front of stuff to transmit
  *	@sk_security: used by security modules
  *	@sk_write_pending: a write to stream socket waits to start
  *	@sk_state_change: callback to indicate change in the state of the sock
  *	@sk_data_ready: callback to indicate there is data to be processed
  *	@sk_write_space: callback to indicate there is bf sending space available
  *	@sk_error_report: callback to indicate errors (e.g. %MSG_ERRQUEUE)
  *	@sk_backlog_rcv: callback to process the backlog
  *	@sk_destruct: called at sock freeing time, i.e. when all refcnt == 0
 */
struct sock {
	/*
	 * Now struct inet_timewait_sock also uses sock_common, so please just
	 * don't add nothing before this first member (__sk_common) --acme
	 */
	struct sock_common	__sk_common;
#define sk_family		__sk_common.skc_family
#define sk_state		__sk_common.skc_state
#define sk_reuse		__sk_common.skc_reuse
#define sk_bound_dev_if		__sk_common.skc_bound_dev_if
#define sk_node			__sk_common.skc_node
#define sk_bind_node		__sk_common.skc_bind_node
#define sk_refcnt		__sk_common.skc_refcnt
#define sk_hash			__sk_common.skc_hash
#define sk_prot			__sk_common.skc_prot
	/*
	 * 关闭标志，RCV_SHUTDOWN接受关闭，SEND_SHUTDOWN 发送关闭，SHUTDOWN_MASK完全关闭
	 */
	unsigned char		sk_shutdown : 2,
						/*raw udp是否执行校验和*/
				sk_no_check : 2,
				/*标识传输层的一些状态
				 *SOCK_SNDBUF_LOCK:用户通过套接口选项设置了发送缓冲区大小
				 *SOCK_RCVBUF_LOCK:用户通过套接口选项设置了接受缓冲区大小
				 *SOCK_BINDADDR_LOCK:绑定了本地地址
				 *SOCK_BINDPORT_LOCK:绑定了本地端口
				 **/
				sk_userlocks : 4;
	/*套接口协议*/
	unsigned char		sk_protocol;
	/*套接口类型*/
	unsigned short		sk_type;
	/*接受缓冲区大小的上限*/
	int			sk_rcvbuf;
	/*
	 *同步锁：包括两种锁，一种是用户进程读取数据和网络层向传输层传递数据之间的锁
	 * 二是控制linux下半步访问本传输控制块的同步锁，以免多个下半步同时访问本传输控制块
	 */
	socket_lock_t		sk_lock;
	/*
	 *进程等待队列，进程等待链接，等待输出缓冲区，等待读数据时，都会将进程暂存到此队列中.
	 */
	wait_queue_head_t	*sk_sleep;
	/*
	 * 目的路由缓存。一般都是在创建传输控制块发送数据报文时，发现未设置该字段才从路由表中或路由缓存中查询到相应的路由项来设置该字段
	 * 这样可以加速数据的输出，后续数据的输出不必再查询路由，某些情况下会刷新此目的路哟缓存，比如断开链接，重新进行链接，tcp重传，重新
	 * 绑定端口等操作
	 */
	struct dst_entry	*sk_dst_cache;
	/*与ipsec相关的传输策略*/
	struct xfrm_policy	*sk_policy[2];
	/*操作目的路由缓存的读写锁*/
	rwlock_t		sk_dst_lock;
	/*接受队列sk_receive_queue中所有报文的总长度*/
	atomic_t		sk_rmem_alloc;
	/*所在传输控制块，为发送而分配的所有skb数据区的大小*/
	atomic_t		sk_wmem_alloc;
	/*分配辅助缓冲区的上限，辅助数据包括进行设置选项，设置过滤时分配的内存和组播设置等*/
	atomic_t		sk_omem_alloc;
	/*
	 * 接受队列，等待用户进程读取，tcp比较特别，接受到的数据不能直接复制到用户空间才缓存在此
	 * */
	struct sk_buff_head	sk_receive_queue;
	/*
	 *发送队列，在tcp中，此队列也是重传队列，在sk_send_head之前为重传队列，之后为发送队列。
	 */
	struct sk_buff_head	sk_write_queue;
	/*与网络设备的dma相关*/
	struct sk_buff_head	sk_async_wait_queue;
	/*发送队列中，所有报文数据的总长度，目前只用于tcp*/
	int			sk_wmem_queued;
	/*预分配缓存长度，这只是一个标识，目前只用于tcp，当分配的缓存小于该值时，分配必然成功，否则需重新确认的分配的缓存是否有效*/
	int			sk_forward_alloc;
	gfp_t			sk_allocation;
	/*发送缓冲区长度的上限，发送队列中，报文总长度不能超过该值*/
	int			sk_sndbuf;
	/*目的路由设备的特性*/
	int			sk_route_caps;
	/*传输层支持的GSO类型*/
	int			sk_gso_type;
	/*标识接受缓存下限值*/
	int			sk_rcvlowat;
	/*一些状态和标志*/
	unsigned long 		sk_flags;
	/*SO_LINGER 那个时间参数*/
	unsigned long	        sk_lingertime;
	/*
	 * The backlog queue is special, it is always used with
	 * the per-socket spinlock held and requires low latency
	 * access. Therefore we special case it's implementation.
	 */
	/*
	 *后备接受队列，目前只用户TCP，传输控制块被上锁后(如应用层读取数据),当有新的报文传输到传输控制块时，
	 *只能把报文放到后备队列，之后有用户进程读取tcp数据时，再从该队列取出，复制到用户空间
	 */
	struct {
		struct sk_buff *head;
		struct sk_buff *tail;
	} sk_backlog;
	/*错误链表，存放详细的出错信息。应用程序通过setsockopt IP_RECVERR选项，即需获取详细出错信息，当有错误发生时，可通过
	 * recvmsg(),参数为MSG_ERRQUEUE来获取详细的出错信息*/
	struct sk_buff_head	sk_error_queue;
	struct proto		*sk_prot_creator;
	/**/
	rwlock_t		sk_callback_lock;
	/*记录当前传输层中发生的最后一次致命错误的错误码，应用层读取后会自动初恢复为初始状态*/
	int			sk_err,
				/*用于记录非致命的错误，或者用作在传输控制块被锁定时记录错误的后备队员*/
				sk_err_soft;
	/*当前已建立的链接数，没有被accept的*/
	unsigned short		sk_ack_backlog;
	/*连接队列长度的上限(listen参数)*/
	unsigned short		sk_max_ack_backlog;
	/*用于设置由此套接口输出数据包的Qos类别*/
	__u32			sk_priority;
	/*返回连接至该套接口的外部进程的身份认证，目前主要用于PF_UNIX协议族*/
	struct ucred		sk_peercred;
	/*套接子层接受时间，初始值为MAX_SCHEDULE_TIMEOUT
	 *可以通过SO_RCVTIMEO设置接受超时时间
	 */
	long			sk_rcvtimeo;
	/*发送超时时间*/
	long			sk_sndtimeo;
	/*套接口过滤器，在传输层对输入的数据包通过BPF过滤代码进行过滤，只对设置了套接口过滤器的进程有效。*/
	struct sk_filter      	*sk_filter;
	/*传输控制块存放私有数据的指针*/
	void			*sk_protinfo;
	/*通过tcp的不同状态，来实现连接定时器，FIN_WAIT_2定时器及tcp保活定时器*/
	struct timer_list	sk_timer;
	/*未启用SOCK_RCVTSTAMP套接口选项时，记录报文接受数据到应用层的时间戳，在启用SOCK_RCVTSTAMP套接口选项时，
	 * 接受数据到应用层的时间戳记录在SKB的tstamp中*/
	struct timeval		sk_stamp;
	/*指向对应套接口的指针*/
	struct socket		*sk_socket;
	/* RPC层存放私有数据的指针*/
	void			*sk_user_data;
	struct page		*sk_sndmsg_page;
	/*sk_write_space发送队列第一个未发送的节点，前边的是重传队列，后面的是发送队列*/
	struct sk_buff		*sk_send_head;
	/*sk_sndmsg_page中的数据尾的偏移*/
	__u32			sk_sndmsg_off;
	/*标识有数据写入套接口，也就是有写书据的请求*/
	int			sk_write_pending;
	void			*sk_security;
	/*当传输控制块的状态发生变化时，唤醒那些等待本套接口的进程，在创建套接口时初始化。*/
	void			(*sk_state_change)(struct sock *sk);
	/*当有数据接受到达处理时，唤醒或发信号通知等待本套接口的进程，在创建套接口时被初始化。*/
	void			(*sk_data_ready)(struct sock *sk, int bytes);
	/*当发送缓存大小发生变化或套接口释放时，唤醒因等待本套接口而处于睡眠状态的进程，包括sk_sleep队列和fasync_list队列上的进程*/
	void			(*sk_write_space)(struct sock *sk);
	/*报告错误的回调函数，如果等待该传输控制块的进程正在睡眠，则将其唤醒*/
	void			(*sk_error_report)(struct sock *sk);
	/*用于TCP和PPPoE中，用于接受预备队列和后备队列中的TCP段，tcp接口为tcp_v4_do_rcv,如果预备队列中还存在tcp段，则调用tcp_prequeue_process()
	 * 预处理，该函数会回调sk_backlog_rcv,如果后备队列中还存在tcp段，则调用 release_sock()处理，也会调用sk_backlog_rcv.该函数在
	 * 创建套接口的传输控制块时由传输层的backlog_rcv接口初始化*/
  	int			(*sk_backlog_rcv)(struct sock *sk,
						  struct sk_buff *skb);  
	/*进行传输控制块的销毁，在释放传输控制块前释放一些其他资源，在sk_free()释放传输控制块时调用，当传输控制块的计数为0时，才真正释放，ipv4中
	 * 为inet_sock_destruct()*/
	void                    (*sk_destruct)(struct sock *sk);
};

/*
 * Hashed lists helper routines
 */
static inline struct sock *__sk_head(const struct hlist_head *head)
{
	return hlist_entry(head->first, struct sock, sk_node);
}

static inline struct sock *sk_head(const struct hlist_head *head)
{
	return hlist_empty(head) ? NULL : __sk_head(head);
}

static inline struct sock *sk_next(const struct sock *sk)
{
	return sk->sk_node.next ?
		hlist_entry(sk->sk_node.next, struct sock, sk_node) : NULL;
}

static inline int sk_unhashed(const struct sock *sk)
{
	return hlist_unhashed(&sk->sk_node);
}

static inline int sk_hashed(const struct sock *sk)
{
	return !sk_unhashed(sk);
}

static __inline__ void sk_node_init(struct hlist_node *node)
{
	node->pprev = NULL;
}

static __inline__ void __sk_del_node(struct sock *sk)
{
	__hlist_del(&sk->sk_node);
}

static __inline__ int __sk_del_node_init(struct sock *sk)
{
	if (sk_hashed(sk)) {
		__sk_del_node(sk);
		sk_node_init(&sk->sk_node);
		return 1;
	}
	return 0;
}

/* Grab socket reference count. This operation is valid only
   when sk is ALREADY grabbed f.e. it is found in hash table
   or a list and the lookup is made under lock preventing hash table
   modifications.
 */

static inline void sock_hold(struct sock *sk)
{
	atomic_inc(&sk->sk_refcnt);
}

/* Ungrab socket in the context, which assumes that socket refcnt
   cannot hit zero, f.e. it is true in context of any socketcall.
 */
static inline void __sock_put(struct sock *sk)
{
	atomic_dec(&sk->sk_refcnt);
}

static __inline__ int sk_del_node_init(struct sock *sk)
{
	int rc = __sk_del_node_init(sk);

	if (rc) {
		/* paranoid for a while -acme */
		WARN_ON(atomic_read(&sk->sk_refcnt) == 1);
		__sock_put(sk);
	}
	return rc;
}

static __inline__ void __sk_add_node(struct sock *sk, struct hlist_head *list)
{
	hlist_add_head(&sk->sk_node, list);
}

static __inline__ void sk_add_node(struct sock *sk, struct hlist_head *list)
{
	sock_hold(sk);
	__sk_add_node(sk, list);
}

static __inline__ void __sk_del_bind_node(struct sock *sk)
{
	__hlist_del(&sk->sk_bind_node);
}

static __inline__ void sk_add_bind_node(struct sock *sk,
					struct hlist_head *list)
{
	hlist_add_head(&sk->sk_bind_node, list);
}

#define sk_for_each(__sk, node, list) \
	hlist_for_each_entry(__sk, node, list, sk_node)
#define sk_for_each_from(__sk, node) \
	if (__sk && ({ node = &(__sk)->sk_node; 1; })) \
		hlist_for_each_entry_from(__sk, node, sk_node)
#define sk_for_each_continue(__sk, node) \
	if (__sk && ({ node = &(__sk)->sk_node; 1; })) \
		hlist_for_each_entry_continue(__sk, node, sk_node)
#define sk_for_each_safe(__sk, node, tmp, list) \
	hlist_for_each_entry_safe(__sk, node, tmp, list, sk_node)
#define sk_for_each_bound(__sk, node, list) \
	hlist_for_each_entry(__sk, node, list, sk_bind_node)

/* Sock flags */
enum sock_flags {
	/*链接已端口，套接口即将关闭*/
	SOCK_DEAD,
	/*标志tcp会话即将结束，再接受到FIN时设置*/
	SOCK_DONE,
	/*带外数据放入正常的数据流，在普通数据流中接受带外数据*/
	SOCK_URGINLINE,
	/*启用tcp传输层的保活定时*/
	SOCK_KEEPOPEN,
	SOCK_LINGER,
	/*协议控制块已释放，ipv4协议未使用*/
	SOCK_DESTROY,
	/*套接口支持收发广播报文*/
	SOCK_BROADCAST,
	/*标识是否启用段的接受时间作为时间戳*/
	SOCK_TIMESTAMP,
	/*在ax25和ipx协议中标识已建立链接，ipv4未使用*/
	SOCK_ZAPPED,
	/*标识是否初始化传输控制块的sk_write_space()指针，这样在sock_wfree()中sk_write_space会被调用*/
	SOCK_USE_WRITE_QUEUE, /* whether to call sk->sk_write_space in sock_wfree */
	/*记录套接口的调试信息*/
	SOCK_DBG, /* %SO_DEBUG setting */
	/*数据包的接受时间作为时间戳*/
	SOCK_RCVTSTAMP, /* %SO_TIMESTAMP setting */
	/*使用本地路由还是策略路由*/
	SOCK_LOCALROUTE, /* route locally only, %SO_DONTROUTE setting */
	/*发送队列的缓存区最近是否缩小过*/
	SOCK_QUEUE_SHRUNK, /* write queue has been shrunk recently */
};

static inline void sock_copy_flags(struct sock *nsk, struct sock *osk)
{
	nsk->sk_flags = osk->sk_flags;
}

static inline void sock_set_flag(struct sock *sk, enum sock_flags flag)
{
	__set_bit(flag, &sk->sk_flags);
}

static inline void sock_reset_flag(struct sock *sk, enum sock_flags flag)
{
	__clear_bit(flag, &sk->sk_flags);
}

static inline int sock_flag(struct sock *sk, enum sock_flags flag)
{
	return test_bit(flag, &sk->sk_flags);
}

static inline void sk_acceptq_removed(struct sock *sk)
{
	sk->sk_ack_backlog--;
}

static inline void sk_acceptq_added(struct sock *sk)
{
	sk->sk_ack_backlog++;
}

static inline int sk_acceptq_is_full(struct sock *sk)
{
	return sk->sk_ack_backlog > sk->sk_max_ack_backlog;
}

/*
 * Compute minimal free write space needed to queue new packets.
 */
static inline int sk_stream_min_wspace(struct sock *sk)
{
	return sk->sk_wmem_queued / 2;
}

static inline int sk_stream_wspace(struct sock *sk)
{
	return sk->sk_sndbuf - sk->sk_wmem_queued;
}

extern void sk_stream_write_space(struct sock *sk);

static inline int sk_stream_memory_free(struct sock *sk)
{
	return sk->sk_wmem_queued < sk->sk_sndbuf;
}

extern void sk_stream_rfree(struct sk_buff *skb);

static inline void sk_stream_set_owner_r(struct sk_buff *skb, struct sock *sk)
{
	skb->sk = sk;
	skb->destructor = sk_stream_rfree;
	atomic_add(skb->truesize, &sk->sk_rmem_alloc);
	sk->sk_forward_alloc -= skb->truesize;
}

static inline void sk_stream_free_skb(struct sock *sk, struct sk_buff *skb)
{
	skb_truesize_check(skb);
	sock_set_flag(sk, SOCK_QUEUE_SHRUNK);
	sk->sk_wmem_queued   -= skb->truesize;
	sk->sk_forward_alloc += skb->truesize;
	__kfree_skb(skb);
}

/* The per-socket spinlock must be held here. */
static inline void sk_add_backlog(struct sock *sk, struct sk_buff *skb)
{
	if (!sk->sk_backlog.tail) {
		sk->sk_backlog.head = sk->sk_backlog.tail = skb;
	} else {
		sk->sk_backlog.tail->next = skb;
		sk->sk_backlog.tail = skb;
	}
	skb->next = NULL;
}

#define sk_wait_event(__sk, __timeo, __condition)		\
({	int rc;							\
	release_sock(__sk);					\
	rc = __condition;					\
	if (!rc) {						\
		*(__timeo) = schedule_timeout(*(__timeo));	\
	}							\
	lock_sock(__sk);					\
	rc = __condition;					\
	rc;							\
})

extern int sk_stream_wait_connect(struct sock *sk, long *timeo_p);
extern int sk_stream_wait_memory(struct sock *sk, long *timeo_p);
extern void sk_stream_wait_close(struct sock *sk, long timeo_p);
extern int sk_stream_error(struct sock *sk, int flags, int err);
extern void sk_stream_kill_queues(struct sock *sk);

extern int sk_wait_data(struct sock *sk, long *timeo);

struct request_sock_ops;
struct timewait_sock_ops;

/* Networking protocol blocks we attach to sockets.
 * socket layer -> transport layer interface
 * transport -> network interface is defined by struct inet_proto
 */
/*从传输层->网络层,tcp_prot  udp_prot  raw_prot*/
struct proto {
	void			(*close)(struct sock *sk, 
					long timeout);
	int			(*connect)(struct sock *sk,
				        struct sockaddr *uaddr, 
					int addr_len);
	int			(*disconnect)(struct sock *sk, int flags);

	struct sock *		(*accept) (struct sock *sk, int flags, int *err);

	int			(*ioctl)(struct sock *sk, int cmd,
					 unsigned long arg);
	/*传输层接口初始话，在创建套接口时，在inet_create函数中调用*/
	int			(*init)(struct sock *sk);
	/*没有与之对应的系统调用，当关闭套接口时调用*/
	int			(*destroy)(struct sock *sk);
	void			(*shutdown)(struct sock *sk, int how);
	int			(*setsockopt)(struct sock *sk, int level, 
					int optname, char __user *optval,
					int optlen);
	int			(*getsockopt)(struct sock *sk, int level, 
					int optname, char __user *optval, 
					int __user *option);  	 
	int			(*compat_setsockopt)(struct sock *sk,
					int level,
					int optname, char __user *optval,
					int optlen);
	int			(*compat_getsockopt)(struct sock *sk,
					int level,
					int optname, char __user *optval,
					int __user *option);
	int			(*sendmsg)(struct kiocb *iocb, struct sock *sk,
					   struct msghdr *msg, size_t len);
	int			(*recvmsg)(struct kiocb *iocb, struct sock *sk,
					   struct msghdr *msg,
					size_t len, int noblock, int flags, 
					int *addr_len);
	int			(*sendpage)(struct sock *sk, struct page *page,
					int offset, size_t size, int flags);
	int			(*bind)(struct sock *sk, 
					struct sockaddr *uaddr, int addr_len);

	/*用于接受预备队列和后备队列中的段*/
	int			(*backlog_rcv) (struct sock *sk, 
						struct sk_buff *skb);

	/* Keeping track of sk's, looking them up, and port selection methods. */
	/*hash为添加到管理传输控制块散列表的接口，unhash为从管理传输控制块散列表删除的接口
	 * 不同的传输层协议组织管理传输控制块不一样，因此需要提供不同的方法，tcp为tcp_v4_hash 和tcp_unhash.
	 * udp不许要hash接口 只有unhash接口*/
	void			(*hash)(struct sock *sk);
	void			(*unhash)(struct sock *sk);
	/*实现地址与端口的绑定，snum为绑定的端口，如果为0，则自动选择一个临时端口，tcp为tcp_v4_get_port  udp为udp_v4_get_port*/
	int			(*get_port)(struct sock *sk, unsigned short snum);

	/* Memory pressure */
	/*目前只有tcp使用，当前整个tcp传输层中为缓冲区分配的内存超过tcp_mem[1]，便进入告警状态，会调用此接口设置告警状态，
	 * 在tcp中 指向tcp_enter_memory_pressure*/
	void			(*enter_memory_pressure)(void);
	/*目前tcp使用，标识当前tcp传输层中为缓冲区分配的内存(包括输入缓冲队列),在tcp中为tcp_memory_allocated*/
	atomic_t		*memory_allocated;	/* Current allocated memory. */
	/*标识当前在tcp中已创建的套接口的数目，目前只在tcp中使用，它指向变量tcp_sockets_allocated*/
	atomic_t		*sockets_allocated;	/* Current number of sockets. */
	/*
	 * Pressure flag: try to collapse.
	 * Technical note: it is used by multiple contexts non atomically.
	 * All the sk_stream_mem_schedule() is of this nature: accounting
	 * is strict, actions are advisory and have some latency.
	 */
	/*
	 * 标志，目前只在tcp中使用，在tcp传输层中 缓冲大小进入警告状态时，置1，否则置0，指向变量tcp_memory_presssure
	 */
	int			*memory_pressure;
	/*sysctl_tcp_mem*/
	int			*sysctl_mem;
	/*sysctl_tcp_wmem*/
	int			*sysctl_wmem;
	/*sysctl_tcp_rmem*/
	int			*sysctl_rmem;
	/*目前只在tcp中使用，tcp首部的最大长度，考虑了所有的选项*/
	int			max_header;

	/*用来分配传输控制块的slab高速缓存*/
	struct kmem_cache		*slab;
	/*传输控制块大小*/
	unsigned int		obj_size;

	/*目前只在tcp中使用，标识整个tcp传输层中待销毁的套接口的数目。在tcp中，它指向变量tcp_orphan_count*/
	atomic_t		*orphan_count;

	/*目前只在tcp中使用，指向链接请求处理接口集合，包括发送SYN+ACK实现*/
	struct request_sock_ops	*rsk_prot;
	/*目前只在tcp中使用，指向timewait控制块操作接口,tcp中为tcp_timewait_sock_ops.
	 * timewait_sock_ops提供两个操作接口，tcp_twsk_unique()用于检测被timewait控制块绑定的端口是否可用，
	 * 而twsk_destructor()用于在释放timewait控制块时，在启用MD5数字签名的情况下做一些清理工作*/
	struct timewait_sock_ops *twsk_prot;

	struct module		*owner;

	/*传输层名称，tcp协议为tcp   udp协议为UDP*/
	char			name[32];

	/*注册到proto_list中*/
	struct list_head	node;
#ifdef SOCK_REFCNT_DEBUG
	atomic_t		socks;
#endif
	/*统计每个cpu的proto状态*/
	struct {
		int inuse;
		u8  __pad[SMP_CACHE_BYTES - sizeof(int)];
	} stats[NR_CPUS];
};

extern int proto_register(struct proto *prot, int alloc_slab);
extern void proto_unregister(struct proto *prot);

#ifdef SOCK_REFCNT_DEBUG
static inline void sk_refcnt_debug_inc(struct sock *sk)
{
	atomic_inc(&sk->sk_prot->socks);
}

static inline void sk_refcnt_debug_dec(struct sock *sk)
{
	atomic_dec(&sk->sk_prot->socks);
	printk(KERN_DEBUG "%s socket %p released, %d are still alive\n",
	       sk->sk_prot->name, sk, atomic_read(&sk->sk_prot->socks));
}

static inline void sk_refcnt_debug_release(const struct sock *sk)
{
	if (atomic_read(&sk->sk_refcnt) != 1)
		printk(KERN_DEBUG "Destruction of the %s socket %p delayed, refcnt=%d\n",
		       sk->sk_prot->name, sk, atomic_read(&sk->sk_refcnt));
}
#else /* SOCK_REFCNT_DEBUG */
#define sk_refcnt_debug_inc(sk) do { } while (0)
#define sk_refcnt_debug_dec(sk) do { } while (0)
#define sk_refcnt_debug_release(sk) do { } while (0)
#endif /* SOCK_REFCNT_DEBUG */

/* Called with local bh disabled */
static __inline__ void sock_prot_inc_use(struct proto *prot)
{
	prot->stats[smp_processor_id()].inuse++;
}

static __inline__ void sock_prot_dec_use(struct proto *prot)
{
	prot->stats[smp_processor_id()].inuse--;
}

/* With per-bucket locks this operation is not-atomic, so that
 * this version is not worse.
 */
static inline void __sk_prot_rehash(struct sock *sk)
{
	sk->sk_prot->unhash(sk);
	sk->sk_prot->hash(sk);
}

/* About 10 seconds */
#define SOCK_DESTROY_TIME (10*HZ)

/* Sockets 0-1023 can't be bound to unless you are superuser */
#define PROT_SOCK	1024

#define SHUTDOWN_MASK	3
#define RCV_SHUTDOWN	1
#define SEND_SHUTDOWN	2

#define SOCK_SNDBUF_LOCK	1
#define SOCK_RCVBUF_LOCK	2
#define SOCK_BINDADDR_LOCK	4
#define SOCK_BINDPORT_LOCK	8

/* sock_iocb: used to kick off async processing of socket ios */
struct sock_iocb {
	struct list_head	list;

	int			flags;
	int			size;
	struct socket		*sock;
	struct sock		*sk;
	struct scm_cookie	*scm;
	struct msghdr		*msg, async_msg;
	struct kiocb		*kiocb;
};

static inline struct sock_iocb *kiocb_to_siocb(struct kiocb *iocb)
{
	return (struct sock_iocb *)iocb->private;
}

static inline struct kiocb *siocb_to_kiocb(struct sock_iocb *si)
{
	return si->kiocb;
}

struct socket_alloc {
	struct socket socket;
	struct inode vfs_inode;
};

static inline struct socket *SOCKET_I(struct inode *inode)
{
	return &container_of(inode, struct socket_alloc, vfs_inode)->socket;
}

static inline struct inode *SOCK_INODE(struct socket *socket)
{
	return &container_of(socket, struct socket_alloc, socket)->vfs_inode;
}

extern void __sk_stream_mem_reclaim(struct sock *sk);
extern int sk_stream_mem_schedule(struct sock *sk, int size, int kind);

#define SK_STREAM_MEM_QUANTUM ((int)PAGE_SIZE)

static inline int sk_stream_pages(int amt)
{
	return (amt + SK_STREAM_MEM_QUANTUM - 1) / SK_STREAM_MEM_QUANTUM;
}

static inline void sk_stream_mem_reclaim(struct sock *sk)
{
	if (sk->sk_forward_alloc >= SK_STREAM_MEM_QUANTUM)
		__sk_stream_mem_reclaim(sk);
}

static inline void sk_stream_writequeue_purge(struct sock *sk)
{
	struct sk_buff *skb;

	while ((skb = __skb_dequeue(&sk->sk_write_queue)) != NULL)
		sk_stream_free_skb(sk, skb);
	sk_stream_mem_reclaim(sk);
}

static inline int sk_stream_rmem_schedule(struct sock *sk, struct sk_buff *skb)
{
	return (int)skb->truesize <= sk->sk_forward_alloc ||
		sk_stream_mem_schedule(sk, skb->truesize, 1);
}

static inline int sk_stream_wmem_schedule(struct sock *sk, int size)
{
	return size <= sk->sk_forward_alloc ||
	       sk_stream_mem_schedule(sk, size, 0);
}

/* Used by processes to "lock" a socket state, so that
 * interrupts and bottom half handlers won't change it
 * from under us. It essentially blocks any incoming
 * packets, so that we won't get any new data or any
 * packets that change the state of the socket.
 *
 * While locked, BH processing will add new packets to
 * the backlog queue.  This queue is processed by the
 * owner of the socket lock right before it is released.
 *
 * Since ~2.3.5 it is also exclusive sleep lock serializing
 * accesses from user process context.
 */
#define sock_owned_by_user(sk)	((sk)->sk_lock.owner)

/*
 * Macro so as to not evaluate some arguments when
 * lockdep is not enabled.
 *
 * Mark both the sk_lock and the sk_lock.slock as a
 * per-address-family lock class.
 */
#define sock_lock_init_class_and_name(sk, sname, skey, name, key) 	\
do {									\
	sk->sk_lock.owner = NULL;					\
	init_waitqueue_head(&sk->sk_lock.wq);				\
	spin_lock_init(&(sk)->sk_lock.slock);				\
	debug_check_no_locks_freed((void *)&(sk)->sk_lock,		\
			sizeof((sk)->sk_lock));				\
	lockdep_set_class_and_name(&(sk)->sk_lock.slock,		\
		       	(skey), (sname));				\
	lockdep_init_map(&(sk)->sk_lock.dep_map, (name), (key), 0);	\
} while (0)

extern void FASTCALL(lock_sock_nested(struct sock *sk, int subclass));

static inline void lock_sock(struct sock *sk)
{
	lock_sock_nested(sk, 0);
}

extern void FASTCALL(release_sock(struct sock *sk));

/* BH context may only use the following locking interface. */
#define bh_lock_sock(__sk)	spin_lock(&((__sk)->sk_lock.slock))
#define bh_lock_sock_nested(__sk) \
				spin_lock_nested(&((__sk)->sk_lock.slock), \
				SINGLE_DEPTH_NESTING)
#define bh_unlock_sock(__sk)	spin_unlock(&((__sk)->sk_lock.slock))

extern struct sock		*sk_alloc(int family,
					  gfp_t priority,
					  struct proto *prot, int zero_it);
extern void			sk_free(struct sock *sk);
extern struct sock		*sk_clone(const struct sock *sk,
					  const gfp_t priority);

extern struct sk_buff		*sock_wmalloc(struct sock *sk,
					      unsigned long size, int force,
					      gfp_t priority);
extern struct sk_buff		*sock_rmalloc(struct sock *sk,
					      unsigned long size, int force,
					      gfp_t priority);
extern void			sock_wfree(struct sk_buff *skb);
extern void			sock_rfree(struct sk_buff *skb);

extern int			sock_setsockopt(struct socket *sock, int level,
						int op, char __user *optval,
						int optlen);

extern int			sock_getsockopt(struct socket *sock, int level,
						int op, char __user *optval, 
						int __user *optlen);
extern struct sk_buff 		*sock_alloc_send_skb(struct sock *sk,
						     unsigned long size,
						     int noblock,
						     int *errcode);
extern void *sock_kmalloc(struct sock *sk, int size,
			  gfp_t priority);
extern void sock_kfree_s(struct sock *sk, void *mem, int size);
extern void sk_send_sigurg(struct sock *sk);

/*
 * Functions to fill in entries in struct proto_ops when a protocol
 * does not implement a particular function.
 */
extern int                      sock_no_bind(struct socket *, 
					     struct sockaddr *, int);
extern int                      sock_no_connect(struct socket *,
						struct sockaddr *, int, int);
extern int                      sock_no_socketpair(struct socket *,
						   struct socket *);
extern int                      sock_no_accept(struct socket *,
					       struct socket *, int);
extern int                      sock_no_getname(struct socket *,
						struct sockaddr *, int *, int);
extern unsigned int             sock_no_poll(struct file *, struct socket *,
					     struct poll_table_struct *);
extern int                      sock_no_ioctl(struct socket *, unsigned int,
					      unsigned long);
extern int			sock_no_listen(struct socket *, int);
extern int                      sock_no_shutdown(struct socket *, int);
extern int			sock_no_getsockopt(struct socket *, int , int,
						   char __user *, int __user *);
extern int			sock_no_setsockopt(struct socket *, int, int,
						   char __user *, int);
extern int                      sock_no_sendmsg(struct kiocb *, struct socket *,
						struct msghdr *, size_t);
extern int                      sock_no_recvmsg(struct kiocb *, struct socket *,
						struct msghdr *, size_t, int);
extern int			sock_no_mmap(struct file *file,
					     struct socket *sock,
					     struct vm_area_struct *vma);
extern ssize_t			sock_no_sendpage(struct socket *sock,
						struct page *page,
						int offset, size_t size, 
						int flags);

/*
 * Functions to fill in entries in struct proto_ops when a protocol
 * uses the inet style.
 */
extern int sock_common_getsockopt(struct socket *sock, int level, int optname,
				  char __user *optval, int __user *optlen);
extern int sock_common_recvmsg(struct kiocb *iocb, struct socket *sock,
			       struct msghdr *msg, size_t size, int flags);
extern int sock_common_setsockopt(struct socket *sock, int level, int optname,
				  char __user *optval, int optlen);
extern int compat_sock_common_getsockopt(struct socket *sock, int level,
		int optname, char __user *optval, int __user *optlen);
extern int compat_sock_common_setsockopt(struct socket *sock, int level,
		int optname, char __user *optval, int optlen);

extern void sk_common_release(struct sock *sk);

/*
 *	Default socket callbacks and setup code
 */
 
/* Initialise core socket variables */
extern void sock_init_data(struct socket *sock, struct sock *sk);

/**
 *	sk_filter - run a packet through a socket filter
 *	@sk: sock associated with &sk_buff
 *	@skb: buffer to filter
 *	@needlock: set to 1 if the sock is not locked by caller.
 *
 * Run the filter code and then cut skb->data to correct size returned by
 * sk_run_filter. If pkt_len is 0 we toss packet. If skb->len is smaller
 * than pkt_len we keep whole skb->data. This is the socket level
 * wrapper to sk_run_filter. It returns 0 if the packet should
 * be accepted or -EPERM if the packet should be tossed.
 *
 */

static inline int sk_filter(struct sock *sk, struct sk_buff *skb)
{
	int err;
	struct sk_filter *filter;
	
	err = security_sock_rcv_skb(sk, skb);
	if (err)
		return err;
	
	rcu_read_lock_bh();
	filter = sk->sk_filter;
	if (filter) {
		unsigned int pkt_len = sk_run_filter(skb, filter->insns,
				filter->len);
		err = pkt_len ? pskb_trim(skb, pkt_len) : -EPERM;
	}
 	rcu_read_unlock_bh();

	return err;
}

/**
 * 	sk_filter_rcu_free: Free a socket filter
 *	@rcu: rcu_head that contains the sk_filter to free
 */
static inline void sk_filter_rcu_free(struct rcu_head *rcu)
{
	struct sk_filter *fp = container_of(rcu, struct sk_filter, rcu);
	kfree(fp);
}

/**
 *	sk_filter_release: Release a socket filter
 *	@sk: socket
 *	@fp: filter to remove
 *
 *	Remove a filter from a socket and release its resources.
 */

static inline void sk_filter_release(struct sock *sk, struct sk_filter *fp)
{
	unsigned int size = sk_filter_len(fp);

	atomic_sub(size, &sk->sk_omem_alloc);

	if (atomic_dec_and_test(&fp->refcnt))
		call_rcu_bh(&fp->rcu, sk_filter_rcu_free);
}

static inline void sk_filter_charge(struct sock *sk, struct sk_filter *fp)
{
	atomic_inc(&fp->refcnt);
	atomic_add(sk_filter_len(fp), &sk->sk_omem_alloc);
}

/*
 * Socket reference counting postulates.
 *
 * * Each user of socket SHOULD hold a reference count.
 * * Each access point to socket (an hash table bucket, reference from a list,
 *   running timer, skb in flight MUST hold a reference count.
 * * When reference count hits 0, it means it will never increase back.
 * * When reference count hits 0, it means that no references from
 *   outside exist to this socket and current process on current CPU
 *   is last user and may/should destroy this socket.
 * * sk_free is called from any context: process, BH, IRQ. When
 *   it is called, socket has no references from outside -> sk_free
 *   may release descendant resources allocated by the socket, but
 *   to the time when it is called, socket is NOT referenced by any
 *   hash tables, lists etc.
 * * Packets, delivered from outside (from network or from another process)
 *   and enqueued on receive/error queues SHOULD NOT grab reference count,
 *   when they sit in queue. Otherwise, packets will leak to hole, when
 *   socket is looked up by one cpu and unhasing is made by another CPU.
 *   It is true for udp/raw, netlink (leak to receive and error queues), tcp
 *   (leak to backlog). Packet socket does all the processing inside
 *   BR_NETPROTO_LOCK, so that it has not this race condition. UNIX sockets
 *   use separate SMP lock, so that they are prone too.
 */

/* Ungrab socket and destroy it, if it was the last reference. */
static inline void sock_put(struct sock *sk)
{
	if (atomic_dec_and_test(&sk->sk_refcnt))
		sk_free(sk);
}

extern int sk_receive_skb(struct sock *sk, struct sk_buff *skb,
			  const int nested);

/* Detach socket from process context.
 * Announce socket dead, detach it from wait queue and inode.
 * Note that parent inode held reference count on this struct sock,
 * we do not release it in this function, because protocol
 * probably wants some additional cleanups or even continuing
 * to work with this socket (TCP).
 */
static inline void sock_orphan(struct sock *sk)
{
	write_lock_bh(&sk->sk_callback_lock);
	sock_set_flag(sk, SOCK_DEAD);
	sk->sk_socket = NULL;
	sk->sk_sleep  = NULL;
	write_unlock_bh(&sk->sk_callback_lock);
}

static inline void sock_graft(struct sock *sk, struct socket *parent)
{
	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_sleep = &parent->wait;
	parent->sk = sk;
	sk->sk_socket = parent;
	security_sock_graft(sk, parent);
	write_unlock_bh(&sk->sk_callback_lock);
}

static inline void sock_copy(struct sock *nsk, const struct sock *osk)
{
#ifdef CONFIG_SECURITY_NETWORK
	void *sptr = nsk->sk_security;
#endif

	memcpy(nsk, osk, osk->sk_prot->obj_size);
#ifdef CONFIG_SECURITY_NETWORK
	nsk->sk_security = sptr;
	security_sk_clone(osk, nsk);
#endif
}

extern int sock_i_uid(struct sock *sk);
extern unsigned long sock_i_ino(struct sock *sk);

static inline struct dst_entry *
__sk_dst_get(struct sock *sk)
{
	return sk->sk_dst_cache;
}

static inline struct dst_entry *
sk_dst_get(struct sock *sk)
{
	struct dst_entry *dst;

	read_lock(&sk->sk_dst_lock);
	dst = sk->sk_dst_cache;
	if (dst)
		dst_hold(dst);
	read_unlock(&sk->sk_dst_lock);
	return dst;
}

static inline void
__sk_dst_set(struct sock *sk, struct dst_entry *dst)
{
	struct dst_entry *old_dst;

	old_dst = sk->sk_dst_cache;
	sk->sk_dst_cache = dst;
	dst_release(old_dst);
}

static inline void
sk_dst_set(struct sock *sk, struct dst_entry *dst)
{
	write_lock(&sk->sk_dst_lock);
	__sk_dst_set(sk, dst);
	write_unlock(&sk->sk_dst_lock);
}

static inline void
__sk_dst_reset(struct sock *sk)
{
	struct dst_entry *old_dst;

	old_dst = sk->sk_dst_cache;
	sk->sk_dst_cache = NULL;
	dst_release(old_dst);
}

static inline void
sk_dst_reset(struct sock *sk)
{
	write_lock(&sk->sk_dst_lock);
	__sk_dst_reset(sk);
	write_unlock(&sk->sk_dst_lock);
}

extern struct dst_entry *__sk_dst_check(struct sock *sk, u32 cookie);

extern struct dst_entry *sk_dst_check(struct sock *sk, u32 cookie);

static inline int sk_can_gso(const struct sock *sk)
{
	return net_gso_ok(sk->sk_route_caps, sk->sk_gso_type);
}

static inline void sk_setup_caps(struct sock *sk, struct dst_entry *dst)
{
	__sk_dst_set(sk, dst);
	sk->sk_route_caps = dst->dev->features;
	if (sk->sk_route_caps & NETIF_F_GSO)
		sk->sk_route_caps |= NETIF_F_GSO_MASK;
	if (sk_can_gso(sk)) {
		if (dst->header_len)
			sk->sk_route_caps &= ~NETIF_F_GSO_MASK;
		else 
			sk->sk_route_caps |= NETIF_F_SG | NETIF_F_HW_CSUM;
	}
}

static inline void sk_charge_skb(struct sock *sk, struct sk_buff *skb)
{
	sk->sk_wmem_queued   += skb->truesize;
	sk->sk_forward_alloc -= skb->truesize;
}

static inline int skb_copy_to_page(struct sock *sk, char __user *from,
				   struct sk_buff *skb, struct page *page,
				   int off, int copy)
{
	if (skb->ip_summed == CHECKSUM_NONE) {
		int err = 0;
		__wsum csum = csum_and_copy_from_user(from,
						     page_address(page) + off,
							    copy, 0, &err);
		if (err)
			return err;
		skb->csum = csum_block_add(skb->csum, csum, skb->len);
	} else if (copy_from_user(page_address(page) + off, from, copy))
		return -EFAULT;

	skb->len	     += copy;
	skb->data_len	     += copy;
	skb->truesize	     += copy;
	sk->sk_wmem_queued   += copy;
	sk->sk_forward_alloc -= copy;
	return 0;
}

/*
 * 	Queue a received datagram if it will fit. Stream and sequenced
 *	protocols can't normally use this as they need to fit buffers in
 *	and play with them.
 *
 * 	Inlined as it's very short and called for pretty much every
 *	packet ever received.
 */

static inline void skb_set_owner_w(struct sk_buff *skb, struct sock *sk)
{
	sock_hold(sk);
	skb->sk = sk;
	skb->destructor = sock_wfree;
	atomic_add(skb->truesize, &sk->sk_wmem_alloc);
}

static inline void skb_set_owner_r(struct sk_buff *skb, struct sock *sk)
{
	skb->sk = sk;
	skb->destructor = sock_rfree;
	atomic_add(skb->truesize, &sk->sk_rmem_alloc);
}

extern void sk_reset_timer(struct sock *sk, struct timer_list* timer,
			   unsigned long expires);

extern void sk_stop_timer(struct sock *sk, struct timer_list* timer);

extern int sock_queue_rcv_skb(struct sock *sk, struct sk_buff *skb);

static inline int sock_queue_err_skb(struct sock *sk, struct sk_buff *skb)
{
	/* Cast skb->rcvbuf to unsigned... It's pointless, but reduces
	   number of warnings when compiling with -W --ANK
	 */
	if (atomic_read(&sk->sk_rmem_alloc) + skb->truesize >=
	    (unsigned)sk->sk_rcvbuf)
		return -ENOMEM;
	skb_set_owner_r(skb, sk);
	skb_queue_tail(&sk->sk_error_queue, skb);
	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_data_ready(sk, skb->len);
	return 0;
}

/*
 *	Recover an error report and clear atomically
 */
 
static inline int sock_error(struct sock *sk)
{
	int err;
	if (likely(!sk->sk_err))
		return 0;
	err = xchg(&sk->sk_err, 0);
	return -err;
}

static inline unsigned long sock_wspace(struct sock *sk)
{
	int amt = 0;

	if (!(sk->sk_shutdown & SEND_SHUTDOWN)) {
		amt = sk->sk_sndbuf - atomic_read(&sk->sk_wmem_alloc);
		if (amt < 0) 
			amt = 0;
	}
	return amt;
}

/*
 *@how 1:检测标识应用程序通过recv等调用时，是否在等待数据的接受
 *		2:检测传输控制块的发送队列是否达到上限
 *  	0:不做任何检测，直接向等待进程发送SIGIO信号
 *		3:向等待进程发送SIGURG信号
 *@band POLL_IN POLL_OUT POLL_MSG POLL_ERR POLL_PRI POLL_HUP
 */
static inline void sk_wake_async(struct sock *sk, int how, int band)
{
	if (sk->sk_socket && sk->sk_socket->fasync_list)
		sock_wake_async(sk->sk_socket, how, band);
}

#define SOCK_MIN_SNDBUF 2048
#define SOCK_MIN_RCVBUF 256

static inline void sk_stream_moderate_sndbuf(struct sock *sk)
{
	if (!(sk->sk_userlocks & SOCK_SNDBUF_LOCK)) {
		sk->sk_sndbuf = min(sk->sk_sndbuf, sk->sk_wmem_queued / 2);
		sk->sk_sndbuf = max(sk->sk_sndbuf, SOCK_MIN_SNDBUF);
	}
}

static inline struct sk_buff *sk_stream_alloc_pskb(struct sock *sk,
						   int size, int mem,
						   gfp_t gfp)
{
	struct sk_buff *skb;
	int hdr_len;

	hdr_len = SKB_DATA_ALIGN(sk->sk_prot->max_header);
	skb = alloc_skb_fclone(size + hdr_len, gfp);
	if (skb) {
		skb->truesize += mem;
		if (sk_stream_wmem_schedule(sk, skb->truesize)) {
			skb_reserve(skb, hdr_len);
			return skb;
		}
		__kfree_skb(skb);
	} else {
		sk->sk_prot->enter_memory_pressure();
		sk_stream_moderate_sndbuf(sk);
	}
	return NULL;
}

static inline struct sk_buff *sk_stream_alloc_skb(struct sock *sk,
						  int size,
						  gfp_t gfp)
{
	return sk_stream_alloc_pskb(sk, size, 0, gfp);
}

static inline struct page *sk_stream_alloc_page(struct sock *sk)
{
	struct page *page = NULL;

	page = alloc_pages(sk->sk_allocation, 0);
	if (!page) {
		sk->sk_prot->enter_memory_pressure();
		sk_stream_moderate_sndbuf(sk);
	}
	return page;
}

#define sk_stream_for_retrans_queue(skb, sk)				\
		for (skb = (sk)->sk_write_queue.next;			\
		     (skb != (sk)->sk_send_head) &&			\
		     (skb != (struct sk_buff *)&(sk)->sk_write_queue);	\
		     skb = skb->next)

/*from STCP for fast SACK Process*/
#define sk_stream_for_retrans_queue_from(skb, sk)			\
		for (; (skb != (sk)->sk_send_head) &&                   \
		     (skb != (struct sk_buff *)&(sk)->sk_write_queue);	\
		     skb = skb->next)

/*
 *	Default write policy as shown to user space via poll/select/SIGIO
 */
static inline int sock_writeable(const struct sock *sk) 
{
	return atomic_read(&sk->sk_wmem_alloc) < (sk->sk_sndbuf / 2);
}

static inline gfp_t gfp_any(void)
{
	return in_softirq() ? GFP_ATOMIC : GFP_KERNEL;
}

static inline long sock_rcvtimeo(const struct sock *sk, int noblock)
{
	return noblock ? 0 : sk->sk_rcvtimeo;
}

static inline long sock_sndtimeo(const struct sock *sk, int noblock)
{
	return noblock ? 0 : sk->sk_sndtimeo;
}

static inline int sock_rcvlowat(const struct sock *sk, int waitall, int len)
{
	return (waitall ? len : min_t(int, sk->sk_rcvlowat, len)) ? : 1;
}

/* Alas, with timeout socket operations are not restartable.
 * Compare this to poll().
 */
static inline int sock_intr_errno(long timeo)
{
	return timeo == MAX_SCHEDULE_TIMEOUT ? -ERESTARTSYS : -EINTR;
}

static __inline__ void
sock_recv_timestamp(struct msghdr *msg, struct sock *sk, struct sk_buff *skb)
{
	struct timeval stamp;

	skb_get_timestamp(skb, &stamp);
	if (sock_flag(sk, SOCK_RCVTSTAMP)) {
		/* Race occurred between timestamp enabling and packet
		   receiving.  Fill in the current time for now. */
		if (stamp.tv_sec == 0)
			do_gettimeofday(&stamp);
		skb_set_timestamp(skb, &stamp);
		put_cmsg(msg, SOL_SOCKET, SO_TIMESTAMP, sizeof(struct timeval),
			 &stamp);
	} else
		sk->sk_stamp = stamp;
}

/**
 * sk_eat_skb - Release a skb if it is no longer needed
 * @sk: socket to eat this skb from
 * @skb: socket buffer to eat
 * @copied_early: flag indicating whether DMA operations copied this data early
 *
 * This routine must be called with interrupts disabled or with the socket
 * locked so that the sk_buff queue operation is ok.
*/
#ifdef CONFIG_NET_DMA
static inline void sk_eat_skb(struct sock *sk, struct sk_buff *skb, int copied_early)
{
	__skb_unlink(skb, &sk->sk_receive_queue);
	if (!copied_early)
		__kfree_skb(skb);
	else
		__skb_queue_tail(&sk->sk_async_wait_queue, skb);
}
#else
static inline void sk_eat_skb(struct sock *sk, struct sk_buff *skb, int copied_early)
{
	__skb_unlink(skb, &sk->sk_receive_queue);
	__kfree_skb(skb);
}
#endif

extern void sock_enable_timestamp(struct sock *sk);
extern int sock_get_timestamp(struct sock *, struct timeval __user *);

/* 
 *	Enable debug/info messages 
 */

#ifdef CONFIG_NETDEBUG
#define NETDEBUG(fmt, args...)	printk(fmt,##args)
#define LIMIT_NETDEBUG(fmt, args...) do { if (net_ratelimit()) printk(fmt,##args); } while(0)
#else
#define NETDEBUG(fmt, args...)	do { } while (0)
#define LIMIT_NETDEBUG(fmt, args...) do { } while(0)
#endif

/*
 * Macros for sleeping on a socket. Use them like this:
 *
 * SOCK_SLEEP_PRE(sk)
 * if (condition)
 * 	schedule();
 * SOCK_SLEEP_POST(sk)
 *
 * N.B. These are now obsolete and were, afaik, only ever used in DECnet
 * and when the last use of them in DECnet has gone, I'm intending to
 * remove them.
 */

#define SOCK_SLEEP_PRE(sk) 	{ struct task_struct *tsk = current; \
				DECLARE_WAITQUEUE(wait, tsk); \
				tsk->state = TASK_INTERRUPTIBLE; \
				add_wait_queue((sk)->sk_sleep, &wait); \
				release_sock(sk);

#define SOCK_SLEEP_POST(sk)	tsk->state = TASK_RUNNING; \
				remove_wait_queue((sk)->sk_sleep, &wait); \
				lock_sock(sk); \
				}

static inline void sock_valbool_flag(struct sock *sk, int bit, int valbool)
{
	if (valbool)
		sock_set_flag(sk, bit);
	else
		sock_reset_flag(sk, bit);
}

extern __u32 sysctl_wmem_max;
extern __u32 sysctl_rmem_max;

#ifdef CONFIG_NET
int siocdevprivate_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg);
#else
static inline int siocdevprivate_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
	return -ENODEV;
}
#endif

extern void sk_init(void);

#ifdef CONFIG_SYSCTL
extern struct ctl_table core_table[];
#endif

extern int sysctl_optmem_max;

extern __u32 sysctl_wmem_default;
extern __u32 sysctl_rmem_default;

#endif	/* _SOCK_H */

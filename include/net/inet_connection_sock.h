/*
 * NET		Generic infrastructure for INET connection oriented protocols.
 *
 *		Definitions for inet_connection_sock 
 *
 * Authors:	Many people, see the TCP sources
 *
 * 		From code originally in TCP
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _INET_CONNECTION_SOCK_H
#define _INET_CONNECTION_SOCK_H

#include <linux/compiler.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/poll.h>

#include <net/inet_sock.h>
#include <net/request_sock.h>

#define INET_CSK_DEBUG 1

/* Cancel timers, when they are not required. */
#undef INET_CSK_CLEAR_TIMERS

struct inet_bind_bucket;
struct inet_hashinfo;
struct tcp_congestion_ops;

/*
 * Pointers to address related TCP functions
 * (i.e. things that depend on the address family)
 */
struct inet_connection_sock_af_ops {
	/*从传输层向网络层传递的接口，tcp设置为ip_queue_xmit()*/
	int	    (*queue_xmit)(struct sk_buff *skb, int ipfragok);
	/*计算传输层首部校验和函数，tcp中初始化为tcp_v4_send_check*/
	void	    (*send_check)(struct sock *sk, int len,
				  struct sk_buff *skb);
	/*如果此传输控制块还没有路由缓存项，为传输控制块选择路由缓存项，tcp中设置为inet_sk_rebuild_header()*/
	int	    (*rebuild_header)(struct sock *sk);
	/*处理连接请求接口，tcp中设置为tcp_v4_conn_request()*/
	int	    (*conn_request)(struct sock *sk, struct sk_buff *skb);
	/*完成三次握手后，调用此接口来创建一个新的套接口，tcp中为tcp_v4_syn_recv_sock*/
	struct sock *(*syn_recv_sock)(struct sock *sk, struct sk_buff *skb,
				      struct request_sock *req,
				      struct dst_entry *dst);
	/*在启用tw_recycle时，关闭套接口时，记录相关时间戳信息到对端信息管理块中，tcp中设置为tcp_v4_remember_stamp()*/
	int	    (*remember_stamp)(struct sock *sk);
	/*ipv4首部中为ip首部的长度，iphdr的结构的大小*/
	u16	    net_header_len;
	/*ipv4套接口地址的大小，sizoef(struct sockaddr_in)*/
	u16	    sockaddr_len;
	/*传输层setsockopt getsockopt compat_setsockopt compat_getsockopt调用接口*/
	int	    (*setsockopt)(struct sock *sk, int level, int optname, 
				  char __user *optval, int optlen);
	int	    (*getsockopt)(struct sock *sk, int level, int optname, 
				  char __user *optval, int __user *optlen);
	int	    (*compat_setsockopt)(struct sock *sk,
				int level, int optname,
				char __user *optval, int optlen);
	int	    (*compat_getsockopt)(struct sock *sk,
				int level, int optname,
				char __user *optval, int __user *optlen);
	/*将ip套接口地址结构中的地址信息复制到传输控制块中，tcp中为inet_csk_addr2sockaddr(),实际中并未使用*/
	void	    (*addr2sockaddr)(struct sock *sk, struct sockaddr *);
};

/** inet_connection_sock - INET connection oriented sock
 *
 * @icsk_accept_queue:	   FIFO of established children 
 * @icsk_bind_hash:	   Bind node
 * @icsk_timeout:	   Timeout
 * @icsk_retransmit_timer: Resend (no ack)
 * @icsk_rto:		   Retransmit timeout
 * @icsk_pmtu_cookie	   Last pmtu seen by socket
 * @icsk_ca_ops		   Pluggable congestion control hook
 * @icsk_af_ops		   Operations which are AF_INET{4,6} specific
 * @icsk_ca_state:	   Congestion control state
 * @icsk_retransmits:	   Number of unrecovered [RTO] timeouts
 * @icsk_pending:	   Scheduled timer event
 * @icsk_backoff:	   Backoff
 * @icsk_syn_retries:      Number of allowed SYN (or equivalent) retries
 * @icsk_probes_out:	   unanswered 0 window probes
 * @icsk_ext_hdr_len:	   Network protocol overhead (IP/IPv6 options)
 * @icsk_ack:		   Delayed ACK control data
 * @icsk_mtup;		   MTU probing control data
 */
struct inet_connection_sock {
	/* inet_sock has to be the first member! */
	struct inet_sock	  icsk_inet;
	/*
	 *当tcp传输层接收到客户端的连接请求后，会创建一个客户端套接口存放到icsk_accept_queue容器中，等待应用程序调用accept读取
	 */
	struct request_sock_queue icsk_accept_queue;
	/*指向与之绑定的本地端口信息，在绑定过程中被设置*/
	struct inet_bind_bucket	  *icsk_bind_hash;
	/*如果tcp段在制定时间内没收到ack，则认为发送失败，而进行重传的超时时间。通常设置为jiffices+icsk_rto*/
	unsigned long		  icsk_timeout;
	/*通过icsk_pending来区分重传定时器和持续定时器的实现，超时时间内没接受到ack会发送重传，则链接对方通告窗口为0时，会启动持续定时器
	 * ，探查窗口大小*/
 	struct timer_list	  icsk_retransmit_timer;
	/*用于延迟发送ack的定时器，(经受时延的ack)*/
 	struct timer_list	  icsk_delack_timer;
	/*超时重传时间，初始值为TCP_TIMEOUT_INIT,当往返时间超过此值时被认为传输失败，超时重传时间根据当前网络动态计算获得*/
	__u32			  icsk_rto;
	/*最后一次跟新的路径MTU*/
	__u32			  icsk_pmtu_cookie;
	/*指向某个拥塞控制算法的指针*/
	const struct tcp_congestion_ops *icsk_ca_ops;
	/*tcp的一个操作接口集，包括ip层发送的接口，tcp层setsockopt接口等，加载tcp协议模块时，在tcp_v4_init_sock()时
	 * 初始化为inet_connection_sock_af_ops的结构类型常量ipv4_specific*/
	const struct inet_connection_sock_af_ops *icsk_af_ops;
	/*根据pmtu同步本地MSS函数指针，加载tcp协议模块时，在tcp_v4_init_sock()中初始化为tcp_sync_mss()*/
	unsigned int		  (*icsk_sync_mss)(struct sock *sk, u32 pmtu);
	/*拥塞控制状态*/
	__u8			  icsk_ca_state;
	/*记录超时重传的次数*/
	__u8			  icsk_retransmits;
	/*标识预订的定时器事件，只取ICSK_TIME_RETRANS或ICSK_TIME_PROBE0.重传或灵窗口探测时会调用inet_csk_reset_xmit_timer()设置该字段*/
	__u8			  icsk_pending;
	/*用来计算tcp持续定时器下一个设定值的指数退辟算法指数，在传送超时时会递增*/
	__u8			  icsk_backoff;
	/*在建立tcp链接时，最多允许发送的syn和syn+ack段的次数*/
	__u8			  icsk_syn_retries;
	/*持续定时器或保活定时器周期性发出去但未被确认的TCP段数目，在收到ACK之后清零*/
	__u8			  icsk_probes_out;
	/*ip首部中选项部分长度*/
	__u16			  icsk_ext_hdr_len;
	/*延时确认控制数据块*/
	struct {
		/*
		 *当前发送确认的紧急程度和状态, 在数据从内核空间复制到用户空间时会检测该状态，如果需要会立即发送确认，而在计算
		 *rcv_mss时，会根据情况调整此状态，由于pending是按位存储的，因此多个状态可以同时存在
		 *ICSK_ACK_SCHED:有ACK需要发送,是立即发送还是延时发送,还需要看其他标志,也是能否发送确认的前提,在接收到有负荷的TCP段后,会设置该标志
		 *ICSK_ACK_TIMER:延时发送ACK定时器已经启动
		 *ICSK_ACK_PUSHED:只要由ACK需要发送，并且pingpong为0，ACK可以立即发送
		 *ICSK_ACK_PUSHED2:只要有ACK需要发送，都可以立即发送，无论是否处于快速发送模式
		 */
		__u8		  pending;	 /* ACK is pending			   */
		/*标识在快速发送模式中，可以快速发送的ACK的数量,与pingpong一同作为判断是否在快速发送确认模式下的条件，
		 * 如果要延时发送确认，则必须在延时发送确认模式下*/
		__u8		  quick;	 /* Scheduled number of quick acks	   */
		/*
		 * 标识启用和禁用快速发送模式，通过TCP_QUICKACK可以设置此值
		 * 0:不延时发送，进行快速发送
		 * 1:延时发送ack
		 */
		__u8		  pingpong;	 /* The session is interactive		   */
		/*软中断和用户进程不能同时占有套接口，因此如果套接口已被用户进程锁定,而此时延时定时器被触发，在逻辑上此时应该立即发送ack，
		 * 但是套接口被用户进程锁定，只能置blocked为1，表示套接口被用户进程锁定，此时不能发送ack，有机会立即发送ack，这些机会包括接受到数据之后
		 * 或数据被复制到用户空间之后*/
		__u8		  blocked;	 /* Delayed ACK was blocked by socket lock */
		/*
		 * 用来计算延时确认的估值，在接收到tcp段时会根据本次与上次接收的时间间隔来调整该值，而在
		 * 设置时延确认定时器时也会根据条件调整该值。
		 */
		__u32		  ato;		 /* Predicted tick of soft clock	   */
		/*当前的延时确认时间，超时后会发送ack*/
		unsigned long	  timeout;	 /* Currently scheduled timeout		   */
		/*标识最近一次接受到数据包的时间*/
		__u32		  lrcvtime;	 /* timestamp of last received data packet */
		/*最后一个接收到的段的长度，用来计算rcv_mss*/
		__u16		  last_seg_size; /* Size of last incoming segment	   */
		/*由最近接收到的段计算出的mss，主要用来确认是否进行延时确认*/
		__u16		  rcv_mss;	 /* MSS used for delayed ACK decisions	   */ 
	} icsk_ack;
	/*有关路径mtu发现的控制数据块，在tcp_mtup_init()中初始化*/
	struct {
		/*标识是否启用路径mtu发现*/
		int		  enabled;

		/* Range of MTUs to search */
		/*用来标识进行路径mtu发现的区间的上下限*/
		int		  search_high;
		int		  search_low;

		/* Information on the current probe. */
		/*为当前路径mtu探测段的长度，也用与判断路径mtu探测是否完成，无论成功还是失败，路径mtu探测完成后，此值都设为0*/
		int		  probe_size;
	} icsk_mtup;
	/*存储各种有关tcp拥塞控制算法的私有参数*/
	u32			  icsk_ca_priv[16];
#define ICSK_CA_PRIV_SIZE	(16 * sizeof(u32))
};

#define ICSK_TIME_RETRANS	1	/* Retransmit timer */
#define ICSK_TIME_DACK		2	/* Delayed ack timer */
#define ICSK_TIME_PROBE0	3	/* Zero window probe timer */
#define ICSK_TIME_KEEPOPEN	4	/* Keepalive timer */

static inline struct inet_connection_sock *inet_csk(const struct sock *sk)
{
	return (struct inet_connection_sock *)sk;
}

static inline void *inet_csk_ca(const struct sock *sk)
{
	return (void *)inet_csk(sk)->icsk_ca_priv;
}

extern struct sock *inet_csk_clone(struct sock *sk,
				   const struct request_sock *req,
				   const gfp_t priority);

enum inet_csk_ack_state_t {
	ICSK_ACK_SCHED	= 1,
	ICSK_ACK_TIMER  = 2,
	ICSK_ACK_PUSHED = 4,
	ICSK_ACK_PUSHED2 = 8
};

extern void inet_csk_init_xmit_timers(struct sock *sk,
				      void (*retransmit_handler)(unsigned long),
				      void (*delack_handler)(unsigned long),
				      void (*keepalive_handler)(unsigned long));
extern void inet_csk_clear_xmit_timers(struct sock *sk);

static inline void inet_csk_schedule_ack(struct sock *sk)
{
	inet_csk(sk)->icsk_ack.pending |= ICSK_ACK_SCHED;
}

static inline int inet_csk_ack_scheduled(const struct sock *sk)
{
	return inet_csk(sk)->icsk_ack.pending & ICSK_ACK_SCHED;
}

static inline void inet_csk_delack_init(struct sock *sk)
{
	memset(&inet_csk(sk)->icsk_ack, 0, sizeof(inet_csk(sk)->icsk_ack));
}

extern void inet_csk_delete_keepalive_timer(struct sock *sk);
extern void inet_csk_reset_keepalive_timer(struct sock *sk, unsigned long timeout);

#ifdef INET_CSK_DEBUG
extern const char inet_csk_timer_bug_msg[];
#endif

static inline void inet_csk_clear_xmit_timer(struct sock *sk, const int what)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	
	if (what == ICSK_TIME_RETRANS || what == ICSK_TIME_PROBE0) {
		icsk->icsk_pending = 0;
#ifdef INET_CSK_CLEAR_TIMERS
		sk_stop_timer(sk, &icsk->icsk_retransmit_timer);
#endif
	} else if (what == ICSK_TIME_DACK) {
		icsk->icsk_ack.blocked = icsk->icsk_ack.pending = 0;
#ifdef INET_CSK_CLEAR_TIMERS
		sk_stop_timer(sk, &icsk->icsk_delack_timer);
#endif
	}
#ifdef INET_CSK_DEBUG
	else {
		pr_debug("%s", inet_csk_timer_bug_msg);
	}
#endif
}

/*
 *	Reset the retransmission timer
 */
static inline void inet_csk_reset_xmit_timer(struct sock *sk, const int what,
					     unsigned long when,
					     const unsigned long max_when)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (when > max_when) {
#ifdef INET_CSK_DEBUG
		pr_debug("reset_xmit_timer: sk=%p %d when=0x%lx, caller=%p\n",
			 sk, what, when, current_text_addr());
#endif
		when = max_when;
	}

	if (what == ICSK_TIME_RETRANS || what == ICSK_TIME_PROBE0) {
		icsk->icsk_pending = what;
		icsk->icsk_timeout = jiffies + when;
		sk_reset_timer(sk, &icsk->icsk_retransmit_timer, icsk->icsk_timeout);
	} else if (what == ICSK_TIME_DACK) {
		icsk->icsk_ack.pending |= ICSK_ACK_TIMER;
		icsk->icsk_ack.timeout = jiffies + when;
		sk_reset_timer(sk, &icsk->icsk_delack_timer, icsk->icsk_ack.timeout);
	}
#ifdef INET_CSK_DEBUG
	else {
		pr_debug("%s", inet_csk_timer_bug_msg);
	}
#endif
}

extern struct sock *inet_csk_accept(struct sock *sk, int flags, int *err);

extern struct request_sock *inet_csk_search_req(const struct sock *sk,
						struct request_sock ***prevp,
						const __be16 rport,
						const __be32 raddr,
						const __be32 laddr);
extern int inet_csk_bind_conflict(const struct sock *sk,
				  const struct inet_bind_bucket *tb);
extern int inet_csk_get_port(struct inet_hashinfo *hashinfo,
			     struct sock *sk, unsigned short snum,
			     int (*bind_conflict)(const struct sock *sk,
						  const struct inet_bind_bucket *tb));

extern struct dst_entry* inet_csk_route_req(struct sock *sk,
					    const struct request_sock *req);

static inline void inet_csk_reqsk_queue_add(struct sock *sk,
					    struct request_sock *req,
					    struct sock *child)
{
	reqsk_queue_add(&inet_csk(sk)->icsk_accept_queue, req, sk, child);
}

extern void inet_csk_reqsk_queue_hash_add(struct sock *sk,
					  struct request_sock *req,
					  unsigned long timeout);

static inline void inet_csk_reqsk_queue_removed(struct sock *sk,
						struct request_sock *req)
{
	if (reqsk_queue_removed(&inet_csk(sk)->icsk_accept_queue, req) == 0)
		inet_csk_delete_keepalive_timer(sk);
}

static inline void inet_csk_reqsk_queue_added(struct sock *sk,
					      const unsigned long timeout)
{
	if (reqsk_queue_added(&inet_csk(sk)->icsk_accept_queue) == 0)
		inet_csk_reset_keepalive_timer(sk, timeout);
}

static inline int inet_csk_reqsk_queue_len(const struct sock *sk)
{
	return reqsk_queue_len(&inet_csk(sk)->icsk_accept_queue);
}

static inline int inet_csk_reqsk_queue_young(const struct sock *sk)
{
	return reqsk_queue_len_young(&inet_csk(sk)->icsk_accept_queue);
}

static inline int inet_csk_reqsk_queue_is_full(const struct sock *sk)
{
	return reqsk_queue_is_full(&inet_csk(sk)->icsk_accept_queue);
}

static inline void inet_csk_reqsk_queue_unlink(struct sock *sk,
					       struct request_sock *req,
					       struct request_sock **prev)
{
	reqsk_queue_unlink(&inet_csk(sk)->icsk_accept_queue, req, prev);
}

static inline void inet_csk_reqsk_queue_drop(struct sock *sk,
					     struct request_sock *req,
					     struct request_sock **prev)
{
	inet_csk_reqsk_queue_unlink(sk, req, prev);
	inet_csk_reqsk_queue_removed(sk, req);
	reqsk_free(req);
}

extern void inet_csk_reqsk_queue_prune(struct sock *parent,
				       const unsigned long interval,
				       const unsigned long timeout,
				       const unsigned long max_rto);

extern void inet_csk_destroy_sock(struct sock *sk);

/*
 * LISTEN is a special case for poll..
 */
static inline unsigned int inet_csk_listen_poll(const struct sock *sk)
{
	return !reqsk_queue_empty(&inet_csk(sk)->icsk_accept_queue) ?
			(POLLIN | POLLRDNORM) : 0;
}

extern int  inet_csk_listen_start(struct sock *sk, const int nr_table_entries);
extern void inet_csk_listen_stop(struct sock *sk);

extern void inet_csk_addr2sockaddr(struct sock *sk, struct sockaddr *uaddr);

extern int inet_csk_ctl_sock_create(struct socket **sock,
				    unsigned short family,
				    unsigned short type,
				    unsigned char protocol);

extern int inet_csk_compat_getsockopt(struct sock *sk, int level, int optname,
				      char __user *optval, int __user *optlen);
extern int inet_csk_compat_setsockopt(struct sock *sk, int level, int optname,
				      char __user *optval, int optlen);
#endif /* _INET_CONNECTION_SOCK_H */

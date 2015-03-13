/*
 * NET		Generic infrastructure for Network protocols.
 *
 *		Definitions for request_sock 
 *
 * Authors:	Arnaldo Carvalho de Melo <acme@conectiva.com.br>
 *
 * 		From code originally in include/net/tcp.h
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _REQUEST_SOCK_H
#define _REQUEST_SOCK_H

#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#include <net/sock.h>

struct request_sock;
struct sk_buff;
struct dst_entry;
struct proto;

struct request_sock_ops {
	int		family;
	/*是tcp_request_sock结构长度，*/
	int		obj_size;
	struct kmem_cache	*slab;
	/*发送SYN+ACK段的函数指针，tcp中为tcp_v4_send_synack(),*/
	int		(*rtx_syn_ack)(struct sock *sk,
				       struct request_sock *req,
				       struct dst_entry *dst);
	/*发送ack段的函数指针，tcp中为tcp_v4_send_ack*/
	void		(*send_ack)(struct sk_buff *skb,
				    struct request_sock *req);
	/*发送rst段的函数指着，tcp中为tcp_v4_send_reset*/
	void		(*send_reset)(struct sock *sk,
				      struct sk_buff *skb);
	/*在释放连接请求块时调用。tcp_v4_reqsk_destructor*/
	void		(*destructor)(struct request_sock *req);
};

/* struct request_sock - mini sock to represent a connection request
 */
struct request_sock {
	struct request_sock		*dl_next; /* Must be first member! */
	/*客户端链接请求段中通告的MSS,如果无通告，则为初始值，RFC中建议的536*/
	u16				mss;
	/*发送SYN+ACK段的次数,达到系统上限时，取消连接操作*/
	u8				retrans;
	/*未使用*/
	u8				__pad;
	/* The following two fields can be easily recomputed I think -AK */
	/*标识本端的最大通告窗口，在生成SYN+ACK时，计算该值*/
	u32				window_clamp; /* window clamp at creation time */
	/*标识在连接建立时，本端接收窗口大小，初始化为0，在生成SYN+ACK时计算该值*/
	u32				rcv_wnd;	  /* rcv_wnd offered first time */
	/*下一个将要发送的ACK中的时间戳值，当一个包含最后发送ACK确认序号的段到达时，该段中的时间戳被保存在ts_recent中*/
	u32				ts_recent;
	/*服务端接收到连接请求，并发送SYN+ACK段作为应答后，等待客户端确认的超时时间。一旦超时，会重新发送SYN+ACK,直到链接建立或重发次数达到上限*/
	unsigned long			expires;
	/*处理链接请求的函数指针表,tcp指向tcp_request_sock_ops*/
	const struct request_sock_ops	*rsk_ops;
	/*指向对应状态的传输控制块。在链接建立前无效，三次握手后会创建对应的传输控制块，而此时链接请求块也完成了使命，调用accept将链接请求块提取走，
	 * 并释放*/
	struct sock			*sk;
	/*有关安全的id*/
	u32				secid;
	u32				peer_secid;
};

static inline struct request_sock *reqsk_alloc(const struct request_sock_ops *ops)
{
	struct request_sock *req = kmem_cache_alloc(ops->slab, GFP_ATOMIC);

	if (req != NULL)
		req->rsk_ops = ops;

	return req;
}

static inline void __reqsk_free(struct request_sock *req)
{
	kmem_cache_free(req->rsk_ops->slab, req);
}

static inline void reqsk_free(struct request_sock *req)
{
	req->rsk_ops->destructor(req);
	__reqsk_free(req);
}

extern int sysctl_max_syn_backlog;

/** struct listen_sock - listen state
 *
 * @max_qlen_log - log_2 of maximal queued SYNs/REQUESTs
 */
struct listen_sock {
	/*实际分配用来保存SYN请求连接的syn_table结构数组的长度，值为nr_table_entries以2为低的对数*/
	u8			max_qlen_log;
	/* 3 bytes hole, try to use */
	/*当前链接请求块数*/
	int			qlen;
	/*未重传过SYN+ACK的请求块数目，如果没有发生重传，qlen_yound==qlen,发生重传，qlen_yound--*/
	int			qlen_young;
	/*用于记录连接定时器处理函数下次激活时需处理的连接请求块散列表入口，在本次结束时，将当前的入口保存到该字段，
	 * 在下次处理时，就从该入口开始处理*/
	int			clock_hand;
	/*用来计算syn请求块键值的随机数,在rsqsk_queue_alloc()中随机生成*/
	u32			hash_rnd;
	/*实际用来保存SYN请求链接的request_sock的结构数组长度*/
	u32			nr_table_entries;
	struct request_sock	*syn_table[0];
};

/** struct request_sock_queue - queue of request_socks
 *
 * @rskq_accept_head - FIFO head of established children
 * @rskq_accept_tail - FIFO tail of established children
 * @rskq_defer_accept - User waits for some data after accept()
 * @syn_wait_lock - serializer
 *
 * %syn_wait_lock is necessary only to avoid proc interface having to grab the main
 * lock sock while browsing the listening hash (otherwise it's deadlock prone).
 *
 * This lock is acquired in read mode only from listening_get_next() seq_file
 * op and it's acquired in write mode _only_ from code that is actively
 * changing rskq_accept_head. All readers that are holding the master sock lock
 * don't need to grab this lock in read mode too as rskq_accept_head. writes
 * are always protected from the main sock lock.
 */
struct request_sock_queue {
	struct request_sock	*rskq_accept_head;
	struct request_sock	*rskq_accept_tail;
	/*访问listen_opt 以及listen_sock结构成员的同步控制读写锁*/
	rwlock_t		syn_wait_lock;
	/*保存相关tcp层的选项TCP_DEFER_ACCEPT的值*/
	u8			rskq_defer_accept;
	/* 3 bytes hole, try to pack */
	struct listen_sock	*listen_opt;
};

extern int reqsk_queue_alloc(struct request_sock_queue *queue,
			     unsigned int nr_table_entries);

static inline struct listen_sock *reqsk_queue_yank_listen_sk(struct request_sock_queue *queue)
{
	struct listen_sock *lopt;

	write_lock_bh(&queue->syn_wait_lock);
	lopt = queue->listen_opt;
	queue->listen_opt = NULL;
	write_unlock_bh(&queue->syn_wait_lock);

	return lopt;
}

static inline void __reqsk_queue_destroy(struct request_sock_queue *queue)
{
	kfree(reqsk_queue_yank_listen_sk(queue));
}

extern void reqsk_queue_destroy(struct request_sock_queue *queue);

static inline struct request_sock *
	reqsk_queue_yank_acceptq(struct request_sock_queue *queue)
{
	struct request_sock *req = queue->rskq_accept_head;

	queue->rskq_accept_head = NULL;
	return req;
}

static inline int reqsk_queue_empty(struct request_sock_queue *queue)
{
	return queue->rskq_accept_head == NULL;
}

static inline void reqsk_queue_unlink(struct request_sock_queue *queue,
				      struct request_sock *req,
				      struct request_sock **prev_req)
{
	write_lock(&queue->syn_wait_lock);
	*prev_req = req->dl_next;
	write_unlock(&queue->syn_wait_lock);
}

static inline void reqsk_queue_add(struct request_sock_queue *queue,
				   struct request_sock *req,
				   struct sock *parent,
				   struct sock *child)
{
	req->sk = child;
	sk_acceptq_added(parent);

	if (queue->rskq_accept_head == NULL)
		queue->rskq_accept_head = req;
	else
		queue->rskq_accept_tail->dl_next = req;

	queue->rskq_accept_tail = req;
	req->dl_next = NULL;
}

static inline struct request_sock *reqsk_queue_remove(struct request_sock_queue *queue)
{
	struct request_sock *req = queue->rskq_accept_head;

	BUG_TRAP(req != NULL);

	queue->rskq_accept_head = req->dl_next;
	if (queue->rskq_accept_head == NULL)
		queue->rskq_accept_tail = NULL;

	return req;
}

static inline struct sock *reqsk_queue_get_child(struct request_sock_queue *queue,
						 struct sock *parent)
{
	struct request_sock *req = reqsk_queue_remove(queue);
	struct sock *child = req->sk;

	BUG_TRAP(child != NULL);

	/*递减sk中的sk_ack_backlog变量的值*/
	sk_acceptq_removed(parent);
	__reqsk_free(req);
	return child;
}

static inline int reqsk_queue_removed(struct request_sock_queue *queue,
				      struct request_sock *req)
{
	struct listen_sock *lopt = queue->listen_opt;

	if (req->retrans == 0)
		--lopt->qlen_young;

	return --lopt->qlen;
}

static inline int reqsk_queue_added(struct request_sock_queue *queue)
{
	struct listen_sock *lopt = queue->listen_opt;
	const int prev_qlen = lopt->qlen;

	lopt->qlen_young++;
	lopt->qlen++;
	return prev_qlen;
}

static inline int reqsk_queue_len(const struct request_sock_queue *queue)
{
	return queue->listen_opt != NULL ? queue->listen_opt->qlen : 0;
}

static inline int reqsk_queue_len_young(const struct request_sock_queue *queue)
{
	return queue->listen_opt->qlen_young;
}

static inline int reqsk_queue_is_full(const struct request_sock_queue *queue)
{
	return queue->listen_opt->qlen >> queue->listen_opt->max_qlen_log;
}

static inline void reqsk_queue_hash_req(struct request_sock_queue *queue,
					u32 hash, struct request_sock *req,
					unsigned long timeout)
{
	struct listen_sock *lopt = queue->listen_opt;

	req->expires = jiffies + timeout;
	req->retrans = 0;
	req->sk = NULL;
	req->dl_next = lopt->syn_table[hash];

	write_lock(&queue->syn_wait_lock);
	lopt->syn_table[hash] = req;
	write_unlock(&queue->syn_wait_lock);
}

#endif /* _REQUEST_SOCK_H */

/*
 *		INETPEER - A storage for permanent information about peers
 *
 *  Version:	$Id: inetpeer.h,v 1.2 2002/01/12 07:54:56 davem Exp $
 *
 *  Authors:	Andrey V. Savochkin <saw@msu.ru>
 */

#ifndef _NET_INETPEER_H
#define _NET_INETPEER_H

#include <linux/types.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/spinlock.h>
#include <asm/atomic.h>

/*对端信息块*/
struct inet_peer
{
	/* group together avl_left,avl_right,v4daddr to speedup lookups */
	/*用来将对端信息块组织成avl树,v4daddr为key,代表对端的ip地址*/
	struct inet_peer	*avl_left, *avl_right;
	__be32			v4daddr;	/* peer's address */
	__u16			avl_height;
	/*一个单调递增值，用来设置ip分片中的id域,根据对端地址初始化为随机值*/
	__u16			ip_id_count;	/* IP ID for the next packet */
	/*链接到inet_peer_unused_head链表上， 该链表上的对端信息块都是当前闲置的，可回收的*/
	struct inet_peer	*unused_next, **unused_prevp;
	/*记录该信息块引用技术为0的时间， 当闲置时间过程时，则回收*/
	__u32			dtime;		/* the time of last use of not
						 * referenced entries */
	atomic_t		refcnt;
	/*递增id，对端发送分片的计数器*/
	atomic_t		rid;		/* Frag reception counter */
	/*tcp中，记录最后一个ack段到达的时间*/
	__u32			tcp_ts;
	/*tcp中，记录接收到的段中的时间戳，设置ts_recent的时间*/
	unsigned long		tcp_ts_stamp;
};

void			inet_initpeers(void) __init;

/* can be called with or without local BH being disabled */
struct inet_peer	*inet_getpeer(__be32 daddr, int create);

/* can be called from BH context or outside */
extern void inet_putpeer(struct inet_peer *p);

extern spinlock_t inet_peer_idlock;
/* can be called with or without local BH being disabled */
static inline __u16	inet_getid(struct inet_peer *p, int more)
{
	__u16 id;

	spin_lock_bh(&inet_peer_idlock);
	id = p->ip_id_count;
	p->ip_id_count += 1 + more;
	spin_unlock_bh(&inet_peer_idlock);
	return id;
}

#endif /* _NET_INETPEER_H */

#ifndef _NET_NEIGHBOUR_H
#define _NET_NEIGHBOUR_H

#include <linux/neighbour.h>

/*
 *	Generic neighbour manipulation
 *
 *	Authors:
 *	Pedro Roque		<roque@di.fc.ul.pt>
 *	Alexey Kuznetsov	<kuznet@ms2.inr.ac.ru>
 *
 * 	Changes:
 *
 *	Harald Welte:		<laforge@gnumonks.org>
 *		- Add neighbour cache statistics like rtstat
 */

#include <asm/atomic.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>

#include <linux/err.h>
#include <linux/sysctl.h>

#define NUD_IN_TIMER	(NUD_INCOMPLETE|NUD_REACHABLE|NUD_DELAY|NUD_PROBE)
#define NUD_VALID	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE|NUD_PROBE|NUD_STALE|NUD_DELAY)
#define NUD_CONNECTED	(NUD_PERMANENT|NUD_NOARP|NUD_REACHABLE)

struct neighbour;

struct neigh_parms
{
	/*该实例所对应的网络设备,在通过neigh_parms_alloc()创建neigh_parms实例时设置*/
	struct net_device *dev;
	/*将同一协议族的所有neigh_parms链接在一起，每个neigh_table都有各自的neigh_parms队列*/
	struct neigh_parms *next;
	/*提供给老式接口的初始化和销毁接口，net_device结构中也有一个neigh_setup成员函数指针。*/
	int	(*neigh_setup)(struct neighbour *);
	void	(*neigh_destructor)(struct neighbour *);
	/*指向neigh_parms实例所属的邻居表*/
	struct neigh_table *tbl;

	/*邻居表的sysctl表，对arp是在arp模块初始化函数arp_init()中对其初始化，可以从/proc中读写邻居表的参数*/
	void	*sysctl_table;

	/*如果为1，该邻居参数实例正在被删除，不能再使用，也不能创建对应网络设备的邻居项，在网络设备禁用时调用neigh_parms_release()设置*/
	int dead;
	/*引用计数*/
	atomic_t refcnt;
	/*为控制同步访问而设置的参数*/
	struct rcu_head rcu_head;

	/*base_reachable_time为reachable_time的基准值，而reachable_time为NUD_REACHABLE状态超时时间，该值为随机值，介于base_reachable_time和
	 * 1.5倍的base_reachable_time之间，通常每300s在neigh_periodic_time()中更新一次*/
	int	base_reachable_time;
	/*用于重传arp请求报文的超时时间，主机在输出一个arp请求报文之后的retrans_time个jiffies内，如果没有收到arp应答，则会重新输出一个arp请求报文*/
	int	retrans_time;
	/*一个邻居项如果持续时间达到gc_staletime,且没有被引用，则会将被删除*/
	int	gc_staletime;
	int	reachable_time;
	/*邻居项维持在NUD_DELAY状态delay_probe_time之后进入NUD_PROBE状态，或者处于NUD_REACHABLE状态的邻居项闲置时间超过delay_probe_time后，直接进入
	 * NUD_PROBE状态*/
	int	delay_probe_time;

	/*proxy_queue队列长度上限*/
	int	queue_len;
	/*发送并确认可达的单播arp请求报文数目*/
	int	ucast_probes;
	/*地址解析时，应用程序(通常是arpd)可发送的arp请求的报文的数目*/
	int	app_probes;
	/*为了解析一个邻居地址，可发送的广播arp请求报文数目，arp发送的为多播报文，而非广播报文？？？*/
	int	mcast_probes;
	/*reserved*/
	int	anycast_delay;
	/*处理代理请求报文可延时的时间*/
	int	proxy_delay;
	/*proxy_queue队列长度上限*/
	int	proxy_qlen;
	/*当邻居项两次更新的时间间隔小于该值时，用覆盖的方式来更新邻居项，当有多个在同一网段的代理arp服务器答复对相同地址的查询*/
	int	locktime;
};

/*对应一个网络设备的一个邻居协议*/
struct neigh_statistics
{
	/*已分配的neighbour结构实例总数，包括已释放的*/
	unsigned long allocs;		/* number of allocated neighs */
	/*在neigh_destroy()中删除的邻居项总数*/
	unsigned long destroys;		/* number of destroyed neighs */
	/*扩容hash_buckets散列表的次数*/
	unsigned long hash_grows;	/* number of hash resizes */

	/*尝试解析一个邻居地址的失败次数，这并不是发送arp请求报文的数目，而是对于一个邻居来说，
	 * 在neigh_timer_handler()所有尝试都失败之后才进行计数*/
	unsigned long res_failed;	/* nomber of failed resolutions */

	/*调用neigh_lookup的次数*/
	unsigned long lookups;		/* number of lookups */
	/*调用neigh_lookup()成功返回总次数*/
	unsigned long hits;		/* number of hits (among lookups) */

	/*ipv6用来标识接受到发往组播或单播地址的arp请求报文总数*/
	unsigned long rcv_probes_mcast;	/* number of received mcast ipv6 */
	unsigned long rcv_probes_ucast; /* number of received ucast ipv6 */

	/*分别记录调用neigh_periodic_timer()或neigh_forced_gc()的次数*/
	unsigned long periodic_gc_runs;	/* number of periodic GC runs */
	unsigned long forced_gc_runs;	/* number of forced GC runs */
};

#define NEIGH_CACHE_STAT_INC(tbl, field)				\
	do {								\
		preempt_disable();					\
		(per_cpu_ptr((tbl)->stats, smp_processor_id())->field)++; \
		preempt_enable();					\
	} while (0)

struct neighbour
{
	/*把邻居项插入到散列表桶链表上，每次都在桶前面插入邻居项*/
	struct neighbour	*next;
	/*指向相关协议的neigh_table实例，即该邻居项所在的邻居表，如果该邻居项对应的是一个ipv4地址，该字段指向arp_tbl*/
	struct neigh_table	*tbl;
	/*调节邻居协议的参数,在创建邻居项函数neigh_create()中，首先调用neigh_alloc()分配一个邻居项，在该函数中使用邻居表的parms对邻居项的
	 * 该字段进行初始化，接着neigh_create()调用邻居表的constructor()，对于arp为arp_constructor(),对邻居项做特定的设置时将该字段修改为
	 * 协议相关设备的参数*/
	struct neigh_parms	*parms;
	/*通过次网络设备可以访问到该邻居。对每个邻居来说，只能有一个可用来访问该邻居的网络设备*/
	struct net_device		*dev;
	/*最近一次被使用时间,该字段值并不总是与数据传输同步更新，当邻居不处于NUD_CONNECTED状态时，该值在neigh_event_send()更新中，
	 * 当处于NUD_CONNECTED状态时，该值在gc_timer定时器处理函数中更新*/
	unsigned long		used;
	/*记录最近一次确认该邻居可达的时间，用来描述邻居的可达性，通常是接受到该邻居的报文时更新，传输层通过neigh_confirm()更新，
	 * 邻居子系统通过neigh_update()更新*/
	unsigned long		confirmed;
	/*记录最近一次被neigh_update更新的时间，该字段值在邻居状态发生变化时更新，*/
	unsigned long		updated;
	/*记录该邻居项的一些标志和特性
	 * NTF_ROUTER  此标志只使用与ipv6 ,标识该邻居为一个路由器*/
	__u8			flags;
	/*邻居项状态*/
	__u8			nud_state;
	/*邻居项地址的类型，对于arp,是在创建邻居项时arp_constructor()中设置的，该类型与路由表类型意义相同，最经常使用的类型为
	 * RTN_UNICAST, RTN_LOCAL,RTN_BROADCAST,RTN_ANYCAST,RTN_MULTICAST*/
	__u8			type;
	/*生存标志，如果为1，则认为该邻居项正在被删除,最后通过垃圾回收删除*/
	__u8			dead;
	/*尝试发送请求报文而未能得到应答的次数，该值在定时器处理函数中被检测，当该值达到指定的上限时，该邻居项便进入NUD_FAILED状态*/
	atomic_t		probes;
	/*用来访问控制邻居项的读写锁*/
	rwlock_t		lock;
	/*与存储在primary_key三层协议地址对应的2进制的2层硬件地址，以太网地址长度为6B,其他可能会更长，但是不会超过32B,
	 * 因此该数组长度设置为32*/
	unsigned char		ha[ALIGN(MAX_ADDR_LEN, sizeof(unsigned long))];
	/*指向缓存的2层协议首部hh_cache结构实例链表*/
	struct hh_cache		*hh;
	/*引用计数*/
	atomic_t		refcnt;
	/*输出函数，用于将报文输出到该邻居，在邻居项的整个生命周期中，由于其状态是不断变化的，从而导致该指针会指向不同的输出函数，
	 * 例如，当邻居项可达时会调用neigh_connect将output设置为neigh_ops->connected_output*/
	int			(*output)(struct sk_buff *skb);
	/*当邻居项无效时，用来缓存要发送的报文，*/
	struct sk_buff_head	arp_queue;
	/*用来管理多种超时情况的定时器*/
	struct timer_list	timer;
	/*用来指向邻居项函数指针表实例。*/
	struct neigh_ops	*ops;
	/*存储哈希函数使用的三层协议地址*/
	u8			primary_key[0];
};

struct neigh_ops
{
	int			family;
	/*发送请求报文函数，当发送第一个报文时，需要新的邻居项，发送报文被缓存到arp_queue队列中，然后调用solicit发送请求报文*/
	void			(*solicit)(struct neighbour *, struct sk_buff*);
	/*当邻居项缓存有未发送的报文，而该邻居项又不可达时，被调用来向三层报告错误的函数。
	 * arp中为，arp_error_report()，最终会给报文发送方发送一个主机不可达的icmp差错报文。*/
	void			(*error_report)(struct neighbour *, struct sk_buff*);
	/*最通用的输出函数，用于所有情况。*/
	int			(*output)(struct sk_buff*);
	/*当确定邻居到达时，使用的输出函数，只是简单的添加2层首部*/
	int			(*connected_output)(struct sk_buff*);
	/*在已缓存的2层首部的情况下使用的输出函数。*/
	int			(*hh_output)(struct sk_buff*);
	/*实际上 以上几个输出接口，除了hh_output外，并不真正发送数据包，只是在准备好2层首部后，调用queue_xmit接口*/
	int			(*queue_xmit)(struct sk_buff*);
};

struct pneigh_entry
{
	/*将pneigh_entry结构链接到phash_buckets散列表的一个桶内*/
	struct pneigh_entry	*next;
	/*通过该网络设备接受到的arp请求报文才能代理*/
	struct net_device		*dev;
	/*NTF_PROXY 代理表项标志，用ip命令在代理的邻居时会添加此标志，比如ip neigh add proxy 10.0.0.4 dev eth0*/
	u8			flags;
	/*存储三层协议地址，存储空间根据neigh_table结构的key_len字段分配，只有目标地址和该三层协议地址匹配的arp请求报文才能代理*/
	u8			key[0];
};

/*
 *	neighbour table manipulation
 */


/*一个neigh_table对应一个邻居协议,所有的neigh_table链接到全局变量neigh_tables中*/
struct neigh_table
{
	/*用来链接到neigh_tables中*/
	struct neigh_table	*next;
	/*邻居协议所属的地址族*/
	int			family;
	/*邻居项的大小，对于arp来说，初始化为sizeof(neighbour)+4,这是因为在arp中，这是因为在arp的neightbour结构中 最后一个零长数组实际指向
	 * 一个ipv4地址，因此其中的4是一个ipv4的地址长度*/
	int			entry_size;
	/*哈希函数所使用的key的大小，哈希函数使用的key是一个三层协议地址，所以在ipv4中 key是一个ip地址的长度，值为4*/
	int			key_len;
	/*哈希函数，用来计算哈希值，arp中为arp_hash()*/
	__u32			(*hash)(const void *pkey, const struct net_device *);
	/*邻居表项初始化函数，用来初始化一个neighbour结构和协议相关字段。在arp中 该函数为arp_constructor,由邻居表项初始化函数neigh_create()调用*/
	int			(*constructor)(struct neighbour *);
	/*这两个函数在创建和释放一个代理时调用，ipv4中没有使用，只在ipv6中使用*/
	int			(*pconstructor)(struct pneigh_entry *);
	void			(*pdestructor)(struct pneigh_entry *);
	/*用来初始话neigh_table->proxy_queue缓存队列中的代理arp报文*/
	void			(*proxy_redo)(struct sk_buff *skb);
	/*用来分配neightbour结构实例的缓冲池名字符串，arp_tlb的该字段为"arp_cache"*/
	char			*id;
	/*存储一些协议相关的可调参数*/
	struct neigh_parms	parms;
	/* HACK. gc_* shoul follow parms without a gap! */
	/*垃圾回收时钟gc_timer的到期间隔时间，每当该时钟到期触发一次垃圾回收，初始化为30s*/
	int			gc_interval;
	/*次三额阀值对应与内存对邻居项作垃圾回收处理的不同级别*/
	int			gc_thresh1;/*如果缓存中的邻居项数少于这个值，不做垃圾回收*/
	int			gc_thresh2;/*超过这个值，如果新建邻居项若超过5s未刷新，必须强制刷新并强制垃圾回收*/
	int			gc_thresh3;/*超过这个值，新建邻居项必须强制刷新并垃圾回收*/
	/*记录最近一次调用neigh_forced_gc()强制刷新邻居表的时间，用来做为是否垃圾回收的判断条件*/
	unsigned long		last_flush;
	/*垃圾回收定时器*/
	struct timer_list 	gc_timer;
	/*处理proxy_queue队列的定时器，当proxy_queue队列为空时，第一个arp报文加入到队列就会启动该定时器，
	 * 该定时器在neigh_table_init()中初始化，处理历程为neigh_proxy_process()*/
	struct timer_list 	proxy_timer;
	/*对于接受到的 需要进行代理的arp报文，会先将其缓存到proxy_queue队列中，在定时器处理函数中再对其进行处理*/
	struct sk_buff_head	proxy_queue;
	/*整个表中 邻居项的数目，在用neigh_alloc()创建和用neigh_destroy()释放邻居项时计数*/
	atomic_t		entries;
	/*用于控制邻居表的读写锁，例如neigh_lookup()只需要读邻居表，而neigh_periodic_timer()则需要读写邻居表*/
	rwlock_t		lock;
	/*用于记录neigh_parms结构中 reachable_time成员最近一次被更新的时间*/
	unsigned long		last_rand;
	/*用来分配neighbour实例的slab缓存，在neigh_table_init中初始化*/
	struct kmem_cache		*kmem_cachep;
	/*邻居表中邻居项的各类统计计数*/
	struct neigh_statistics	*stats;
	/*存储邻居项的散列表，该三列表在分配邻居项时，如果邻居项超过散列表容量，可动态扩容*/
	struct neighbour	**hash_buckets;
	/*邻居项三列表筒数减1*/
	unsigned int		hash_mask;
	/*随机数，hash_buckets扩容时计算关键字，以免收到arp攻击*/
	__u32			hash_rnd;
	/*保存下一次垃圾回收处理的桶序号，如果超过最大值hash_mash，则从散列表第一桶开始*/
	unsigned int		hash_chain_gc;
	/*存储arp代理三层协议地址的散列表，在neigh_table_init_no_netlink中完成初始化*/
	struct pneigh_entry	**phash_buckets;
#ifdef CONFIG_PROC_FS
	/*/proc/net/stat/下注册arp_cache文件，在neigh_table_init_no_netlink中完成注册*/
	struct proc_dir_entry	*pde;
#endif
};

/* flags for neigh_update() */
#define NEIGH_UPDATE_F_OVERRIDE			0x00000001
#define NEIGH_UPDATE_F_WEAK_OVERRIDE		0x00000002
#define NEIGH_UPDATE_F_OVERRIDE_ISROUTER	0x00000004
#define NEIGH_UPDATE_F_ISROUTER			0x40000000
#define NEIGH_UPDATE_F_ADMIN			0x80000000

extern void			neigh_table_init(struct neigh_table *tbl);
extern void			neigh_table_init_no_netlink(struct neigh_table *tbl);
extern int			neigh_table_clear(struct neigh_table *tbl);
extern struct neighbour *	neigh_lookup(struct neigh_table *tbl,
					     const void *pkey,
					     struct net_device *dev);
extern struct neighbour *	neigh_lookup_nodev(struct neigh_table *tbl,
						   const void *pkey);
extern struct neighbour *	neigh_create(struct neigh_table *tbl,
					     const void *pkey,
					     struct net_device *dev);
extern void			neigh_destroy(struct neighbour *neigh);
extern int			__neigh_event_send(struct neighbour *neigh, struct sk_buff *skb);
extern int			neigh_update(struct neighbour *neigh, const u8 *lladdr, u8 new, 
					     u32 flags);
extern void			neigh_changeaddr(struct neigh_table *tbl, struct net_device *dev);
extern int			neigh_ifdown(struct neigh_table *tbl, struct net_device *dev);
extern int			neigh_resolve_output(struct sk_buff *skb);
extern int			neigh_connected_output(struct sk_buff *skb);
extern int			neigh_compat_output(struct sk_buff *skb);
extern struct neighbour 	*neigh_event_ns(struct neigh_table *tbl,
						u8 *lladdr, void *saddr,
						struct net_device *dev);

extern struct neigh_parms	*neigh_parms_alloc(struct net_device *dev, struct neigh_table *tbl);
extern void			neigh_parms_release(struct neigh_table *tbl, struct neigh_parms *parms);
extern void			neigh_parms_destroy(struct neigh_parms *parms);
extern unsigned long		neigh_rand_reach_time(unsigned long base);

extern void			pneigh_enqueue(struct neigh_table *tbl, struct neigh_parms *p,
					       struct sk_buff *skb);
extern struct pneigh_entry	*pneigh_lookup(struct neigh_table *tbl, const void *key, struct net_device *dev, int creat);
extern int			pneigh_delete(struct neigh_table *tbl, const void *key, struct net_device *dev);

struct netlink_callback;
struct nlmsghdr;
extern int neigh_dump_info(struct sk_buff *skb, struct netlink_callback *cb);
extern int neigh_add(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg);
extern int neigh_delete(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg);
extern void neigh_app_ns(struct neighbour *n);

extern int neightbl_dump_info(struct sk_buff *skb, struct netlink_callback *cb);
extern int neightbl_set(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg);

extern void neigh_for_each(struct neigh_table *tbl, void (*cb)(struct neighbour *, void *), void *cookie);
extern void __neigh_for_each_release(struct neigh_table *tbl, int (*cb)(struct neighbour *));
extern void pneigh_for_each(struct neigh_table *tbl, void (*cb)(struct pneigh_entry *));

struct neigh_seq_state {
	struct neigh_table *tbl;
	void *(*neigh_sub_iter)(struct neigh_seq_state *state,
				struct neighbour *n, loff_t *pos);
	unsigned int bucket;
	unsigned int flags;
#define NEIGH_SEQ_NEIGH_ONLY	0x00000001
#define NEIGH_SEQ_IS_PNEIGH	0x00000002
#define NEIGH_SEQ_SKIP_NOARP	0x00000004
};
extern void *neigh_seq_start(struct seq_file *, loff_t *, struct neigh_table *, unsigned int);
extern void *neigh_seq_next(struct seq_file *, void *, loff_t *);
extern void neigh_seq_stop(struct seq_file *, void *);

extern int			neigh_sysctl_register(struct net_device *dev, 
						      struct neigh_parms *p,
						      int p_id, int pdev_id,
						      char *p_name,
						      proc_handler *proc_handler,
						      ctl_handler *strategy);
extern void			neigh_sysctl_unregister(struct neigh_parms *p);

static inline void __neigh_parms_put(struct neigh_parms *parms)
{
	atomic_dec(&parms->refcnt);
}

static inline void neigh_parms_put(struct neigh_parms *parms)
{
	if (atomic_dec_and_test(&parms->refcnt))
		neigh_parms_destroy(parms);
}

static inline struct neigh_parms *neigh_parms_clone(struct neigh_parms *parms)
{
	atomic_inc(&parms->refcnt);
	return parms;
}

/*
 *	Neighbour references
 */

static inline void neigh_release(struct neighbour *neigh)
{
	if (atomic_dec_and_test(&neigh->refcnt))
		neigh_destroy(neigh);
}

static inline struct neighbour * neigh_clone(struct neighbour *neigh)
{
	if (neigh)
		atomic_inc(&neigh->refcnt);
	return neigh;
}

#define neigh_hold(n)	atomic_inc(&(n)->refcnt)

static inline void neigh_confirm(struct neighbour *neigh)
{
	if (neigh)
		neigh->confirmed = jiffies;
}

static inline int neigh_is_connected(struct neighbour *neigh)
{
	return neigh->nud_state&NUD_CONNECTED;
}

static inline int neigh_is_valid(struct neighbour *neigh)
{
	return neigh->nud_state&NUD_VALID;
}

static inline int neigh_event_send(struct neighbour *neigh, struct sk_buff *skb)
{
	neigh->used = jiffies;
	if (!(neigh->nud_state&(NUD_CONNECTED|NUD_DELAY|NUD_PROBE)))
		return __neigh_event_send(neigh, skb);
	return 0;
}

static inline int neigh_hh_output(struct hh_cache *hh, struct sk_buff *skb)
{
	unsigned seq;
	int hh_len;

	do {
		int hh_alen;

		seq = read_seqbegin(&hh->hh_lock);
		hh_len = hh->hh_len;
		hh_alen = HH_DATA_ALIGN(hh_len);
		memcpy(skb->data - hh_alen, hh->hh_data, hh_alen);
	} while (read_seqretry(&hh->hh_lock, seq));

	skb_push(skb, hh_len);
	return hh->hh_output(skb);
}

/*查找邻居项失败，根据参数create  是否创建一个邻居项*/
static inline struct neighbour *
__neigh_lookup(struct neigh_table *tbl, const void *pkey, struct net_device *dev, int creat)
{
	struct neighbour *n = neigh_lookup(tbl, pkey, dev);

	if (n || !creat)
		return n;

	n = neigh_create(tbl, pkey, dev);
	return IS_ERR(n) ? NULL : n;
}

/*查找邻居项失败，则直接创建邻居项*/
static inline struct neighbour *
__neigh_lookup_errno(struct neigh_table *tbl, const void *pkey,
  struct net_device *dev)
{
	struct neighbour *n = neigh_lookup(tbl, pkey, dev);

	if (n)
		return n;

	return neigh_create(tbl, pkey, dev);
}

struct neighbour_cb {
	unsigned long sched_next;
	unsigned int flags;
};

#define LOCALLY_ENQUEUED 0x1

#define NEIGH_CB(skb)	((struct neighbour_cb *)(skb)->cb)

#endif

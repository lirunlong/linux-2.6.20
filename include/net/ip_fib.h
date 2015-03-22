/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET  is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the Forwarding Information Base.
 *
 * Authors:	A.N.Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef _NET_IP_FIB_H
#define _NET_IP_FIB_H

#include <net/flow.h>
#include <linux/seq_file.h>
#include <net/fib_rules.h>

struct fib_config {
	/*目的地址掩码程度*/
	u8			fc_dst_len;
	/*路由的服务类型位字段*/
	u8			fc_tos;
	/*表明该路由的特性*/
	u8			fc_protocol;
	/*路由范围*/
	u8			fc_scope;
	/*路由表项的类型*/
	u8			fc_type;
	/* 3 bytes unused */
	/*路由表id*/
	u32			fc_table;
	/*路由项的目的地址*/
	__be32			fc_dst;
	/*路由项的网管地址*/
	__be32			fc_gw;
	/*路由项的输出网络设备索引*/
	int			fc_oif;
	/*一些标志*/
	u32			fc_flags;
	/*路由项的优先级*/
	u32			fc_priority;
	/*首选源地址*/
	__be32			fc_prefsrc;
	/*路由和协议相关的度量值*/
	struct nlattr		*fc_mx;
	/*多路径路由下一跳的属性值*/
	struct rtnexthop	*fc_mp;
	int			fc_mx_len;
	int			fc_mp_len;
	/*基于策略路由的分类标签*/
	u32			fc_flow;
	/*多路径缓存算法*/
	u32			fc_mp_alg;
	/*
	 * NLM_F_REPLACE:如果存在则替换
	 * NLM_F_EXCL:如果存在则不添加
	 * NLM_F_CREATE:如果不存在则创建
	 * NLM_F_APPEND:添加到最后
	 */ 
	u32			fc_nlflags;
	/*配置路由的netlink数据包信息*/
	struct nl_info		fc_nlinfo;
 };

struct fib_info;

/*存放下一跳路由的地址(nh_gw),支持多路径路由时，一个路由会有多个fib_nb结构
 * 下一跳地址的选择有多种算法，基于nh_weight nh_power成员
 * */
struct fib_nh {
	/*该路由表项输出网络设备*/
	struct net_device	*nh_dev;
	/*将nh_hash链入散列表*/
	struct hlist_node	nh_hash;
	/*指向所属的fib_info结构*/
	struct fib_info		*nh_parent;
	unsigned		nh_flags;
	/*路由范围*/
	unsigned char		nh_scope;
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	/*当内核编译支持多路径路由时，用于实现加权随机论转算法*/
	int			nh_weight;
	int			nh_power;
#endif
#ifdef CONFIG_NET_CLS_ROUTE
	/*基于策略路由的分类标签*/
	__u32			nh_tclassid;
#endif
	/*该路由项的输出网络设备索引*/
	int			nh_oif;
	/*路由的网管地址*/
	__be32			nh_gw;
};

/*
 * This structure contains data shared by many of routes.
 */

struct fib_info {
	/*将fib_info实例插入到fib_info_hash三列表中,所有的fib_info实例都会插入到fib_info_hash散列表*/
	struct hlist_node	fib_hash;
	/*将fib_info实例插入到fib_info_laddrhash散列表中，在路由表项有一个首选源地址时，才会将fib_info插入到fib_info_laddrhash散列表中*/
	struct hlist_node	fib_lhash;
	/*fib_info实例引用的fib_node结构的数目*/
	int			fib_treeref;
	/*路由查找成功而被持有引用的计数*/
	atomic_t		fib_clntref;
	/*标记正在被删除，如果为1，警告不能再使用，正在删除*/
	int			fib_dead;
	/*当前使用的唯一表示RTNH_F_DEAD,表示下一跳已无效，在支持多路径条件下使用*/
	unsigned		fib_flags;
	/*同一个fib_node 的alias实例根据fib_alias的fa_tos递增排序，如果fa_tos相同，则根据相关的fib_info的fib_protocol递增排序
	 * 多个fib_alias可以共享一个fib_info
	 * 设置路由的协议：如RTPROT_REDIRECT
	 * 大于RTPROT_STATIC不是由内核生成的，由用户空间路由协议生成的
	 */
	int			fib_protocol;
	/*首选源ip地址*/
	__be32			fib_prefsrc;
	/*路由优先级，值越小，优先级越高，添加路由表项时，如果没有明确设定，他的值默认为0*/
	u32			fib_priority;
	/*与路由相关的一组度量值，默认为0*/
	u32			fib_metrics[RTAX_MAX];
#define fib_mtu fib_metrics[RTAX_MTU-1]
#define fib_window fib_metrics[RTAX_WINDOW-1]
#define fib_rtt fib_metrics[RTAX_RTT-1]
#define fib_advmss fib_metrics[RTAX_ADVMSS-1]
	/*可用下一跳数量，通常为1，当内核支持多路径路由时，才有可能大于1*/
	int			fib_nhs;
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	/*当内核编译支持多路径路由时，用于实现加权随机论转算法*/
	int			fib_power;
#endif
#ifdef CONFIG_IP_ROUTE_MULTIPATH_CACHED
	/*当内核编译支持多路经路由时，标识多路经缓存算法*/
	u32			fib_mp_alg;
#endif
	/*当支持多路径路由时，下一跳散列表*/
	struct fib_nh		fib_nh[0];
#define fib_dev		fib_nh[0].nh_dev
};


#ifdef CONFIG_IP_MULTIPLE_TABLES
struct fib_rule;
#endif

struct fib_result {
	unsigned char	prefixlen;
	unsigned char	nh_sel;
	unsigned char	type;
	unsigned char	scope;
#ifdef CONFIG_IP_ROUTE_MULTIPATH_CACHED
	__be32          network;
	__be32          netmask;
#endif
	struct fib_info *fi;
#ifdef CONFIG_IP_MULTIPLE_TABLES
	struct fib_rule	*r;
#endif
};

struct fib_result_nl {
	__be32		fl_addr;   /* To be looked up*/
	u32		fl_mark;
	unsigned char	fl_tos;
	unsigned char   fl_scope;
	unsigned char   tb_id_in;

	unsigned char   tb_id;      /* Results */
	unsigned char	prefixlen;
	unsigned char	nh_sel;
	unsigned char	type;
	unsigned char	scope;
	int             err;      
};

#ifdef CONFIG_IP_ROUTE_MULTIPATH

#define FIB_RES_NH(res)		((res).fi->fib_nh[(res).nh_sel])
#define FIB_RES_RESET(res)	((res).nh_sel = 0)

#else /* CONFIG_IP_ROUTE_MULTIPATH */

#define FIB_RES_NH(res)		((res).fi->fib_nh[0])
#define FIB_RES_RESET(res)

#endif /* CONFIG_IP_ROUTE_MULTIPATH */

#define FIB_RES_PREFSRC(res)		((res).fi->fib_prefsrc ? : __fib_res_prefsrc(&res))
#define FIB_RES_GW(res)			(FIB_RES_NH(res).nh_gw)
#define FIB_RES_DEV(res)		(FIB_RES_NH(res).nh_dev)
#define FIB_RES_OIF(res)		(FIB_RES_NH(res).nh_oif)

#ifdef CONFIG_IP_ROUTE_MULTIPATH_CACHED
#define FIB_RES_NETWORK(res)		((res).network)
#define FIB_RES_NETMASK(res)	        ((res).netmask)
#else /* CONFIG_IP_ROUTE_MULTIPATH_CACHED */
#define FIB_RES_NETWORK(res)		(0)
#define FIB_RES_NETMASK(res)	        (0)
#endif /* CONFIG_IP_ROUTE_MULTIPATH_WRANDOM */

/*路由表，所有的路由表链接到全局散列表fib_table_hash*/
struct fib_table {
	/*用来将各个路由表链接成一个双向链表*/
	struct hlist_node tb_hlist;
	/*
	 * 路由表表示。在支持策略路由的情况下，系统中最多可以有256个路由表，枚举类型rt_class_t中定义了保留的路由表ID,
	 * 除此之外，从1到RT_TABLE_DEFAULT-1都是可以有用户定义的
	 */
	u32		tb_id;
	/*reserved*/
	unsigned	tb_stamp;
	/*
	 * 用户在当前路由表搜索符合条件的路由表项，在FIB_HASH算法中为fn_hash_lookup(),此接口被fib_lookup 调用
	 */
	int		(*tb_lookup)(struct fib_table *tb, const struct flowi *flp, struct fib_result *res);
	/*
	 * 用于在当前路由表中插入给定的路由表项，在FIB_HASH算法中为fn_hash_insert(),此接口被inet_rtm_newroute和ip_rt_ioctl调用，
	 * 通常在ip route add 和route add 命令时被激活。该接口页被fib_magic调用
	 */
	int		(*tb_insert)(struct fib_table *, struct fib_config *);
	/*
	 * 用于在当前路由表中删除符合条件的路由表项，在FIB_HASH算法中为fn_hash_delete(),此接口被inet_rtm_delroute 和ip_rt_ioctl调用，
	 * 该接口也被fib_magic调用
	 */
	int		(*tb_delete)(struct fib_table *, struct fib_config *);
	/*
	 * dump出路由表的内容，在FIB_HASHz算法中为fn_hash_dump(),此接口也被inet_rtm_getroute调用
	 */
	int		(*tb_dump)(struct fib_table *table, struct sk_buff *skb,
				     struct netlink_callback *cb);
	/*
	 * 删除设置有RTNH_F_DEAD标志的fib_info结构实例，在FIB_HASH算法中为fib_hash_flush()
	 */
	int		(*tb_flush)(struct fib_table *table);
	/*
	 * 选择一条默认路由，在FIB_HASH算法中为fib_hash_select_default()
	 */
	void		(*tb_select_default)(struct fib_table *table,
					     const struct flowi *flp, struct fib_result *res);

	/*
	 * 路由表项的三列表起始地址，在FIB_HASH算法中指向fn_hash结构
	 */
	unsigned char	tb_data[0];
};

#ifndef CONFIG_IP_MULTIPLE_TABLES

extern struct fib_table *ip_fib_local_table;
extern struct fib_table *ip_fib_main_table;

static inline struct fib_table *fib_get_table(u32 id)
{
	if (id != RT_TABLE_LOCAL)
		return ip_fib_main_table;
	return ip_fib_local_table;
}

/*获取指定的路由表*/
static inline struct fib_table *fib_new_table(u32 id)
{
	return fib_get_table(id);
}

static inline int fib_lookup(const struct flowi *flp, struct fib_result *res)
{
	if (ip_fib_local_table->tb_lookup(ip_fib_local_table, flp, res) &&
	    ip_fib_main_table->tb_lookup(ip_fib_main_table, flp, res))
		return -ENETUNREACH;
	return 0;
}

static inline void fib_select_default(const struct flowi *flp, struct fib_result *res)
{
	if (FIB_RES_GW(*res) && FIB_RES_NH(*res).nh_scope == RT_SCOPE_LINK)
		ip_fib_main_table->tb_select_default(ip_fib_main_table, flp, res);
}

#else /* CONFIG_IP_MULTIPLE_TABLES */
#define ip_fib_local_table fib_get_table(RT_TABLE_LOCAL)
#define ip_fib_main_table fib_get_table(RT_TABLE_MAIN)

extern int fib_lookup(struct flowi *flp, struct fib_result *res);

extern struct fib_table *fib_new_table(u32 id);
extern struct fib_table *fib_get_table(u32 id);
extern void fib_select_default(const struct flowi *flp, struct fib_result *res);

#endif /* CONFIG_IP_MULTIPLE_TABLES */

/* Exported by fib_frontend.c */
extern struct nla_policy rtm_ipv4_policy[];
extern void		ip_fib_init(void);
extern int inet_rtm_delroute(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg);
extern int inet_rtm_newroute(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg);
extern int inet_rtm_getroute(struct sk_buff *skb, struct nlmsghdr* nlh, void *arg);
extern int inet_dump_fib(struct sk_buff *skb, struct netlink_callback *cb);
extern int fib_validate_source(__be32 src, __be32 dst, u8 tos, int oif,
			       struct net_device *dev, __be32 *spec_dst, u32 *itag);
extern void fib_select_multipath(const struct flowi *flp, struct fib_result *res);

struct rtentry;

/* Exported by fib_semantics.c */
extern int ip_fib_check_default(__be32 gw, struct net_device *dev);
extern int fib_sync_down(__be32 local, struct net_device *dev, int force);
extern int fib_sync_up(struct net_device *dev);
extern __be32  __fib_res_prefsrc(struct fib_result *res);

/* Exported by fib_hash.c */
extern struct fib_table *fib_hash_init(u32 id);

#ifdef CONFIG_IP_MULTIPLE_TABLES
extern int fib4_rules_dump(struct sk_buff *skb, struct netlink_callback *cb);

extern void __init fib4_rules_init(void);

#ifdef CONFIG_NET_CLS_ROUTE
extern u32 fib_rules_tclass(struct fib_result *res);
#endif

#endif

static inline void fib_combine_itag(u32 *itag, struct fib_result *res)
{
#ifdef CONFIG_NET_CLS_ROUTE
#ifdef CONFIG_IP_MULTIPLE_TABLES
	u32 rtag;
#endif
	*itag = FIB_RES_NH(*res).nh_tclassid<<16;
#ifdef CONFIG_IP_MULTIPLE_TABLES
	rtag = fib_rules_tclass(res);
	if (*itag == 0)
		*itag = (rtag<<16);
	*itag |= (rtag>>16);
#endif
#endif
}

extern void free_fib_info(struct fib_info *fi);

static inline void fib_info_put(struct fib_info *fi)
{
	if (atomic_dec_and_test(&fi->fib_clntref))
		free_fib_info(fi);
}

static inline void fib_res_put(struct fib_result *res)
{
	if (res->fi)
		fib_info_put(res->fi);
#ifdef CONFIG_IP_MULTIPLE_TABLES
	if (res->r)
		fib_rule_put(res->r);
#endif
}

#ifdef CONFIG_PROC_FS
extern int  fib_proc_init(void);
extern void fib_proc_exit(void);
#endif

#endif  /* _NET_FIB_H */

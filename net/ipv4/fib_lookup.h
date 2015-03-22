#ifndef _FIB_LOOKUP_H
#define _FIB_LOOKUP_H

#include <linux/types.h>
#include <linux/list.h>
#include <net/ip_fib.h>

struct fib_alias {
	/*将共享同一个fib_node的fib_alias实例链接在一起*/
	struct list_head	fa_list;
	struct rcu_head rcu;
	/*fib_info实例，该实例存储着如何处理与该路由相匹配的数据包的消息*/
	struct fib_info		*fa_info;
	/*ip的TOS ,同一个fib_node的alias实例根据该字段递增排列
	 * 路由的服务类型tos字段，为0时没有设置tos，所以在路由查找任何值时都可以匹配，
	 * fa_tos用户对每一条路由表项配置的TOS,区别与fib_rule4中的tos
	 * */
	u8			fa_tos;
	/*路由表项的类型，间接定义路由查找匹配时应采取的动作,如RTN_UNSPEC*/
	u8			fa_type;
	/*路由表的作用范围*/
	u8			fa_scope;
	/*一些标志的位图，目前只有一个标志，FA_S_ACCESSED表示该表项被访问过*/
	u8			fa_state;
};

#define FA_S_ACCESSED	0x01

/* Exported by fib_semantics.c */
extern int fib_semantic_match(struct list_head *head,
			      const struct flowi *flp,
			      struct fib_result *res, __be32 zone, __be32 mask,
				int prefixlen);
extern void fib_release_info(struct fib_info *);
extern struct fib_info *fib_create_info(struct fib_config *cfg);
extern int fib_nh_match(struct fib_config *cfg, struct fib_info *fi);
extern int fib_dump_info(struct sk_buff *skb, u32 pid, u32 seq, int event,
			 u32 tb_id, u8 type, u8 scope, __be32 dst,
			 int dst_len, u8 tos, struct fib_info *fi,
			 unsigned int);
extern void rtmsg_fib(int event, __be32 key, struct fib_alias *fa,
		      int dst_len, u32 tb_id, struct nl_info *info);
extern struct fib_alias *fib_find_alias(struct list_head *fah,
					u8 tos, u32 prio);
extern int fib_detect_death(struct fib_info *fi, int order,
			    struct fib_info **last_resort,
			    int *last_idx, int *dflt);

#endif /* _FIB_LOOKUP_H */

/*
 * Common code for low-level network console, dump, and debugger code
 *
 * Derived from netconsole, kgdb-over-ethernet, and netdump patches
 */

#ifndef _LINUX_NETPOLL_H
#define _LINUX_NETPOLL_H

#include <linux/netdevice.h>
#include <linux/interrupt.h>
#include <linux/rcupdate.h>
#include <linux/list.h>

struct netpoll {
	/*实例所绑定的网络设备，通过该设备接口接受和发送报文*/
	struct net_device *dev;
	/*实例所绑定的网络设备名，如eth0*/
	char dev_name[IFNAMSIZ];
	/*netpoll实例名，如netconsole*/
	const char *name;
	/*
	 * netpoll实例接受报文例程
	 * netpoll实例接受处理的报文不会再上传到上层协议
	 **/
	void (*rx_hook)(struct netpoll *, int, char *, int);

	/*本地ip  与远端ip*/
	u32 local_ip, remote_ip;
	/*本地与远端udp  port*/
	u16 local_port, remote_port;
	/*本地与远端mac 地址*/
 	u8 local_mac[ETH_ALEN], remote_mac[ETH_ALEN];
};

struct netpoll_info {
	/*引用计数*/
	atomic_t refcnt;
	/*并发访问锁，确保同一时刻只有一个cpu调用网络设备的poll接口，轮寻操作*/
	spinlock_t poll_lock;
	/*标识正在从网络设备读取数据的cpu,-1代表没有*/
	int poll_owner;
	/*标识接受特性
	 *NETPOLL_RX_ENABLED:所有netpoll实例允许输入的报文
	 *NETPOLL_RX_DROP: 尚未使用
	 */
	int rx_flags;
	/*并发访问锁，确保同一时刻只有一个cpu在进行netpoll的输入操作*/
	spinlock_t rx_lock;
	/*为netpoll接受而注册的相关信息*/
	struct netpoll *rx_np; /* netpoll that registered an rx_hook */
	/*存储接收到的arp报文*/
	struct sk_buff_head arp_tx; /* list of arp requests to reply to */

	/*
	 * 调用netpoll_send_skb()没有能成功输出数据包或者设备繁忙，则将待输出报文缓存到txq，
	 * 待tx_work工作队列尝试将它输出
	 */
	struct sk_buff_head txq;
	struct delayed_work tx_work;
};

void netpoll_poll(struct netpoll *np);
void netpoll_send_udp(struct netpoll *np, const char *msg, int len);
int netpoll_parse_options(struct netpoll *np, char *opt);
int netpoll_setup(struct netpoll *np);
int netpoll_trap(void);
void netpoll_set_trap(int trap);
void netpoll_cleanup(struct netpoll *np);
int __netpoll_rx(struct sk_buff *skb);


#ifdef CONFIG_NETPOLL
/*返回0 netpoll实例没有接受，需要交由协议栈处理*/
static inline int netpoll_rx(struct sk_buff *skb)
{
	struct netpoll_info *npinfo = skb->dev->npinfo;
	unsigned long flags;
	int ret = 0;

	/*如果设备没有设置netpoll信息块或这是netpoll实例不支持接受数据包，则返回*/
	if (!npinfo || (!npinfo->rx_np && !npinfo->rx_flags))
		return 0;

	spin_lock_irqsave(&npinfo->rx_lock, flags);
	/* check rx_flags again with the lock held */
	if (npinfo->rx_flags && __netpoll_rx(skb))
		ret = 1;
	spin_unlock_irqrestore(&npinfo->rx_lock, flags);

	return ret;
}

static inline void *netpoll_poll_lock(struct net_device *dev)
{
	rcu_read_lock(); /* deal with race on ->npinfo */
	if (dev->npinfo) {
		spin_lock(&dev->npinfo->poll_lock);
		dev->npinfo->poll_owner = smp_processor_id();
		return dev->npinfo;
	}
	return NULL;
}

static inline void netpoll_poll_unlock(void *have)
{
	struct netpoll_info *npi = have;

	if (npi) {
		npi->poll_owner = -1;
		spin_unlock(&npi->poll_lock);
	}
	rcu_read_unlock();
}

#else
#define netpoll_rx(a) 0
#define netpoll_poll_lock(a) NULL
#define netpoll_poll_unlock(a)
#endif

#endif

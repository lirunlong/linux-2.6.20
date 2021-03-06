/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the TCP protocol.
 *
 * Version:	@(#)tcp.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_TCP_H
#define _LINUX_TCP_H

#include <linux/types.h>
#include <asm/byteorder.h>
#include <linux/socket.h>

struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif	
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
};

/*
 *	The union cast uses a gcc extension to avoid aliasing problems
 *  (union is compatible to any of its members)
 *  This means this part of the code is -fstrict-aliasing safe now.
 */
union tcp_word_hdr { 
	struct tcphdr hdr;
	__be32 		  words[5];
}; 

#define tcp_flag_word(tp) ( ((union tcp_word_hdr *)(tp))->words [3]) 

enum { 
	TCP_FLAG_CWR = __constant_htonl(0x00800000), 
	TCP_FLAG_ECE = __constant_htonl(0x00400000), 
	TCP_FLAG_URG = __constant_htonl(0x00200000), 
	TCP_FLAG_ACK = __constant_htonl(0x00100000), 
	TCP_FLAG_PSH = __constant_htonl(0x00080000), 
	TCP_FLAG_RST = __constant_htonl(0x00040000), 
	TCP_FLAG_SYN = __constant_htonl(0x00020000), 
	TCP_FLAG_FIN = __constant_htonl(0x00010000),
	TCP_RESERVED_BITS = __constant_htonl(0x0F000000),
	TCP_DATA_OFFSET = __constant_htonl(0xF0000000)
}; 

/* TCP socket options */
#define TCP_NODELAY		1	/* Turn off Nagle's algorithm. */
#define TCP_MAXSEG		2	/* Limit MSS */
#define TCP_CORK		3	/* Never send partially complete segments */
#define TCP_KEEPIDLE		4	/* Start keeplives after this period */
#define TCP_KEEPINTVL		5	/* Interval between keepalives */
#define TCP_KEEPCNT		6	/* Number of keepalives before death */
#define TCP_SYNCNT		7	/* Number of SYN retransmits */
#define TCP_LINGER2		8	/* Life time of orphaned FIN-WAIT-2 state */
#define TCP_DEFER_ACCEPT	9	/* Wake up listener only when data arrive */
#define TCP_WINDOW_CLAMP	10	/* Bound advertised window */
#define TCP_INFO		11	/* Information about this connection. */
#define TCP_QUICKACK		12	/* Block/reenable quick acks */
#define TCP_CONGESTION		13	/* Congestion control algorithm */
#define TCP_MD5SIG		14	/* TCP MD5 Signature (RFC2385) */

#define TCPI_OPT_TIMESTAMPS	1
#define TCPI_OPT_SACK		2
#define TCPI_OPT_WSCALE		4
#define TCPI_OPT_ECN		8

enum tcp_ca_state
{
	TCP_CA_Open = 0,
#define TCPF_CA_Open	(1<<TCP_CA_Open)
	TCP_CA_Disorder = 1,
#define TCPF_CA_Disorder (1<<TCP_CA_Disorder)
	TCP_CA_CWR = 2,
#define TCPF_CA_CWR	(1<<TCP_CA_CWR)
	TCP_CA_Recovery = 3,
#define TCPF_CA_Recovery (1<<TCP_CA_Recovery)
	TCP_CA_Loss = 4
#define TCPF_CA_Loss	(1<<TCP_CA_Loss)
};

struct tcp_info
{
	__u8	tcpi_state;
	__u8	tcpi_ca_state;
	__u8	tcpi_retransmits;
	__u8	tcpi_probes;
	__u8	tcpi_backoff;
	__u8	tcpi_options;
	__u8	tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;

	__u32	tcpi_rto;
	__u32	tcpi_ato;
	__u32	tcpi_snd_mss;
	__u32	tcpi_rcv_mss;

	__u32	tcpi_unacked;
	__u32	tcpi_sacked;
	__u32	tcpi_lost;
	__u32	tcpi_retrans;
	__u32	tcpi_fackets;

	/* Times. */
	__u32	tcpi_last_data_sent;
	__u32	tcpi_last_ack_sent;     /* Not remembered, sorry. */
	__u32	tcpi_last_data_recv;
	__u32	tcpi_last_ack_recv;

	/* Metrics. */
	__u32	tcpi_pmtu;
	__u32	tcpi_rcv_ssthresh;
	__u32	tcpi_rtt;
	__u32	tcpi_rttvar;
	__u32	tcpi_snd_ssthresh;
	__u32	tcpi_snd_cwnd;
	__u32	tcpi_advmss;
	__u32	tcpi_reordering;

	__u32	tcpi_rcv_rtt;
	__u32	tcpi_rcv_space;

	__u32	tcpi_total_retrans;
};

/* for TCP_MD5SIG socket option */
#define TCP_MD5SIG_MAXKEYLEN	80

struct tcp_md5sig {
	struct __kernel_sockaddr_storage tcpm_addr;	/* address associated */
	__u16	__tcpm_pad1;				/* zero */
	__u16	tcpm_keylen;				/* key length */
	__u32	__tcpm_pad2;				/* zero */
	__u8	tcpm_key[TCP_MD5SIG_MAXKEYLEN];		/* key (binary) */
};

#ifdef __KERNEL__

#include <linux/skbuff.h>
#include <linux/dmaengine.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <net/inet_timewait_sock.h>

/* This defines a selective acknowledgement block. */
struct tcp_sack_block_wire {
	__be32	start_seq;
	__be32	end_seq;
};

struct tcp_sack_block {
	u32	start_seq;
	u32	end_seq;
};

/*保存接收到的tcp选项信息，如时间戳，SACK等
 * 同时标识对端支持的特性，如对段是否支持窗口扩大因子，是否支持SACK等
 */
struct tcp_options_received {
/*	PAWS/RTTM data	*/
	/*记录从接收到的段中取出时间戳设置到ts_recent的时间，用于检测ts_recent的有效性，如果
	 * 自从该时间之后已经超过了24天的时间，则认为ts_recent已无效*/
	long	ts_recent_stamp;/* Time we stored ts_recent (for aging) */
	/*下一个待发送的TCP段中的时间戳回显值，当一个含有最后发送ACK
	 *中确认序号的段到达时,该段中的时间戳被保存在ts_recent中，而下一个待发送的TCP段的时间戳值是由SKB中TCP控制块的成员when填入的，when字段值是由
	 协议栈取系统时间变量jiffies的低32位*/
	u32	ts_recent;	/* Time stamp to echo next		*/
	/*保存最近一次接收到对端的TCP段的时间戳选项中的时间戳值*/
	u32	rcv_tsval;	/* Time stamp value             	*/
	/*保存最近一次接收到对端的TCP段的时间戳选项中的时间戳回显应答*/
	u32	rcv_tsecr;	/* Time stamp echo reply        	*/
	/*标识最近一次接收到的tcp段是否存在时间戳选项，1有，0不存在*/
	u16 	saw_tstamp : 1,	/* Saw TIMESTAMP on last packet		*/
			/*标识tcp连接是否启用时间戳选项。
			 * 在tcp连接中如果接收到的段中有时间戳选项，说明对段也支持时间戳选项，这是tstamp_ok设置为1，
			 * 标识该链接支持时间戳选项，在随后的数据传输中，tcp首部中都会带有时间戳选项*/
		tstamp_ok : 1,	/* TIMESTAMP seen on SYN packet		*/
		/*标识下次发送的段中SACK选项中是否存在D-SACK*/
		dsack : 1,	/* D-SACK is scheduled			*/
		/*标识接受方是否支持窗口扩大因子，只能出现在SYN段中*/
		wscale_ok : 1,	/* Wscale seen on SYN packet		*/
		/*标识接收方是否支持SACK 0不支持，非0 支持
		 * 此外，sack_ok占4位，因此在正常带有负荷的段中，其余位还有其他含义
		 * 第一位标识是否启用FACK拥塞避免，第2位标识SACK选项是否存在D-SACK，第3位保留。
		 */
		sack_ok : 4,	/* SACK seen on SYN packet		*/
		/*发送窗口扩大因子，即要把TCP首部中滑动窗口大小左移snd_wscale位后，才是真正的滑动窗口大小，在TCP首部中，滑动窗口大小是16位，
		 * 而snd_wscale最大值为14，滑动窗口最大可以扩展到30位，*/
		snd_wscale : 4,	/* Window scaling received from sender	*/
		/*接收窗口扩大因子*/
		rcv_wscale : 4;	/* Window scaling to send to receiver	*/
/*	SACKs data	*/
	/*下一个待发送的段中SACK选项的SACK数组的大小，如果为0，则认为没有SACK*/
	u8	eff_sacks;	/* Size of SACK array to send with next packet */
	/*下一个待发送的段中SACK选项的SACK的块数，同时用来计算eff_sacks*/
	u8	num_sacks;	/* Number of SACK blocks		*/
	/*为用户设置的MSS上限，与建立链接时，syn段中MSS，两者之间的最小值作为该链接的MSS上限，存储在mss_clamp中。使用
	 * setsockopt/getsockopt 系统调用TCP_MAXSEG选项设置/获取，有效值在8到32767之间*/
	u16	user_mss;  	/* mss requested by user in ioctl */
	/*该链接的对段MSS上限*/
	u16	mss_clamp;	/* Maximal mss, negotiated at connection setup */
};

struct tcp_request_sock {
	struct inet_request_sock 	req;
#ifdef CONFIG_TCP_MD5SIG
	/* Only used by TCP MD5 Signature so far. */
	struct tcp_request_sock_ops	*af_specific;
#endif
	/*客户端初始序号*/
	u32			 	rcv_isn;
	/*服务端初始序号*/
	u32			 	snt_isn;
};

static inline struct tcp_request_sock *tcp_rsk(const struct request_sock *req)
{
	return (struct tcp_request_sock *)req;
}

struct tcp_sock {
	/* inet_connection_sock has to be the first member of tcp_sock */
	struct inet_connection_sock	inet_conn;
	/*tcp首部长度，包括tcp选项*/
	u16	tcp_header_len;	/* Bytes of tcp header to send		*/
	/*记录该套接口发送到网络设备段的长度，在不支持TSO的情况下，其值就等于MSS，而如果网卡
	 * 支持TSO且采用TSO进行发送，则需要重新计算，tcp_current_mss()*/
	u16	xmit_size_goal;	/* Goal for segmenting output packets	*/

/*
 *	Header prediction flags
 *	0x5?10 << 16 + snd_wnd in net byte order
 */
	/*首部预测标志，会在发送和接收syn，更新窗口或其他恰当的时候，设置该标志。该标志和时间戳
	 * 以及序列号等因素一样是判断执行快速路径还是慢速路径的条件之一*/
	__be32	pred_flags;

/*
 *	RFC793 variables by their proper names. This means you can
 *	read the code and the spec side by side (and laugh ...)
 *	See RFC793 and RFC1122. The RFC writes these in capitals.
 */
	/*等待接收的下一个tcp段的序号，每接收到一个TCP段之后都会更新该值*/
 	u32	rcv_nxt;	/* What we want to receive next 	*/
	/*等待发送的下一个tcp段的序号。*/
 	u32	snd_nxt;	/* Next sequence we send		*/

	/*在输出的段中，最早一个未被确认的段*/
 	u32	snd_una;	/* First byte we want an ack for	*/
	/*最近发送的小包(小于MSS的段)的最后一个字节序号，在成功发送段后，如果报文小于mss，则更新该字段，主要用来判断是否启用nagle算法*/
 	u32	snd_sml;	/* Last byte of the most recently transmitted small packet */
	/*最近一次收到ack段的时间，用于tcp保活*/
	u32	rcv_tstamp;	/* timestamp of last received ACK (for keepalives) */
	/*最近一次发送数据包的时间，主要用于拥塞窗口的设置*/
	u32	lsndtime;	/* timestamp of last sent data packet (for restart window) */

	/* Data for direct copy to user */
	/*用于控制复制数据到用户进程的控制块，包括描述用户空间缓存及其长度，prequeue队列及其占用内存等*/
	struct {
		/*如果未启用tcp_low_latency,TCP段将首先缓存到此队列，直到进程主动读却时才真正地接收到接受队列中并处理*/
		struct sk_buff_head	prequeue;
		/*在未启用tcp_low_latency，当前正在读取tcp流的进程,如果为NULL，标识没有进程对其读取*/
		struct task_struct	*task;
		/*未启用tcp_low_latency时，用来存放数据的用户空间地址，在接收处理tcp段时，直接复制到用户空间*/
		struct iovec		*iov;
		/*prequeue队列当前消耗的内存*/
		int			memory;
		/*用户缓存中当前可以使用的缓存大小，由recv 等的len参数初始化*/
		int			len;
#ifdef CONFIG_NET_DMA
		/* members for async copy */
		struct dma_chan		*dma_chan;
		int			wakeup;
		struct dma_pinned_list	*pinned_list;
		dma_cookie_t		dma_cookie;
#endif
	} ucopy;

	/*记录更新发送窗口的那个ACK段的序号，用来判断是否需要更新窗口。如果后续收到的ack段的序号大于snd_wl1,则说明需要更新，否则不许要更新*/
	u32	snd_wl1;	/* Sequence for window update		*/
	/*接收放提供的接收窗口大小，即发送方发送窗口大小*/
	u32	snd_wnd;	/* The window we expect to receive	*/
	/*接收方通告过的最大窗口值*/
	u32	max_window;	/* Maximal window ever seen from peer	*/
	/*发送方当前有效的MSS*/
	u32	mss_cache;	/* Cached effective mss, not including SACKS */

	/*滑动窗口最大值，滑动窗口大小在变化过程中始终不能超过该值，在tcp建立连接时，该字段被初始化，置位最大的16位整数左移窗口的扩大因子，
	 * 因为滑动窗口在tcp首部中以16位表示，window_clamp太大会导致滑动窗口不能在tcp首部中表示*/
	u32	window_clamp;	/* Maximal window to advertise		*/
	/*当前接收窗口大小的阀值，该字段与rcv_wnd两者配合，达到滑动窗口大小缓慢增长的效果；其初始值为rcv_wnd,当本地套接口收到段，并满足一定条件时，
	 * 会递增该字段值，到下一次发送数据组建tcp首部时，需通告对端当前接收窗口大小，此时更新rcv_wnd,而rcv_wnd的值不能超过rcv_ssthresh.*/
	u32	rcv_ssthresh;	/* Current window clamp			*/

	/*当重传超时发生时，在启用F-RTO时，用来保存待发送的下一个tcp段的序号，在tcp_process_frto()中处理F-rto时使用*/
	u32	frto_highmark;	/* snd_nxt when RTO occurred */
	/*当不知池SACK时，为由于连接接收到重复确认而进入快速恢复阶段的重复确认数阀值，在支持SACK时，在没有确定丢失包的情况下，是TCP流中
	 * 可以重排序的数据段数*/
	u8	reordering;	/* Packet reordering metric.		*/
	/*在传送超时后，记录在启用F-RTO算法时接收到ACK段的数目。传送超时后，如果启用了F-RTO算法，则进入F-RTO处理阶段，在此阶段，
	 * 如果连续收到3个对新数据确认的ACK段，则恢复到正常模式下，非零时，也标识在F-RTO阶段*/
	u8	frto_counter;	/* Number of new acks after RTO */
	/*标识是否允许nagle算法，
	 * TCP_NAGLE_OFF:关闭nagle算法
	 * TCP_NAGLE_CORK:对nagle算法进行优化，使发送的段尽可能携带更多数据，但是有个200ms时间限制，一旦超时会排入发送队列进行发送
	 * TCP_NAGLE_PUSH:正常的nagle算法，不对nagle优化
	 */
	u8	nonagle;	/* Disable Nagle algorithm?             */
	/*保活探测次数，最大为127,TCP_KEEPCNT*/
	u8	keepalive_probes; /* num of allowed keep alive probes	*/

/* RTT measurement */
	/*平滑的RTT，为避免浮点运算，将值放大8倍存储的*/
	u32	srtt;		/* smoothed round trip time << 3	*/
	/*RTT平均偏差，由RTT与RTT均值偏差绝对值加权平均而得到的，其值越大说明RTT抖动的越厉害*/
	u32	mdev;		/* medium deviation			*/
	/*跟踪每次发送窗口内的段被全部确认过程中，RTT平均偏差的最大值，描述RTT抖动的最大范围*/
	u32	mdev_max;	/* maximal mdev for the last rtt period	*/
	/*平滑的RTT平均偏差，由 mdev计算得到，用来计算RTO*/
	u32	rttvar;		/* smoothed mdev_max			*/
	/*计算SND.UNA。用来在计算RTO时比较SND.UNA是否已经被更新了，如果被SND.UNA更新，则需要同时更新rttvar.*/
	u32	rtt_seq;	/* sequence number to update rttvar	*/

	/*从发送队列发出而未得到确认的tcp段的数目。*/
	u32	packets_out;	/* Packets which are "in flight"	*/
	/*已离开主机在网络中且未确认的的TCP段数，包含两种情况，一是通过SACK确认的段，一是丢失的段left_out=sack_out+lost_out
	 *  packets_out是已离开发送队列 不一定离开主机，所以packets_out>=left_out*/
	u32	left_out;	/* Packets which leaved network	*/
	/*重传还未得到确认的tcp段的数目*/
	u32	retrans_out;	/* Retransmitted packets out		*/
/*
 *      Options received (usually on last packet, some only on SYN packets).
 */
	/*存储接收到的tcp选项*/
	struct tcp_options_received rx_opt;

/*
 *	Slow start and congestion control (see also Nagle, and Karn & Partridge)
 */
	/*拥塞控制慢启动阀值*/
 	u32	snd_ssthresh;	/* Slow start size threshold		*/
	/*当前拥塞窗口大小*/
 	u32	snd_cwnd;	/* Sending congestion window		*/
	/*自从上次调整拥塞窗口到目前位置接收到的ack段数，如果该字段为0 ，说明已经调整了拥塞窗口，且到目前为止还没由接收到ack，
	 * 调整拥塞窗口后，每接收到一个ack  snd_cwnd_cnt++*/
 	u16	snd_cwnd_cnt;	/* Linear increase counter		*/
	/*允许的最大拥塞窗口，初始值为65535,之后在接收syn和ack段时，会根据条件是否从路由配置项读取信息更新该字段，最后在tcp链接复位前，
	 * 将更新后的值根据某种算法计算后再更新回相对应的路由配置项中，便于连接使用*/
	u16	snd_cwnd_clamp; /* Do not allow snd_cwnd to grow above this */
	/*当应用程序限制时，记录当前从发送队列发出而未得到确认的段数，用于在检验拥塞窗口时调节拥塞窗口，避免拥塞窗口失效*/
	u32	snd_cwnd_used;
	/*记录最近一次检验拥塞窗口的时间，在拥塞期间，接受到ack后会进行拥塞窗口的检验。而在非拥塞期间，为了防止
	 * 由于应用程序限制而造成拥塞窗口失效，因此在成功发送段后，如果有必要也会检验拥塞窗口*/
	u32	snd_cwnd_stamp;

	/*乱序缓存队列，用于咱存接受到的乱序队列*/
	struct sk_buff_head	out_of_order_queue; /* Out of order segments go here */

	/*当前接收窗口的大小*/
 	u32	rcv_wnd;	/* Current receiver window		*/
	/*标识最早接收但未确认的段的序号，即当前接受窗口的左段，在发送ack时，由rcv_nxt更新，因此rcv_wup更新比rcv_nxt滞后一些*/
	u32	rcv_wup;	/* rcv_nxt on last window update sent	*/
	/*已加入到发送队列的最后一个字节的序号*/
	u32	write_seq;	/* Tail(+1) of data held in tcp send buffer */
	/*通常情况下表示已经真正发出去的最后一个字节的序号，但有时也表示期望发送出去的最后一个字节的序号，
	 * 如启用Nagle算法之后，或在发送持续探测段后*/
	u32	pushed_seq;	/* Last pushed seq, required to talk to windows */
	/*尚未从内核空间复制到用户空间的段最前面的一个字节的序号*/
	u32	copied_seq;	/* Head of yet unread data		*/

/*	SACKs data	*/
	/*
	 *存储用于回复对段SACK的信息，duplicate_sack存储D-SACK信息，selective_acks存储SACK信息，在回复SACK时会从中取出D-SACK和SACK信息，
	 *而在处理在接收到乱需的报文段时，会向这两个字段中填入相应的信息
	 */
	struct tcp_sack_block duplicate_sack[1]; /* D-SACK block */
	struct tcp_sack_block selective_acks[4]; /* The SACKS themselves*/

	/*存储接收到的SACK选项信息*/
	struct tcp_sack_block recv_sack_cache[4];

	/* from STCP, retrans queue hinting */
	struct sk_buff* lost_skb_hint;

	struct sk_buff *scoreboard_skb_hint;
	struct sk_buff *retransmit_skb_hint;
	struct sk_buff *forward_skb_hint;
	struct sk_buff *fastpath_skb_hint;

	int     fastpath_cnt_hint;
	int     lost_cnt_hint;
	int     retransmit_cnt_hint;
	int     forward_cnt_hint;

	/*本端能接收的MSS上限，在建立链接时用来通告对端，此值由路由缓存项中MSS度量值(RTAX_ADVMSS)进行初始化,
	 * 而路由缓存项中MSS度量值则直接取自网络设备接口的MUT减去IP首部及TCP首部的长度，参见 rt_set_nexthop()*/
	u16	advmss;		/* Advertised MSS			*/
	/*在启用FRTO算法的情况下,路径MTU探测成功，进入拥塞控制Disorder,Recovery,Loss状态保存的ssthresh的值,
	 * 主要用来在拥塞窗口撤销时，恢复拥塞控制的慢启动阀值，当此值为0时，禁止撤销拥塞窗口*/
	u16	prior_ssthresh; /* ssthresh saved at recovery start	*/
	/*发送后丢失在传输过程中段的数量。目前tcp协议还没有类似的"段丢失通知机制",因此丢失的段只能通过某种算法进行推测，
	 * 如，当RTO超时之后，可以认为发送的段丢失*/
	u32	lost_out;	/* Lost packets			*/
	/*启用sack后，通过SACK的tcp选项标识已接收到段的数量。不启用SACK时，标识接收到重复确认的次数。此值在
	 * 接收到确认新数据的段时清楚*/
	u32	sacked_out;	/* SACK'd packets			*/
	/*
	 *记录SND.UNA与SACK选项中目前接收方收到的段中最高序号段之间的段数,FACK算法用SACK选项来计算丢失在网络上的段数。例如：
	 *lost_out=fackets_out-sacket_out
	 *left_out=fackets_out
	 */
	u32	fackets_out;	/* FACK'd packets			*/
	/*记录发生拥塞时的SND.NXT,标识重传队列的尾部*/
	u32	high_seq;	/* snd_nxt at onset of congestion	*/

	/*在主动链接时，记录第一个SYN段的发送时间，用来检测ACK序号是否回绕。
	 * 在数据传输阶段，当发送数据超时时，记录上次重传阶段第一个重传段的发送时间，用来判断是否可以进行拥塞撤销
	 */
	u32	retrans_stamp;	/* Timestamp of the last retransmit,
				 * also used in SYN-SENT to remember stamp of
				 * the first SYN. */
	/*
	 * 在使用F-RTO算法进行发送超时处理，或进入Recovery进行重传，或进入Loss进入慢启动时，记录当时SND.UNA,标记重传起始点，它是检测是否可以
	 * 进行拥塞撤销的条件之一，一般在完成拥塞撤销操作或进入拥塞控制Loss状态后清零
	 */
	u32	undo_marker;	/* tracking retrans started here. */
	/*
	 * 在恢复拥塞控制之前可以进行撤销的重传段数，在进入FRTO算法或拥塞状态Loss时清零，在重传时计数，是检测是否可以进行拥塞撤销的条件之一
	 */
	int	undo_retrans;	/* number of undoable retransmissions. */
	/*紧急数据的序号，由所在段的序号加紧急指针*/
	u32	urg_seq;	/* Seq of received urgent pointer */
	/*低8位用于存放接收到的紧急数据
	 * 高8位用于标识紧急相关的状态
	 * TCP_URG_NOTYET:标识接收到的段中存在紧急数据
	 * TCP_URG_VALID:标识紧急数据是有效的，用户可以读取
	 * TCP_URG_READ:标识紧急数据已全部被读取
	 * */
	u16	urg_data;	/* Saved octet of OOB data and control flags */
	/*标识处于紧急模式，高速接收方“紧急数据”已经放置在普通数据流中*/
	u8	urg_mode;	/* In urgent mode		*/
	/*显示拥塞通知状态位
	 * TCP_ECN_OK:标识本端是否支持显示拥塞通知，在建立TCP链接的过程中根据tcp_ecn系统参数和TCP首部中的ECE，CWR标志位设置
	 * TCP_ECN_QUEUE_CWR:标识发送方由于收到显示拥塞 通知而进入拥塞状态
	 * TCP_ECN_DEMAND_CWR:标识接收到的段经历了拥塞
	 */
	u8	ecn_flags;	/* ECN status bits.			*/
	/*
	 * 紧急数据指针，即带外数据的序号，用来计算tcp首部中的“紧急指针”
	 */
	u32	snd_up;		/* Urgent pointer		*/

	/*整个链接中总重传次数*/
	u32	total_retrans;	/* Total retransmits for entire connection */
	/*启用tcp_abc之后，在拥塞回避阶段，保存已确认的字节数，RFC3465*/
	u32	bytes_acked;	/* Appropriate Byte Counting - RFC3465 */

	/*tcp发送保活探测前，tcp链接的空闲时间，即保活定时器启动的时间阀值。在启用SO_KEEPLIVE选项的情况下，一个链接空闲了一段时间之后，
	 * tcp会发送保活探测到对端系统，如果对端系统没有对保活探测进行回应，TCP会重复发送保活探测，直到连续发送而没有得到回应的保活探测达到一定的数量
	 * ,才认为这个连接有效，参见TCP_KEEPIDLE选项
	 */
	unsigned int		keepalive_time;	  /* time before keep alive takes place */
	/*
	 *发送保活探测的时间间隔，参加TCP_KEEPINTVL选项
	 */
	unsigned int		keepalive_intvl;  /* time interval between keep alive probes */
	/*标识tcp迁移到关闭CLOSED状态之前保存在FIN_WAIT_2状态的时间，参加TCP_LINGER2选项*/
	int			linger2;

	/*在启用tcp_syncookies的情况下，建立连接时记录SYN段的时间，用来检测建立链接是否超时*/
	unsigned long last_synq_overflow; 

	/*标识经过TSO分段的段是否需要延时发送，但即使延时发送，也不能超过两个时钟滴答*/
	u32	tso_deferred;

/* Receiver side RTT estimation */
	/*存放接收方的RTT估算值，用于实现通过调节接收窗口来进行流量控制的功能。接收方RTT估算值用来限制调整TCP接收缓冲区空间的频率
	 * ,每次调整TCP接收缓冲区空间的间隔时间不能小于RTT
	 */
	struct {
		/*存放接收方估算的RTT，计算方法因接收到的段中是否有时间戳选项而不同 */
		u32	rtt;
		/*在接收到的段没有时间戳的情况下，更新接收方RTT时的接收窗口右端序号，每完成一个
		 * 接收窗口的接收更新一次接收方RTT*/
		u32	seq;
		/*在接收到的段没有时间戳的情况下，记录每次更新接收方RTT的时间，用来计算接收方的RTT*/
		u32	time;
	} rcv_rtt_est;

/* Receiver queue space */
	/*用来调整TCP接收缓冲空间和接收窗口的大小，也用于实现通过调节接收窗口来进行流量控制的功能。
	 * 每次将数据复制到用户空间，都会调用tcp_rcv_space_adjust()来计算新的TCP接收缓冲空间大小*/
	struct {
		/*用来调整接收缓存的大小*/
		int	space;
		/*已复制到用户空间的tcp段序号*/
		u32	seq;
		/*记录最近一次调整的时间*/
		u32	time;
	} rcvq_space;

/* TCP-specific MTU probe information. */
	/*存储已发送MTU发现段的起始序号和接收序号，与发送MTU发现段的SKB中tcp_skb_cb结构和
	 *的seq和end_seq字段相对应，用来判断路径MTU发现是否成功*/
	struct {
		u32		  probe_seq_start;
		u32		  probe_seq_end;
	} mtu_probe;

#ifdef CONFIG_TCP_MD5SIG
/* TCP AF-Specific parts; only used by MD5 Signature support so far */
	struct tcp_sock_af_ops	*af_specific;

/* TCP MD5 Signagure Option information */
	struct tcp_md5sig_info	*md5sig_info;
#endif
};

static inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

struct tcp_timewait_sock {
	struct inet_timewait_sock tw_sk;
	u32			  tw_rcv_nxt;
	u32			  tw_snd_nxt;
	u32			  tw_rcv_wnd;
	u32			  tw_ts_recent;
	long			  tw_ts_recent_stamp;
#ifdef CONFIG_TCP_MD5SIG
	u16			  tw_md5_keylen;
	u8			  tw_md5_key[TCP_MD5SIG_MAXKEYLEN];
#endif
};

static inline struct tcp_timewait_sock *tcp_twsk(const struct sock *sk)
{
	return (struct tcp_timewait_sock *)sk;
}

#endif

#endif	/* _LINUX_TCP_H */

#include <stdio.h>  
#include <stdlib.h>  
#include <pcap.h>  


char *iptos(u_long in);       //u_long即为 unsigned long  
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
//struct tm *ltime;                 //和时间处理有关的变量  

/* 4字节的IP地址 */
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
} ip_address;

/* IPv4 首部 */
typedef struct ip_header
{
	u_char  ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)  
	u_char  tos;            // 服务类型(Type of service)  
	u_short tlen;           // 总长(Total length)  
	u_short identification; // 标识(Identification)  
	u_short flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)  
	u_char  ttl;            // 存活时间(Time to live)  
	u_char  proto;          // 协议(Protocol)  
	u_short crc;            // 首部校验和(Header checksum)  
	ip_address  saddr;      // 源地址(Source address)  
	ip_address  daddr;      // 目的地址(Destination address)  
	u_int   op_pad;         // 选项与填充(Option + Padding)  
} ip_header;

/* UDP 首部*/
typedef struct udp_header
{
	u_short sport;          // 源端口(Source port)  
	u_short dport;          // 目的端口(Destination port)  
	u_short len;            // UDP数据包长度(Datagram length)  
	u_short crc;            // 校验和(Checksum)  
} udp_header;

typedef struct tcp_header //定义TCP首部 
{
	u_short sport; //16位源端口 
	u_short dport; //16位目的端口 
	u_int th_seq; //32位序列号 
	u_int th_ack; //32位确认号 
	u_char th_lenres;//4位首部长度/6位保留字 
	u_char th_flag; //6位标志位
	u_short th_win; //16位窗口大小
	u_short th_sum; //16位校验和
	u_short th_urp; //16位紧急数据偏移量
}tcp_header;;



int main() {

	pcap_if_t  * alldevs;       //所有网络适配器  
	pcap_if_t  *d;                  //选中的网络适配器  
	char errbuf[PCAP_ERRBUF_SIZE];   //错误缓冲区,大小为256  
	char source[PCAP_ERRBUF_SIZE];
	pcap_t *adhandle;           //捕捉实例,是pcap_open返回的对象  
	int i = 0;                            //适配器计数变量  
	struct pcap_pkthdr *header;    //接收到的数据包的头部  
	const u_char *pkt_data;           //接收到的数据包的内容  
	int res;                                    //表示是否接收到了数据包  
	u_int netmask;                       //过滤时用的子网掩码  
	char packet_filter[] = "ip and tcp";        //过滤字符  
	struct bpf_program fcode;                     //pcap_compile所调用的结构体  
	ip_header *ih;                                    //ip头部  
	udp_header *uh;                             //udp头部 
	tcp_header *th;								//tcp头部
	u_int ip_len;                                       //ip地址有效长度  
	u_short sport, dport;                        //主机字节序列  
												 //time_t local_tv_sec;              //和时间处理有关的变量  
												 //char timestr[16];                 //和时间处理有关的变量  
												 /**
												 int pcap_findalldevs_ex  ( char *  source,
												 struct pcap_rmtauth *  auth,
												 pcap_if_t **  alldevs,
												 char *  errbuf  );
												 PCAP_SRC_IF_STRING代表用户想从一个本地文件开始捕获内容;
												 */
												 //获取本地适配器列表  
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		//结果为-1代表出现获取适配器列表失败  
		fprintf(stderr, "Error in pcap_findalldevs_ex:\n", errbuf);
		//exit(0)代表正常退出,exit(other)为非正常退出,这个值会传给操作系统  
		exit(1);
	}
	//打印设备列表信息  
	/**
	d = alldevs 代表赋值第一个设备,d = d->next代表切换到下一个设备
	结构体 pcap_if_t:
	pcap_if *  next                 指向下一个pcap_if,pcap_if_t和pcap_if 结构是一样的
	char *  name                        代表适配器的名字
	char *  description         对适配器的描述
	pcap_addr *  addresses  适配器存储的地址
	u_int  flags                            适配器接口标识符,值为PCAP_IF_LOOPBACK
	*/
	for (d = alldevs; d != NULL; d = d->next) {
		printf("-----------------------------------------------------------------\nnumber:%d\nname:%s\n", ++i, d->name);
		if (d->description) {
			//打印适配器的描述信息  
			printf("description:%s\n", d->description);
		}
		else {
			//适配器不存在描述信息  
			printf("description:%s", "no description\n");
		}
		//打印本地环回地址  
		printf("\tLoopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");
		/**
		pcap_addr *  next     指向下一个地址的指针
		sockaddr *  addr       IP地址
		sockaddr *  netmask  子网掩码
		sockaddr *  broadaddr   广播地址
		sockaddr *  dstaddr        目的地址
		*/
		pcap_addr_t *a;       //网络适配器的地址用来存储变量  
		for (a = d->addresses; a; a = a->next) {
			//sa_family代表了地址的类型,是IPV4地址类型还是IPV6地址类型  
			switch (a->addr->sa_family)
			{
			case AF_INET:  //代表IPV4类型地址  
				printf("Address Family Name:AF_INET\n");
				if (a->addr) {
					//->的优先级等同于括号,高于强制类型转换,因为addr为sockaddr类型，对其进行操作须转换为sockaddr_in类型  
					printf("Address:%s\n", iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
				}
				if (a->netmask) {
					printf("\tNetmask: %s\n", iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
				}
				if (a->broadaddr) {
					printf("\tBroadcast Address: %s\n", iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
				}
				if (a->dstaddr) {
					printf("\tDestination Address: %s\n", iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
				}
				break;
			/*
			case AF_INET6: //代表IPV6类型地址  
				printf("Address Family Name:AF_INET6\n");
				printf("this is an IPV6 address\n");
				break;
			*/
			default:
				break;
			}
		}
	}
	//i为0代表上述循环未进入,即没有找到适配器,可能的原因为Winpcap没有安装导致未扫描到  
	if (i == 0) {
		printf("interface not found,please check winpcap installation");
	}

	int num;
	printf("Enter the interface number(1-%d):", i);
	//让用户选择选择哪个适配器进行抓包  
	scanf_s("%d", &num);
	printf("\n");

	//用户输入的数字超出合理范围  
	if (num<1 || num>i) {
		printf("number out of range\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	//跳转到选中的适配器  
	for (d = alldevs, i = 0; i< num - 1; d = d->next, i++);

	//运行到此处说明用户的输入是合法的  
	if ((adhandle = pcap_open(d->name,        //设备名称  
		65535,       //存放数据包的内容长度  
		PCAP_OPENFLAG_PROMISCUOUS,  //混杂模式  
		1000,           //超时时间  
		NULL,          //远程验证  
		errbuf         //错误缓冲  
	)) == NULL) {
		//打开适配器失败,打印错误并释放适配器列表  
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		// 释放设备列表   
		pcap_freealldevs(alldevs);
		return -1;
	}
	//打印输出,正在监听中  
	printf("\nlistening on %s...\n", d->description);

	//所在网络为无线局域网  
	if (pcap_datalink(adhandle) == DLT_IEEE802) {
		printf("DLT_IEEE802\n");
	}
	//所在网络为以太网,Ethernet (10Mb, 100Mb, 1000Mb, and up)  
	if (pcap_datalink(adhandle) == DLT_EN10MB) {
		printf("DLT_EN10MB\n");
	}

	//所在网络不是以太网,此处只取这种情况  
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		//释放列表  
		pcap_freealldevs(alldevs);
		return -1;
	}

	//先获得地址的子网掩码  
	if (d->addresses != NULL)
		/* 获得接口第一个地址的掩码 */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* 如果接口没有地址，那么我们假设一个C类的掩码 */
		netmask = 0xffffff;

	//pcap_compile()的原理是将高层的布尔过滤表  
	//达式编译成能够被过滤引擎所解释的低层的字节码  
	if (pcap_compile(adhandle,   //适配器处理对象  
		&fcode,
		packet_filter,   //过滤ip和tcp  
		1,                       //优化标志  
		netmask           //子网掩码  
	)<0)
	{
		//过滤出现问题  
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		// 释放设备列表  
		pcap_freealldevs(alldevs);
		return -1;
	}

	//设置过滤器  
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}


	//利用pcap_next_ex来接受数据包  
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
	{
		if (res == 0) {
			//返回值为0代表接受数据包超时，重新循环继续接收  
			continue;
		}
		else {
			//运行到此处代表接受到正常从数据包  
			// 将时间戳转换成可识别的格式  
			//local_tv_sec = header->ts.tv_sec;  
			//localtime_s(ltime,&local_tv_sec);  
			//strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);  
			//header为帧的头部  
			
			// 获得IP数据包头部的位置  
			ih = (ip_header *)(pkt_data + 14);    //14为以太网帧头部长度  
												  //获得tcp头部的位置  
			ip_len = (ih->ver_ihl & 0xf) * 4;
			
			th = (tcp_header *)((u_char *)ih + ip_len);

			/* 将网络字节序列转换成主机字节序列 */
			sport = ntohs(th->sport);
			dport = ntohs(th->dport);
			if (sport == 80 || dport == 80){
				printf("%.6ld len:%d ", header->ts.tv_usec, header->len);
				printf("ip_length:%d ", ip_len);
				printf("from: %d.%d.%d.%d:%d to: %d.%d.%d.%d:%d\n",
					ih->saddr.byte1,
					ih->saddr.byte2,
					ih->saddr.byte3,
					ih->saddr.byte4,
					sport,
					ih->daddr.byte1,
					ih->daddr.byte2,
					ih->daddr.byte3,
					ih->daddr.byte4,
					dport);
				/* 打印IP地址和TCP端口 */
			}
			
			
		}

	}
	//释放网络适配器列表  
	pcap_freealldevs(alldevs);

	/**
	int pcap_loop  ( pcap_t *  p,
	int  cnt,
	pcap_handler  callback,
	u_char *  user
	);
	typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *,
	const u_char *);
	*/
	//开始捕获信息,当捕获到数据包时,会自动调用这个函数  
	//pcap_loop(adhandle,0,packet_handler,NULL);  

	int inum;
	scanf_s("%d", &inum);

	return 0;

}

/* 每次捕获到数据包时，libpcap都会自动调用这个回调函数 */
/**
pcap_loop()函数是基于回调的原理来进行数据捕获的，如技术文档所说，这是一种精妙的方法，并且在某些场合下，
它是一种很好的选择。但是在处理回调有时候会并不实用，它会增加程序的复杂度，特别是在多线程的C++程序中
*/
/*
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
struct tm *ltime = NULL;
char timestr[16];
time_t local_tv_sec;

// 将时间戳转换成可识别的格式
local_tv_sec = header->ts.tv_sec;
localtime_s(ltime,&local_tv_sec);
strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

printf("%s,%.6ld len:%d\n", timestr, header->ts.tv_usec, header->len);

}
*/
/* 将数字类型的IP地址转换成字符串类型的 */
#define IPTOSBUFFERS    12  
char *iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;

	p =(u_char *) &in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf_s(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}
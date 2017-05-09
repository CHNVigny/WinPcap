#include <stdio.h>  
#include <stdlib.h>  
#include <pcap.h>  


char *iptos(u_long in);       //u_long��Ϊ unsigned long  
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
//struct tm *ltime;                 //��ʱ�䴦���йصı���  

/* 4�ֽڵ�IP��ַ */
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
} ip_address;

/* IPv4 �ײ� */
typedef struct ip_header
{
	u_char  ver_ihl;        // �汾 (4 bits) + �ײ����� (4 bits)  
	u_char  tos;            // ��������(Type of service)  
	u_short tlen;           // �ܳ�(Total length)  
	u_short identification; // ��ʶ(Identification)  
	u_short flags_fo;       // ��־λ(Flags) (3 bits) + ��ƫ����(Fragment offset) (13 bits)  
	u_char  ttl;            // ���ʱ��(Time to live)  
	u_char  proto;          // Э��(Protocol)  
	u_short crc;            // �ײ�У���(Header checksum)  
	ip_address  saddr;      // Դ��ַ(Source address)  
	ip_address  daddr;      // Ŀ�ĵ�ַ(Destination address)  
	u_int   op_pad;         // ѡ�������(Option + Padding)  
} ip_header;

/* UDP �ײ�*/
typedef struct udp_header
{
	u_short sport;          // Դ�˿�(Source port)  
	u_short dport;          // Ŀ�Ķ˿�(Destination port)  
	u_short len;            // UDP���ݰ�����(Datagram length)  
	u_short crc;            // У���(Checksum)  
} udp_header;

typedef struct tcp_header //����TCP�ײ� 
{
	u_short sport; //16λԴ�˿� 
	u_short dport; //16λĿ�Ķ˿� 
	u_int th_seq; //32λ���к� 
	u_int th_ack; //32λȷ�Ϻ� 
	u_char th_lenres;//4λ�ײ�����/6λ������ 
	u_char th_flag; //6λ��־λ
	u_short th_win; //16λ���ڴ�С
	u_short th_sum; //16λУ���
	u_short th_urp; //16λ��������ƫ����
}tcp_header;;



int main() {

	pcap_if_t  * alldevs;       //��������������  
	pcap_if_t  *d;                  //ѡ�е�����������  
	char errbuf[PCAP_ERRBUF_SIZE];   //���󻺳���,��СΪ256  
	char source[PCAP_ERRBUF_SIZE];
	pcap_t *adhandle;           //��׽ʵ��,��pcap_open���صĶ���  
	int i = 0;                            //��������������  
	struct pcap_pkthdr *header;    //���յ������ݰ���ͷ��  
	const u_char *pkt_data;           //���յ������ݰ�������  
	int res;                                    //��ʾ�Ƿ���յ������ݰ�  
	u_int netmask;                       //����ʱ�õ���������  
	char packet_filter[] = "ip and tcp";        //�����ַ�  
	struct bpf_program fcode;                     //pcap_compile�����õĽṹ��  
	ip_header *ih;                                    //ipͷ��  
	udp_header *uh;                             //udpͷ�� 
	tcp_header *th;								//tcpͷ��
	u_int ip_len;                                       //ip��ַ��Ч����  
	u_short sport, dport;                        //�����ֽ�����  
												 //time_t local_tv_sec;              //��ʱ�䴦���йصı���  
												 //char timestr[16];                 //��ʱ�䴦���йصı���  
												 /**
												 int pcap_findalldevs_ex  ( char *  source,
												 struct pcap_rmtauth *  auth,
												 pcap_if_t **  alldevs,
												 char *  errbuf  );
												 PCAP_SRC_IF_STRING�����û����һ�������ļ���ʼ��������;
												 */
												 //��ȡ�����������б�  
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		//���Ϊ-1������ֻ�ȡ�������б�ʧ��  
		fprintf(stderr, "Error in pcap_findalldevs_ex:\n", errbuf);
		//exit(0)���������˳�,exit(other)Ϊ�������˳�,���ֵ�ᴫ������ϵͳ  
		exit(1);
	}
	//��ӡ�豸�б���Ϣ  
	/**
	d = alldevs ����ֵ��һ���豸,d = d->next�����л�����һ���豸
	�ṹ�� pcap_if_t:
	pcap_if *  next                 ָ����һ��pcap_if,pcap_if_t��pcap_if �ṹ��һ����
	char *  name                        ����������������
	char *  description         ��������������
	pcap_addr *  addresses  �������洢�ĵ�ַ
	u_int  flags                            �������ӿڱ�ʶ��,ֵΪPCAP_IF_LOOPBACK
	*/
	for (d = alldevs; d != NULL; d = d->next) {
		printf("-----------------------------------------------------------------\nnumber:%d\nname:%s\n", ++i, d->name);
		if (d->description) {
			//��ӡ��������������Ϣ  
			printf("description:%s\n", d->description);
		}
		else {
			//������������������Ϣ  
			printf("description:%s", "no description\n");
		}
		//��ӡ���ػ��ص�ַ  
		printf("\tLoopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");
		/**
		pcap_addr *  next     ָ����һ����ַ��ָ��
		sockaddr *  addr       IP��ַ
		sockaddr *  netmask  ��������
		sockaddr *  broadaddr   �㲥��ַ
		sockaddr *  dstaddr        Ŀ�ĵ�ַ
		*/
		pcap_addr_t *a;       //�����������ĵ�ַ�����洢����  
		for (a = d->addresses; a; a = a->next) {
			//sa_family�����˵�ַ������,��IPV4��ַ���ͻ���IPV6��ַ����  
			switch (a->addr->sa_family)
			{
			case AF_INET:  //����IPV4���͵�ַ  
				printf("Address Family Name:AF_INET\n");
				if (a->addr) {
					//->�����ȼ���ͬ������,����ǿ������ת��,��ΪaddrΪsockaddr���ͣ�������в�����ת��Ϊsockaddr_in����  
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
			case AF_INET6: //����IPV6���͵�ַ  
				printf("Address Family Name:AF_INET6\n");
				printf("this is an IPV6 address\n");
				break;
			*/
			default:
				break;
			}
		}
	}
	//iΪ0��������ѭ��δ����,��û���ҵ�������,���ܵ�ԭ��ΪWinpcapû�а�װ����δɨ�赽  
	if (i == 0) {
		printf("interface not found,please check winpcap installation");
	}

	int num;
	printf("Enter the interface number(1-%d):", i);
	//���û�ѡ��ѡ���ĸ�����������ץ��  
	scanf_s("%d", &num);
	printf("\n");

	//�û���������ֳ�������Χ  
	if (num<1 || num>i) {
		printf("number out of range\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	//��ת��ѡ�е�������  
	for (d = alldevs, i = 0; i< num - 1; d = d->next, i++);

	//���е��˴�˵���û��������ǺϷ���  
	if ((adhandle = pcap_open(d->name,        //�豸����  
		65535,       //������ݰ������ݳ���  
		PCAP_OPENFLAG_PROMISCUOUS,  //����ģʽ  
		1000,           //��ʱʱ��  
		NULL,          //Զ����֤  
		errbuf         //���󻺳�  
	)) == NULL) {
		//��������ʧ��,��ӡ�����ͷ��������б�  
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		// �ͷ��豸�б�   
		pcap_freealldevs(alldevs);
		return -1;
	}
	//��ӡ���,���ڼ�����  
	printf("\nlistening on %s...\n", d->description);

	//��������Ϊ���߾�����  
	if (pcap_datalink(adhandle) == DLT_IEEE802) {
		printf("DLT_IEEE802\n");
	}
	//��������Ϊ��̫��,Ethernet (10Mb, 100Mb, 1000Mb, and up)  
	if (pcap_datalink(adhandle) == DLT_EN10MB) {
		printf("DLT_EN10MB\n");
	}

	//�������粻����̫��,�˴�ֻȡ�������  
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		//�ͷ��б�  
		pcap_freealldevs(alldevs);
		return -1;
	}

	//�Ȼ�õ�ַ����������  
	if (d->addresses != NULL)
		/* ��ýӿڵ�һ����ַ������ */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* ����ӿ�û�е�ַ����ô���Ǽ���һ��C������� */
		netmask = 0xffffff;

	//pcap_compile()��ԭ���ǽ��߲�Ĳ������˱�  
	//��ʽ������ܹ����������������͵ĵͲ���ֽ���  
	if (pcap_compile(adhandle,   //�������������  
		&fcode,
		packet_filter,   //����ip��tcp  
		1,                       //�Ż���־  
		netmask           //��������  
	)<0)
	{
		//���˳�������  
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		// �ͷ��豸�б�  
		pcap_freealldevs(alldevs);
		return -1;
	}

	//���ù�����  
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}


	//����pcap_next_ex���������ݰ�  
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
	{
		if (res == 0) {
			//����ֵΪ0����������ݰ���ʱ������ѭ����������  
			continue;
		}
		else {
			//���е��˴�������ܵ����������ݰ�  
			// ��ʱ���ת���ɿ�ʶ��ĸ�ʽ  
			//local_tv_sec = header->ts.tv_sec;  
			//localtime_s(ltime,&local_tv_sec);  
			//strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);  
			//headerΪ֡��ͷ��  
			
			// ���IP���ݰ�ͷ����λ��  
			ih = (ip_header *)(pkt_data + 14);    //14Ϊ��̫��֡ͷ������  
												  //���tcpͷ����λ��  
			ip_len = (ih->ver_ihl & 0xf) * 4;
			
			th = (tcp_header *)((u_char *)ih + ip_len);

			/* �������ֽ�����ת���������ֽ����� */
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
				/* ��ӡIP��ַ��TCP�˿� */
			}
			
			
		}

	}
	//�ͷ������������б�  
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
	//��ʼ������Ϣ,���������ݰ�ʱ,���Զ������������  
	//pcap_loop(adhandle,0,packet_handler,NULL);  

	int inum;
	scanf_s("%d", &inum);

	return 0;

}

/* ÿ�β������ݰ�ʱ��libpcap�����Զ���������ص����� */
/**
pcap_loop()�����ǻ��ڻص���ԭ�����������ݲ���ģ��缼���ĵ���˵������һ�־���ķ�����������ĳЩ�����£�
����һ�ֺܺõ�ѡ�񡣵����ڴ���ص���ʱ��Ტ��ʵ�ã��������ӳ���ĸ��Ӷȣ��ر����ڶ��̵߳�C++������
*/
/*
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
struct tm *ltime = NULL;
char timestr[16];
time_t local_tv_sec;

// ��ʱ���ת���ɿ�ʶ��ĸ�ʽ
local_tv_sec = header->ts.tv_sec;
localtime_s(ltime,&local_tv_sec);
strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

printf("%s,%.6ld len:%d\n", timestr, header->ts.tv_usec, header->len);

}
*/
/* ���������͵�IP��ַת�����ַ������͵� */
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
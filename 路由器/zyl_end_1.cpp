#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "pcap.h"
#pragma comment(lib,"ws2_32.lib")
#include <stdio.h>
#include <iostream>

using namespace std;

// 宏定义
#define PACAP_ERRBUF_SIZE 10
#define MAX_IP_NUM 10

// 帧首部
typedef struct FrameHeader_t 
{
	// 目的地址
	BYTE DesMAC[6];
	// 源地址
	BYTE SrcMAC[6];
	// 帧类型
	WORD FrameType;
}FrameHeader_t;

// ARP报文
typedef struct ARPFrame_t 
{
	// 帧首部
	FrameHeader_t FrameHeader;
	// 硬件类型
	WORD HardwareType;
	// 协议类型
	WORD ProtocolType;
	// 硬件地址长度
	BYTE HLen;
	// 协议地址
	BYTE PLen;
	// 操作
	WORD Operation;
	// 发送方MAC
	BYTE SendHa[6];
	// 发送方IP
	DWORD SendIP;
	// 接收方MAC
	BYTE RecvHa[6];
	// 接收方IP
	DWORD RecvIP;
}ARPFrame_t;

// IP报文首部
typedef struct IPHeader_t 
{
	BYTE Ver_HLen;
	BYTE TOS;
	WORD TotalLen;
	WORD ID;
	WORD Flag_Segment;
	// (time to live)
	BYTE TTL;
	// 协议
	BYTE Protocol;
	// 校验和
	WORD Checksum;
	// 源IP
	ULONG SrcIP;
	// 目的IP
	ULONG DstIP;
}IPHeader_t;

// 数据报
typedef struct Data_t {
	// 帧首部
	FrameHeader_t FrameHeader;
	// IP首部
	IPHeader_t IPHeader;
}Data_t;

// ICMP差错报文
typedef struct ICMP {
	// 帧首部
	FrameHeader_t FrameHeader;
	// IP首部
	IPHeader_t IPHeader;
	char buf[0x80];
}ICMP_t;

#pragma pack()
#pragma pack(1)

// 表项（路由器）
class routeitem
{
public:
	// 掩码
	DWORD mask;
	// 目的网络
	DWORD net;
	// 下一跳
	DWORD nextip;
	// 下一跳的MAC地址
	BYTE nextMAC[6];
	// 序号
	int index;
	// 0为直接相连 1为用户添加（直接相连 不可删除）
	int type;
	routeitem* nextitem;
	routeitem()
	{
		// 将其全部设置为零
		memset(this, 0, sizeof(*this));
	}
	// 打印掩码、目的网络、下一跳IP、类型
	void printitem();
};

#pragma pack()
#pragma pack(1)

// 路由表
class routetable
{
public:
	// 最多可以又50个条目
	routeitem* head, * tail;
	// 目前存在的个数
	int num;
	routetable();
	// 添加 （直接投递在最前 接着最长匹配 长的在前）
	void add(routeitem* a);
	//删除 type=0（直接相连）不能删除
	void remove(int index);
	//路由表的打印`mask net next_ip type`
	void print();
	//查找 （最长前缀 返回下一跳的`ip`地址）
	DWORD lookup(DWORD ip);

};

#pragma pack()//恢复4bytes对齐



class arpitem
{
public:
	DWORD ip;
	BYTE mac[6];
};
class ipitem
{
public:
	DWORD sip, dip;
	BYTE smac[6], dmac[6];
};

// arp表 存储已经得到的arp关系
class arptable
{
public:
	// IP地址
	DWORD ip;
	// MAC地址
	BYTE mac[6];
	// 表项数量
	static int num;
	// 插入表项
	static void insert(DWORD ip, BYTE mac[6]);
	// 删除表项
	static int lookup(DWORD ip, BYTE mac[6]);
}atable[50];



//日志类
class log
{
public:
	// 索引
	int index;

	// arp和ip
	char type[5];

	// 具体内容
	ipitem ip; 
	arpitem arp;

	log();
	~log();

	static int num;
	// 日志
	static log diary[50];
	static FILE* fp;
	// `arp`类型写入日志
	static void write2log_arp(ARPFrame_t*); 
	// `ip`类型写入日志
	static void write2log_ip(const char* a, Data_t*); 

	static void print();
};



// 一些重要变量的预声明
pcap_if_t* alldevs;
pcap_if_t* d;
// 打开的网卡
pcap_t* ahandle;
// 网卡对应的地址
pcap_addr* a;
char errbuf[PCAP_ERRBUF_SIZE];
char* pcap_src_if_string;
pcap_if_t* net[10];
char ip[10][20];
char mask[10][20];
BYTE selfmac[6];
char name[100];
BYTE broadcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
// 比较两个数组是否相同
int compare(BYTE a[], BYTE b[]);
// 获取本机的设备列表，将两个ip存入ip数组中,获取IP、mask，计算所在网段
void find_alldevs();	
// 根据ip和掩码计算所在网络
DWORD getnet(DWORD ip, DWORD mask);
// 打开网络接口
pcap_t* open(char* name);
// 获取自己的MAC
void getselfmac(DWORD ip);
// 获取目的ip对应的mac
void getothermac(DWORD ip_, BYTE mac[]);
// 显示基本信息 本机ip，mac
void printbasicinfo();
// 数据报转发 修改源mac和目的mac
void resend(ICMP_t, BYTE dmac[]);
// 打印mac
void getmac(BYTE MAC[]);
// 线程函数
DWORD WINAPI handlerRequest(LPVOID lparam);
// 检验校验和
bool checkchecksum(Data_t*);
// 设置校验和
void setchecksum(Data_t*);





log ltable;

//多线程
HANDLE hThread;
DWORD dwThreadId;

int index;

int main()
{
	scanf("%d", &index);

	// const char* 到char*的转换 解决vs中的报错问题
	pcap_src_if_string = new char[strlen(PCAP_SRC_IF_STRING)];
	strcpy(pcap_src_if_string, PCAP_SRC_IF_STRING);

	// 获取本机ip
	find_alldevs();

	//输出此时存储的IP地址与MAC地址
	for (int i = 0; i < 2; i++)
	{
		printf("%s\t", ip[i]);
		printf("%s\n", mask[i]);
	}

	getselfmac(inet_addr(ip[0]));
	getmac(selfmac);
	BYTE mac[6];
	int op;
	routetable zyl_table;
	hThread = CreateThread(NULL, NULL, handlerRequest, LPVOID(&zyl_table), 0, &dwThreadId);
	routeitem a;

	while (true)
	{
		// 进行简介
    	cout << "====================================================================================" << endl;
    	cout << "粥小霖的路由器，你可以输入以下数字进行相应操作：" << endl;
    	cout << "1. 添加路由表项" << endl;
    	cout << "2. 删除路由表项" << endl;
    	cout << "3. 打印路由表：" << endl;
		cout << "4. 退出程序" << endl;
    	cout << "====================================================================================" << endl;

		// 输入想要进行的操作
		scanf("%d", &op);
		if (op == 1)
		{
			routeitem a;
			char t[30];

			cout << "请输入网络掩码：" << endl;
			scanf("%s", &t);
			a.mask = inet_addr(t);

			cout << "请输入目的网络`ip`地址：" << endl;
			scanf("%s", &t);
			a.net = inet_addr(t);

			cout << "请输入下一跳`ip`地址：" << endl;
			scanf("%s", &t);
			a.nextip = inet_addr(t);

			// 手动添加的类型
			a.type = 1;
			zyl_table.add(&a);
		}
		else if (op == 2)
		{
			cout << "请输入你想要删除的表项编号：" << endl;
			int index;
			scanf("%d", &index);
			zyl_table.remove(index);
		}
		else if (op == 3)
		{
			zyl_table.print();
		}
		else if (op == 4)
		{
			break;
		}
		else {
			cout << "请输入正确的操作号！" << endl;
		}
	}
	return 0;
}



// 获取网卡上的IP
void find_alldevs()	
{
	if (pcap_findalldevs_ex(pcap_src_if_string, NULL, &alldevs, errbuf) == -1)
	{
		printf("%s", "error");
	}
	else
	{
		int i = 0;
		d = alldevs;
		for (; d != NULL; d = d->next)//获取该网络接口设备的ip地址信息
		{
			// 不应该先看信息，再去选择打印出来的接口嘛？
			if (i == index)
			{
				net[i] = d;
				int t = 0;
				for (a = d->addresses; a != nullptr; a = a->next)
				{
					// 如果是IPV4地址
					if (((struct sockaddr_in*)a->addr)->sin_family == AF_INET && a->addr)
					{
						printf("%d ", i);
						printf("%s\t", d->name, d->description);
						printf("%s\t%s\n", "IP地址为：", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));

						// 存储对应IP地址与MAC地址
						strcpy(ip[t], inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
						strcpy(mask[t], inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));

						t += 1;
					}
				}

				// 打开该网卡
				ahandle = open(d->name);
			}
			i++;
		}
	}
	pcap_freealldevs(alldevs);
}

// 打开网络接口
pcap_t* open(char* name)
{
	pcap_t* temp = pcap_open(name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 100, NULL, errbuf);
	if (temp == NULL)
		printf("打开接口失败");
	return temp;
}

// 对比两个地址是否相同 相同返回1 不同返回0
int compare(BYTE a[6], BYTE b[6])
{
	int index = 1;
	for (int i = 0; i < 6; i++)
	{
		if (a[i] != b[i])
			index = 0;
	}
	return index;
}

// 获得本机的`IP`和`MAC`地址
void getselfmac(DWORD ip)
{
	memset(selfmac, 0, sizeof(selfmac));
	ARPFrame_t ARPFrame;

	// 设置目的地址为广播地址
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	}
	// 设置虚拟MAC地址
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.SrcMAC[i] = 0x66;
	}
	// 帧类型为ARP
	ARPFrame.FrameHeader.FrameType = htons(0x0806);
	// 硬件类型为以太网
	ARPFrame.HardwareType = htons(0x0001);
	// 协议类型为IP
	ARPFrame.ProtocolType = htons(0x0800);
	// 硬件地址长度为6
	ARPFrame.HLen = 6;
	// 协议地址长为4
	ARPFrame.PLen = 4;
	// 操作为ARP请求
	ARPFrame.Operation = htons(0x0001);
	// 设置虚拟MAC地址
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.SendHa[i] = 0x66;
	}
	// 设置虚拟IP地址
	ARPFrame.SendIP = inet_addr("112.112.112.112");
	// 设置未知的MAC地址
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.RecvHa[i] = 0x00;
	}
	ARPFrame.RecvIP = ip;

	u_char* h = (u_char*)&ARPFrame;
	int len = sizeof(ARPFrame_t);


	if (ahandle == nullptr) 
	{
		cout << "网卡接口打开错误" << endl;
	}
	else
	{
		if (pcap_sendpacket(ahandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
		{
			cout << "发送失败" << endl;
		}
		else
		{
			while (true)
			{
				cout << "本地发送成功" << endl;
				pcap_pkthdr* pkt_header;
				const u_char* pkt_data;
				int rtn = pcap_next_ex(ahandle, &pkt_header, &pkt_data);
				if (rtn == 1)
				{
					ARPFrame_t* IPPacket = (ARPFrame_t*)pkt_data;
					if (ntohs(IPPacket->FrameHeader.FrameType) == 0x0806)
					{
						// 输出目的MAC地址
						if (!compare(IPPacket->FrameHeader.SrcMAC, ARPFrame.FrameHeader.SrcMAC) && compare(IPPacket->FrameHeader.DesMAC, ARPFrame.FrameHeader.SrcMAC))
						{
							// 把获得的关系写入到日志表中
							ltable.write2log_arp(IPPacket);

							// 输出源MAC地址，源MAC地址即为所需MAC地址
							for (int i = 0; i < 6; i++)
							{
								selfmac[i] = IPPacket->FrameHeader.SrcMAC[i];
							}
							break;
						}
					}
				}
			}
		}
	}
}

// 获取目的`IP`和`MAC`地址
void getothermac(DWORD ip_, BYTE mac[])
{
	memset(mac, 0, sizeof(mac));
	ARPFrame_t ARPFrame;

	// 将APRFrame.FrameHeader.DesMAC设置为广播地址
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	}
		
	// 将APRFrame.FrameHeader.SrcMAC设置为本机网卡的MAC地址
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.SrcMAC[i] = selfmac[i];
		ARPFrame.SendHa[i] = selfmac[i];
	}

	// 帧类型为ARP
	ARPFrame.FrameHeader.FrameType = htons(0x0806);
	// 硬件类型为以太网
	ARPFrame.HardwareType = htons(0x0001);
	// 协议类型为IP
	ARPFrame.ProtocolType = htons(0x0800);
	// 硬件地址长度为6
	ARPFrame.HLen = 6;
	// 协议地址长为4
	ARPFrame.PLen = 4;
	// 操作为ARP请求
	ARPFrame.Operation = htons(0x0001);

	// 将ARPFrame.SendIP设置为本机网卡上绑定的IP地址
	ARPFrame.SendIP = inet_addr(ip[0]);

	// 将ARPFrame.RecvHa设置为0
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.RecvHa[i] = 0;
	}
		
	// 将ARPFrame.RecvIP设置为请求的IP地址
	ARPFrame.RecvIP = ip_;

	u_char* h = (u_char*)&ARPFrame;
	int len = sizeof(ARPFrame_t);

	if (ahandle == nullptr)
	{
		cout << "网卡接口打开失败" << endl;
	}
	else
	{
		if (pcap_sendpacket(ahandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
		{
			cout << "发送失败" << endl;
		}
		else
		{
			while (true)
			{
				cout << "外部发送成功" << endl;
				pcap_pkthdr* pkt_header;
				const u_char* pkt_data;
				int rtn = pcap_next_ex(ahandle, &pkt_header, &pkt_data);
				if (rtn == 1)
				{
					ARPFrame_t* IPPacket = (ARPFrame_t*)pkt_data;
					if (ntohs(IPPacket->FrameHeader.FrameType) == 0x806)
					{
						// 输出目的MAC地址
						if (!compare(IPPacket->FrameHeader.SrcMAC, ARPFrame.FrameHeader.SrcMAC) && compare(IPPacket->FrameHeader.DesMAC, ARPFrame.FrameHeader.SrcMAC) && IPPacket->SendIP == ip_)//&&ip==IPPacket->SendIP
						{
							// 把获得的关系写入到日志表中
							ltable.write2log_arp(IPPacket);
							// 输出源MAC地址
							for (int i = 0; i < 6; i++)
							{
								mac[i] = IPPacket->FrameHeader.SrcMAC[i];
							}
							break;
						}
					}
				}
			}
		}
	}
}

// 打印MAC地址
void getmac(BYTE MAC[])
{
	cout << "MAC地址为：" << endl;
	for (int i = 0; i < 5; i++)
	{
		printf("%02X-", MAC[i]);
	}
	printf("%02X\n", MAC[5]);
}

// 路由表采用链表形式 并初始化直接跳转的网络
routetable::routetable()
{
	head = new routeitem;
	tail = new routeitem;
	head->nextitem = tail;
	num = 0;

	// 本次实验初始一定只有两个网络
	for (int i = 0; i < 2; i++)
	{
		routeitem* temp = new routeitem;

		// 本机网卡的ip和掩码进行按位与 所得为网络号
		temp->net = (inet_addr(ip[i])) & (inet_addr(mask[i]));
		temp->mask = inet_addr(mask[i]);
		temp->type = 0;

		// 将其初始化到链表中
		this->add(temp);
	}
}

// 插入表项
void routetable::add(routeitem* a)
{
	// 直接投递的表项
	if (!a->type)
	{
		a->nextitem = head->nextitem;
		head->nextitem = a;
		a->type = 0;
	}
	
	// 方便找到插入的位置
	routeitem* pointer;

	// 不是直接投递的表相：按照掩码由长至短找到合适的位置
	else
	{
		for (pointer = head->nextitem; pointer != tail && pointer->nextitem != tail; pointer = pointer->nextitem)//head有内容，tail没有
		{
			if (a->mask < pointer->mask && a->mask >= pointer->nextitem->mask || pointer->nextitem == tail)
			{
				break;
			}	
		}
		a->nextitem = pointer->nextitem;

		// 插入到合适位置
		pointer->nextitem = a;
	}

	routeitem* p = head->nextitem;
	for (int i = 0; p != tail; p = p->nextitem, i++)
	{
		p->index = i;
	}
	num++;
}

// 打印表项
void routeitem::printitem()
{
	// 打印的内容为：`掩码 目的网络 下一跳IP 类型`
	in_addr addr;

	// 多打印一个索引
	printf("%d   ", index);

	addr.s_addr = mask;
	char* pchar = inet_ntoa(addr);
	printf("%s\t", pchar);

	addr.s_addr = net;
	pchar = inet_ntoa(addr);
	printf("%s\t", pchar);

	addr.s_addr = nextip;
	pchar = inet_ntoa(addr);
	printf("%s\t\t", pchar);

	printf("%d\n", type);
}

// 打印路由表
void routetable::print()
{
	routeitem* p = head->nextitem;
	for (; p != tail; p = p->nextitem)
	{
		p->printitem();
	}
}

// 删除表项
void routetable::remove(int index)
{
	for (routeitem* t = head; t->nextitem != tail; t = t->nextitem)
	{
		if (t->nextitem->index == index)
		{
			// 直接投递的路由表项不可删除
			if (t->nextitem->type == 0)
			{
				cout << "该项无法删除" << endl;
				return;
			}
			else
			{
				t->nextitem = t->nextitem->nextitem;
				return;
			}
		}
	}
	cout << "查无此项！" << endl;
}

// 查找表项 并返回下一跳`ip`地址
DWORD routetable::lookup(DWORD ip)
{
	routeitem* t = head->nextitem;
	for (; t != tail; t = t->nextitem)
	{
		if ((t->mask & ip) == t->net)
		{
			return t->nextip;
		}
	}
	cout << "未找到对应跳转地址，退出程序" << endl;
	return -1;
}

// 数据报转发 修改源mac和目的mac
void resend(ICMP_t data, BYTE dmac[])
{
	Data_t* temp = (Data_t*)&data;
	
	// 源MAC为本机MAC
	memcpy(temp->FrameHeader.SrcMAC, temp->FrameHeader.DesMAC, 6);

	// 目的MAC为下一跳MAC
	memcpy(temp->FrameHeader.DesMAC, dmac, 6);

	// 生存周期减1
	temp->IPHeader.TTL -= 1;

	if (temp->IPHeader.TTL < 0)
	{
		// 丢弃
		return;
	}
	
	//重新设置校验和
	setchecksum(temp);

	// 发送数据报
	int rtn = pcap_sendpacket(ahandle, (const u_char*)temp, 74);
	if (rtn == 0)
	{
		// 将其写入日志
		ltable.write2log_ip("转发", temp);
	}
		
}



// 初始化日志的参数
int log::num = 0;
log log::diary[50] = {};
FILE* log::fp = nullptr;
log::log()
{
	// `追加 / 更新`方式打开文件 就是可以随意更新文件 将写入的数据追加到文件的末尾
	fp = fopen("log.txt", "a+");
}
log::~log()
{
	fclose(fp);
}

// 日志打印
void log::print()
{
	int i;

	if (num > 50)
	{
		i = (num + 1) % 50;
	}
	else 
	{
		i = 0;
	}

	for (; i < num % 50; i++)
	{
		printf("%d ", diary[i].index);
		printf("%s\t ", diary[i].type);
		
		// 为ARP类型
		if (!strcmp(diary[i].type, "ARP"))
		{
			in_addr addr;

			// 打印对应的`IP`地址
			addr.s_addr = diary[i].arp.ip;
			char* pchar = inet_ntoa(addr);
			printf("%s\t", pchar);

			// 打印对应的`MAC`地址
			for (int i = 0; i < 5; i++)
			{
				printf("%02X.", diary[i].arp.mac[i]);
			}
			printf("%02X\n", diary[i].arp.mac[5]);
		} // 为IP类型
		else if (!strcmp(diary[i].type, "IP"))
		{
			in_addr addr;

			// 打印对应的源`IP`地址
			addr.s_addr = diary[i].ip.sip;
			char* pchar = inet_ntoa(addr);
			printf("源IP：%s\t", pchar);

			// 打印对应的目的IP`地址
			addr.s_addr = diary[i].ip.dip;
			pchar = inet_ntoa(addr);
			printf("目的IP：%s\t", pchar);

			// 打印对应的源`MAC`地址
			printf("源MAC: ");
			for (int i = 0; i < 5; i++)
			{
				printf("%02X.", diary[i].ip.smac[i]);
			}
			printf("%02X\t", diary[i].ip.smac[5]);

			// 打印对应的目的`MAC`地址
			printf("目的MAC: ");
			for (int i = 0; i < 5; i++)
			{
				printf("%02X.", diary[i].ip.dmac[i]);
			}
			printf("%02X\n", diary[i].ip.dmac[5]);
		}
	}
}

// `ip`类型写入日志
void log::write2log_ip(const char* a, Data_t* pkt)
{
	fprintf(fp, "`IP`");
	fprintf(fp, a);
	fprintf(fp, ": ");

	in_addr addr;
	addr.s_addr = pkt->IPHeader.SrcIP;
	char* pchar = inet_ntoa(addr);

	fprintf(fp, "源IP： ");
	fprintf(fp, "%s  ", pchar);
	fprintf(fp, "目的IP： ");
	addr.s_addr = pkt->IPHeader.DstIP;
	fprintf(fp, "%s  ", pchar);
	fprintf(fp, "源MAC： ");
	for (int i = 0; i < 5; i++)
	{
		fprintf(fp, "%02X-", pkt->FrameHeader.SrcMAC[i]);
	}
	fprintf(fp, "%02X  ", pkt->FrameHeader.SrcMAC[5]);
	fprintf(fp, "目的MAC： ");
	for (int i = 0; i < 5; i++)
	{
		fprintf(fp, "%02X-", pkt->FrameHeader.DesMAC[i]);
	}
	fprintf(fp, "%02X\n", pkt->FrameHeader.DesMAC[5]);
}

// `arp`类型写入日志
void log::write2log_arp(ARPFrame_t* pkt)
{
	fprintf(fp, "ARP:");

	in_addr addr;
	addr.s_addr = pkt->SendIP;
	char* pchar = inet_ntoa(addr);
	fprintf(fp, "IP： ");
	fprintf(fp, "%s  ", pchar);

	fprintf(fp, "MAC： ");
	for (int i = 0; i < 5; i++)
	{
		fprintf(fp, "%02X-", pkt->SendHa[i]);
	}
	fprintf(fp, "%02X\n", pkt->SendHa[5]);

}

// 接收和处理线程函数
DWORD WINAPI handlerRequest(LPVOID lparam)
{
	routetable zyl_table = *(routetable*)(LPVOID)lparam;
	while (true)
	{
		pcap_pkthdr* pkt_header; 
		const u_char* pkt_data;
		while (true)
		{
			int rtn = pcap_next_ex(ahandle, &pkt_header, &pkt_data);
			// 接收到消息就跳出循环
			if (rtn)
			{
				break;
			}
		}
		FrameHeader_t* header = (FrameHeader_t*)pkt_data;
		// 目的`MAC`地址是本机
		if (compare(header->DesMAC, selfmac))
		{
			// IP格式的数据报
			if (ntohs(header->FrameType) == 0x0800)
			{
				Data_t* data = (Data_t*)pkt_data;
				// 写入日志
				ltable.write2log_ip("接收", data);

				DWORD ip1_ = data->IPHeader.DstIP;
				// 查找是否有对应表项
				DWORD ip_ = zyl_table.lookup(ip1_);

				// 如果没有则丢弃或递交至上层
				if (ip_ == -1)
				{
					continue;
				}

				// 如果校验和不正确，则直接丢弃不进行处理
				if (checkchecksum(data))
				{
					// 不是直接投递的表项
					if (data->IPHeader.DstIP != inet_addr(ip[0]) && data->IPHeader.DstIP != inet_addr(ip[1]))
					{
						int t1 = compare(data->FrameHeader.DesMAC, broadcast);
						int t2 = compare(data->FrameHeader.SrcMAC, broadcast);
						// 不是广播消息
						if (!t1 && !t2)
						{
							// ICMP报文包含IP数据包报头和其它内容
							ICMP_t* temp_ = (ICMP_t*)pkt_data;
							ICMP_t temp = *temp_;
							
							BYTE mac[6];

							// routetable的查询结果怎么会是零呢？
							if (ip_ == 0)
							{
								// 如果ARP表中没有所需内容，则需要获取ARP
								if (!arptable::lookup(ip1_, mac))
								{
									arptable::insert(ip1_, mac);
								}
								// 转发数据报
								resend(temp, mac);
							}
							else if (ip_ != -1) // 非直接投递，查找下一条IP的MAC
							{
								if (!arptable::lookup(ip_, mac))
								{
									arptable::insert(ip_, mac);
								}
								// 转发数据报
								resend(temp, mac);
							}
						}
					}
				}
			}
		}
	}
}

// 设置校验和
void setchecksum(Data_t* temp)
{
	temp->IPHeader.Checksum = 0;
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	temp->IPHeader.Checksum = ~sum;//取反
}

// 检验校验和
bool checkchecksum(Data_t* temp)
{
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		// 包含原有的校验和相加
		while (sum >= 0x10000)
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	if (sum == 65535)
	{
		// 全1代表正确 返回1
		return 1;
	}
	return 0;
}

// 初始话`arp`表的参数
int arptable::num = 0;
void arptable::insert(DWORD ip, BYTE mac[6])
{
	atable[num].ip = ip;
	getothermac(ip, atable[num].mac);
	memcpy(mac, atable[num].mac, 6);
	num++;
}
int arptable::lookup(DWORD ip, BYTE mac[6])
{
	memset(mac, 0, 6);
	for (int i = 0; i < num; i++)
	{
		if (ip == atable[i].ip)
		{
			memcpy(mac, atable[i].mac, 6);
			return 1;
		}
	}
	// 未知返回0
	return 0;
}
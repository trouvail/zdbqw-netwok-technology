#pragma once
#include "pcap.h"
#pragma pack(1)

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
	// 写入日志
	static void write2log_ip(Data_t*); // ip类型
	static void write2log_arp(ARPFrame_t*); // arp类型
	static void write2log_ip(const char* a, Data_t*); // ip类型

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
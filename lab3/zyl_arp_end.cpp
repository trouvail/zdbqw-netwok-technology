#include <Winsock2.h>
#include<iostream>
#include "pcap.h"
#include "stdio.h"
#include<time.h>
#include <string>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"wsock32.lib")

// 使Visio Studio的警告无效
#pragma warning(disable : 4996)

using namespace std;



// 字节对齐方式
#pragma pack(1)

// 帧首部
typedef struct FrameHeader_t {
	// 目的地址
	BYTE DesMAC[6]; 
	// 源地址
	BYTE SrcMAC[6]; 
	// 帧类型
	WORD FrameType; 
}FrameHeader_t;

// IP首部
typedef struct ARPFrame_t {
	// 用上面定义好的帧首部
	FrameHeader_t FrameHeader;
	// 硬件类型
	WORD HardwareType;
	// 协议类型（本次实验应该为ARP）
	WORD ProtocolType;
	// 硬件地址长度
	BYTE HLen;
	// 协议地址长度
	BYTE PLen;
	// 操作类型（比如ARP的请求或应答）
	WORD Operation;
	// 发送方MAC地址，即源MAC地址
	BYTE SendHa[6];
	// 发送方IP地址，即源IP地址
	DWORD SendIP;
	// 接收方MAC地址，即目的MAC地址
	BYTE RecvHa[6];
	// 接收方IP地址，即目的IP地址
	DWORD RecvIP;
}ARPFrame_t;

// 结束字节对齐方式
# pragma pack()


// 预先声明ARP初始帧，为全局使用
ARPFrame_t ARPFrame;


int main()
{
	// 指向所有设备链表首部
	pcap_if_t* alldevs;
	// 之后回用到循环设备的变量
	pcap_if_t* d;
	// 设置错误信息缓冲区的大小
	char errbuf[PCAP_ERRBUF_SIZE];	
	// 所有的接口个数
	int num = 0;
	// 用户会选择的设备序号
	int n;
	// 预存本机的IP
	char* ip = new char[20];
	// 由于字符串不能为常量，所以自己输入
	char error1[9];
    error1[0] = 'r';
    error1[1] = 'p';
    error1[2] = 'c';
    error1[3] = 'a';
    error1[4] = 'p';
    error1[5] = ':';
    error1[6] = '/';
    error1[7] = '/';
    error1[8] = '\0';

	// 获得本机的设备列表，如果错误直接返回
	if (pcap_findalldevs_ex(error1, NULL, &alldevs, errbuf) == -1)
	{
		cout << "无法获取本机设备" << endl;
		// 释放设备列表
		pcap_freealldevs(alldevs);
		return -1;
	}

	// 显示接口列表描述和对应ip地址
	for (d = alldevs; d != NULL; d = d->next)
	{
		cout << "=========================================================================================" << endl;
		// 设备数加一
		num++;
		// 获取网络接口设备名字
		cout << dec << num << ":" << d->name << endl;
		// 用d->description获取描述信息
		if (d->description != NULL)
		{
			cout << d->description << endl;
		}
		else
		{
			cout << "没有相关描述" << endl;
		}
		// 网络适配器的地址
		pcap_addr_t* a;
		for (a = d->addresses; a != NULL; a = a->next)
		{
			switch (a->addr->sa_family)
			{
			// IPV4类型地址
			case AF_INET:
				printf("Address Family Name:AF_INET\t");
				if (a->addr != NULL)
				{
					// 打印IP地址
					printf("%s\t%s\n", "IP地址:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				}
				break;
			// IPV6类型地址
			case AF_INET6:
				cout << "其地址类型为IPV6" << endl;
				break;
			default:
				break;
			}
		}
		cout << "=========================================================================================" << endl;
	}

	// 没有接口直接返回
	if (num == 0)
	{
		cout << "不可选择接口" << endl;
		return -1;
	}

	// 用户选择接口
	cout << "请选择你想打开的接口：" << "`1 ~ " << num << "`:" << endl;
	num = 0;
	cin >> n;

	// 跳转到相应接口
	for (d = alldevs; num < (n - 1); num++)
	{
		d = d->next;
	}

	// 将设备的IP地址赋值给`ip`
	strcpy(ip, inet_ntoa(((struct sockaddr_in*)(d->addresses)->addr)->sin_addr));

	pcap_t* adhandle;
	adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (adhandle == NULL)
	{
		cout << "打开接口失败" << endl;
		pcap_freealldevs(alldevs);
		return -1;
	}
	else
	{
		cout << "开始监听：" << endl;
		pcap_freealldevs(alldevs);
	}

	// 一、接下来的程序是设置ARP帧的内容，并获取本机的MAC地址与IP地址的关系

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
	// 请求方为本机的IP地址
	ARPFrame.RecvIP = inet_addr(ip);

	// 发送设置好的帧内容，如果发送失败直接退出
	if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		cout << "发送失败" << endl;
		return -1;
	}

	// 声明即将捕获的ARP帧
	ARPFrame_t* IPPacket;

	// 捕获消息，可能会收到多个数据报
	while(true)
	{
		pcap_pkthdr* pkt_header;
		const u_char* pkt_data;
		int rtn = pcap_next_ex(adhandle, &pkt_header, &pkt_data);
		// 捕获到相应的信息
		if (rtn == 1)
		{
			IPPacket = (ARPFrame_t*)pkt_data;
			if ((ntohs(IPPacket->FrameHeader.FrameType) == 0x0806) && (ntohs(IPPacket->Operation) == 0x0002))//如果帧类型为ARP并且操作为ARP应答
			{
				// 打印本机的MAC地址和IP地址
				printf("%s\t%s\n", "IP地址:", ip));
				printf("Mac地址：\n");
				printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
					IPPacket->FrameHeader.SrcMAC[0],
					IPPacket->FrameHeader.SrcMAC[1],
					IPPacket->FrameHeader.SrcMAC[2],
					IPPacket->FrameHeader.SrcMAC[3],
					IPPacket->FrameHeader.SrcMAC[4],
					IPPacket->FrameHeader.SrcMAC[5]
				);
				// 调试程序所用
				cout << 1 << endl;
				break;
			}
		}
	}

	// 二、接下来更改ARP帧的内容，获取想获得的目的IP地址和MAC地址的关系，但只能在同一个网段中

	// 目的ip
	char* des_IP = new char;

	cout << "请输入你想发送到的IP地址:" << endl;
	cin >> des_IP;

	// 发现网关回自动切换到这个网段，所以并不需要去改变原本的MAC地址以及IP地址
	// cout << des_IP; //调试输入所用
	// for (int i = 0; i < 6; i++)
	// {
	// 	 ARPFrame.FrameHeader.SrcMAC[i] = IPPacket->FrameHeader.SrcMAC[i];
	// 	 ARPFrame.SendHa[i] = IPPacket->FrameHeader.SrcMAC[i];
	// }
	// ARPFrame.SendIP = inet_addr(des_IP);

	// 接收方还是本机
	ARPFrame.RecvIP = inet_addr(des_IP);
	// 发送设置好的帧内容，如果发送失败直接退出
	if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		cout << "发送失败" << endl;
		return -1;
	}
	else
	{
		cout << "发送成功" << endl;
	}
	ARPFrame_t* IPPacketNew;

	// 捕获消息，可能会收到多个数据报，与前一次的捕获方法相同
	while(true)
	{
		pcap_pkthdr* pkt_headerNew;
		const u_char* pkt_dataNew;
		int rtnNew = pcap_next_ex(adhandle, &pkt_headerNew, &pkt_dataNew);
		if (rtnNew == 1)
		{
			IPPacketNew = (ARPFrame_t*)pkt_dataNew;
			if ((ntohs(IPPacketNew->FrameHeader.FrameType) == 0x0806) && (ntohs(IPPacketNew->Operation) == 0x0002))//如果帧类型为ARP并且操作为ARP应答
			{
				// 输出其对应的MAC地址
				printf("Mac地址：\n");
				printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
					IPPacketNew->FrameHeader.SrcMAC[0],
					IPPacketNew->FrameHeader.SrcMAC[1],
					IPPacketNew->FrameHeader.SrcMAC[2],
					IPPacketNew->FrameHeader.SrcMAC[3],
					IPPacketNew->FrameHeader.SrcMAC[4],
					IPPacketNew->FrameHeader.SrcMAC[5]
				);
				// 调试程序所用
				cout << 2 << endl;
				break;
			}
		}
	}

	// 关闭接口
	pcap_close(adhandle);
	return 0;
}
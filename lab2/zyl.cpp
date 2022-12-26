#define HAVE_REMOTE

#define WM_PACKET WM_USER + 1 //用户自定义消息

#include <pcap.h>
#include <time.h>
#include <stdio.h>
#include <iostream>

#include<iostream>
#include"pcap.h"
#include<iomanip>
#include<WS2tcpip.h>
#include<windows.h>
#include<cstdlib>
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"packet.lib")
#pragma comment(lib,"wsock32.lib")
#pragma comment(lib,"ws2_32.lib")

#pragma warning(disable : 4996)

using namespace std;

#pragma pack(1)
typedef struct FrameHeader_t //帧首部
{
    BYTE DesMAC[6]; //目的地址
    BYTE SrcMAC[6]; //源地址
    WORD FrameType; //帧类型
} FrameHeader_t;

typedef struct IPHeader_t //IP首部
{
    BYTE Ver_HLen;
    BYTE TOS;
    WORD TotalLen;
    WORD ID;
    WORD Flag_Segment;
    BYTE TTL;
    BYTE Protocal;
    WORD Checksum;
    ULONG SrcIP;
    ULONG DstIP;
} IPHeader_t;

typedef struct Data_t //包含帧首部和IP首部的数据包
{
    FrameHeader_t FrameHeader;
    IPHeader_t IPHeader;
} Data_t;

#pragma pack()


// 以下程序为根据以上代码所设计的捕获数据报的程序


/* 对packet handler函数进行声明 */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

#pragma comment(lib,"wpcap.lib")

int main(int argc, char* argv[])
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int interface_num; // 先声明之后用户选择要用到的端口号
    int i = 0;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
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

    /* 获取本机设备列表 */
    if (pcap_findalldevs_ex(error1, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* 打印列表 */
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number which you like between (1 —— %d):", i); // 输入你想要监听的接口
    scanf("%d", &interface_num);

    if (interface_num < 1 || interface_num > i)
    {
        printf("\nInterface number out of range.\n");
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* 跳转到选中的适配器 */
    for (d = alldevs, i = 0; i < interface_num - 1; d = d->next, i++);

    /* 打开设备 */
    if ((adhandle = pcap_open(d->name,          // 设备名
        65535,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
        PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
        1000,             // 读取超时时间
        NULL,             // 远程机器验证
        errbuf            // 错误缓冲池
    )) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        /* 释放设备列表 */
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nlistening on %s...\n", d->description);

    

    /* 开始捕获 */
    pcap_loop(adhandle, 0, packet_handler, NULL);

    /* 释放设备列表，因为已经捕获到了数据包 */
    pcap_freealldevs(alldevs);

    getchar();

    return 0;
}


/* 每次捕获到数据包时，libpcap都会自动调用这个回调函数 */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    struct tm* ltime;
    char timestr[16];
    time_t local_tv_sec;

    /* 将时间戳转换成可识别的格式 */
    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

    printf("%s,%.6ld len:%d\n", timestr, header->ts.tv_usec, header->len);


    // 检验校验和
    Data_t* IPPacket;
    WORD RecvChecksum;

    IPPacket = (Data_t*)pkt_data;

    RecvChecksum = IPPacket->IPHeader.Checksum;
    // 需要编码的地方，仿照校验和，写输出语句，输出源MAC地址、目的MAC地址和类型/长度字段的值的语句
    /*char src[6];
    char des[6];
    for (int j = 0; j < 6; j++)
    {
        src[j] = (char)IPPacket->FrameHeader.SrcMAC[j];
		   des[j] = (char)IPPacket->FrameHeader.DesMAC[j];
    }
    char type = (char)IPPacket->FrameHeader.FrameType;*/

    

    //char* src = (char*)IPPacket->FrameHeader.SrcMAC;
    //char* des = (char*)IPPacket->FrameHeader.DesMAC;
    //char* type = (char*)IPPacket->FrameHeader.FrameType;

    printf("------------------------------------------------------\n");
    //printf("数据报的源MAC地址为%s，数据报的目的MAC地址为%s，其类型为%s\n", src, des, type);
    //std::cout << src[0] << src[1] << src[2] << src[3] << src[4] << src[5] << std::endl;
    //std::cout << des[0] << des[1] << des[2] << des[3] << des[4] << des[5] << std::endl;
    printf("数据报的源MAC地址为：%02x:", IPPacket->FrameHeader.SrcMAC[0]);
    printf("%02x:", IPPacket->FrameHeader.SrcMAC[1]);
    printf("%02x:", IPPacket->FrameHeader.SrcMAC[2]);
    printf("%02x:", IPPacket->FrameHeader.SrcMAC[3]);
    printf("%02x:", IPPacket->FrameHeader.SrcMAC[4]);
    printf("%02x\n", IPPacket->FrameHeader.SrcMAC[5]);

    printf("数据报的目的MAC地址为：%02x:", IPPacket->FrameHeader.DesMAC[0]);
    printf("%02x:", IPPacket->FrameHeader.DesMAC[1]);
    printf("%02x:", IPPacket->FrameHeader.DesMAC[2]);
    printf("%02x:", IPPacket->FrameHeader.DesMAC[3]);
    printf("%02x:", IPPacket->FrameHeader.DesMAC[4]);
    printf("%02x\n", IPPacket->FrameHeader.DesMAC[5]);

    u_short ethernet_type;
    ethernet_type = ntohs(IPPacket->FrameHeader.FrameType);
    
    printf("其类型/长度字段的值为：%04x\n", ethernet_type);
    
   cout<<"其类型为：";
    switch (ethernet_type)
    {
    case 0x0800:
        cout << "IP";
        break;
    case 0x0806:
        cout << "ARP";
        break;
    case 0x0835:
        cout << "RARP";
        break;
    default:
        cout << "Unknown Protocol";
        break;
    }

    printf("\n");
   
    printf("------------------------------------------------------\n");


}
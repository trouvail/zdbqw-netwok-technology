#include "pcap.h"

#define WM_PACKET WM_USER + 1 //用户自定义消息

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

// protected:

//     //声明消息处理函数
//     afx_msg LRESULT OnPacket(WPARAM wParam, LPARAM lParam);

// BEGIN_MESSAGE_MAP(CCapturePacketDlg, CDialog)

//     ON_MESSAGE(WM_PACKET, OnPacket)

// END_MESSAGE_MAP()

// //消息处理函数
// LRESULT CCapturePacketDlg::OnPacket(WPARAM wParam, LPARAM lParam)
// {
//     //处理捕获到的数据包
// }

// m_Capturer = AfxBeginThread(Capturer, NULL, THREAD_PRIORITY_NORMAL); //为一个函数创建线程
// //数据包捕获工作线程
// UNIT Capturer(PVOID hWnd)
// {
//     //获取本机网络接口卡
//     pcap_if_t * alldevs;
//     pcap_if_t * d;
//     pcap_addr_t * a;
//     char errbuf[PCAP_ERRBUF_SIZE];
//     char errbuf1[PCAP_ERRBUF_SIZE];
//     //获取本机设备列表
//     if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING,
//     NULL,
//     &alldevs,
//     errbuf
//     ) == -1)
//     {
//         //错误处理
//     }

//     //显示接口列表
//     for(d = alldevs; d != NULL; d = d->next)
//     {
//         //利用d->name获取该网络接口设备的名字
//         pcap_next_ex(pcap_open(d->name, 66356, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf1)
        
//         )
//         //利用d->description获取该网路接口的设备的描述信息
//     }
//     //释放设备列表
//     pcap_freealldevs(alldevs);

//     //利用pcap_next_ex()函数捕获数据包

//     //检验校验和
//     Data_t * IPPacket;
//     WORD RecvChecksum;

//     IPPacket = (Data_t *) pkt_data;

//     RecvChecksum = IPPacket->IPHeader.Checksum;
//     //利用窗口的PostMessage()函数发送消息
//     AfgGetApp()->m_pMainWnd->PostMessage(WM_PACKET, 0, 0);
// }







// 以下程序为根据以上代码所设计的捕获数据报的程序
 
#include "stdafx.h"
 
#define HAVE_REMOTE
#include <pcap.h>
 
/* 对packet handler函数进行声明 */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
 
#pragma comment(lib,"wpcap.lib")
 
int _tmain(int argc, _TCHAR* argv[])
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int interface_num; // 先声明之后用户选择要用到的端口号
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
 
	/* 获取本机设备列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
 
	/* 打印列表 */
	for(d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
 
	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
 
	printf("Enter the interface number which you like between (1 —— %d):",i); // 输入你想要监听的接口
	scanf("%d", &interface_num);
 
	if(interface_num < 1 || interface_num > i)
	{
		printf("\nInterface number out of range.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}
 
	/* 跳转到选中的适配器 */
	for(d = alldevs, i=0; i< interface_num - 1 ; d = d->next, i++);

	/* 打开设备 */
	if ( (adhandle = pcap_open(d->name,          // 设备名
		65535,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
		1000,             // 读取超时时间
		NULL,             // 远程机器验证
		errbuf            // 错误缓冲池
		) ) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}
 
	printf("\nlistening on %s...\n", d->description);
 
	/* 释放设备列表，因为已经捕获到了数据包 */
	pcap_freealldevs(alldevs);
 
	/* 开始捕获 */
	pcap_loop(adhandle, 0, packet_handler, NULL);
 
	getchar();
 
	return 0;
}
 
 
/* 每次捕获到数据包时，libpcap都会自动调用这个回调函数 */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;
 
	/* 将时间戳转换成可识别的格式 */
	local_tv_sec = header->ts.tv_sec;
	ltime=localtime(&local_tv_sec);
	strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
 
	printf("%s,%.6ld len:%d\n", timestr, header->ts.tv_usec, header->len);


    // 检验校验和
    Data_t * IPPacket;
    WORD RecvChecksum;

    IPPacket = (Data_t *) pkt_data;

    RecvChecksum = IPPacket->IPHeader.Checksum;
    // 需要编码的地方，仿照校验和，写输出语句，输出源MAC地址、目的MAC地址和类型/长度字段的值的语句
    char src[6];
    char des[6];
    for(int j = 0;j < 6;j++)
    {
        src[j] = (char)IPPacket->FrameHeader.SrcMAC[j];
        des[j] = (char)IPPacket->FrameHeader.DesMAC[j];
    }
    char type = (char)IPPacket->FrameHeader.FrameType

    printf("------------------------------------------------------\n");
    printf("数据报的源MAC地址为%s，数据报的目的MAC地址为%s，其类型为%s\n", src, des, type);
    printf("------------------------------------------------------\n");


}
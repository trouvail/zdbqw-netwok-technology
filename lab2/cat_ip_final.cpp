#define HAVE_REMOTE

#define WM_PACKET WM_USER + 1 //�û��Զ�����Ϣ

#include <pcap.h>
#include <time.h>
#include <stdio.h>
#include <iostream>


#pragma warning(disable : 4996)



#pragma pack(1)
typedef struct FrameHeader_t //֡�ײ�
{
    BYTE DesMAC[6]; //Ŀ�ĵ�ַ
    BYTE SrcMAC[6]; //Դ��ַ
    WORD FrameType; //֡����
} FrameHeader_t;

typedef struct IPHeader_t //IP�ײ�
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

typedef struct Data_t //����֡�ײ���IP�ײ������ݰ�
{
    FrameHeader_t FrameHeader;
    IPHeader_t IPHeader;
} Data_t;

#pragma pack()


// ���³���Ϊ�������ϴ�������ƵĲ������ݱ��ĳ���


/* ��packet handler������������ */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

#pragma comment(lib,"wpcap.lib")

int main(int argc, char* argv[])
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int interface_num; // ������֮���û�ѡ��Ҫ�õ��Ķ˿ں�
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

    /* ��ȡ�����豸�б� */
    if (pcap_findalldevs_ex(error1, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* ��ӡ�б� */
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

    printf("Enter the interface number which you like between (1 ���� %d):", i); // ��������Ҫ�����Ľӿ�
    scanf("%d", &interface_num);

    if (interface_num < 1 || interface_num > i)
    {
        printf("\nInterface number out of range.\n");
        /* �ͷ��豸�б� */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* ��ת��ѡ�е������� */
    for (d = alldevs, i = 0; i < interface_num - 1; d = d->next, i++);

    /* ���豸 */
    if ((adhandle = pcap_open(d->name,          // �豸��
        65535,            // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
        PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ
        1000,             // ��ȡ��ʱʱ��
        NULL,             // Զ�̻�����֤
        errbuf            // ���󻺳��
    )) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        /* �ͷ��豸�б� */
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nlistening on %s...\n", d->description);

    

    /* ��ʼ���� */
    pcap_loop(adhandle, 0, packet_handler, NULL);

    /* �ͷ��豸�б�����Ϊ�Ѿ����������ݰ� */
    pcap_freealldevs(alldevs);

    getchar();

    return 0;
}


/* ÿ�β������ݰ�ʱ��libpcap�����Զ���������ص����� */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    struct tm* ltime;
    char timestr[16];
    time_t local_tv_sec;

    /* ��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

    printf("%s,%.6ld len:%d\n", timestr, header->ts.tv_usec, header->len);


    // ����У���
    Data_t* IPPacket;
    WORD RecvChecksum;

    IPPacket = (Data_t*)pkt_data;

    RecvChecksum = IPPacket->IPHeader.Checksum;

    printf("------------------------------------------------------\n");
    //printf("���ݱ���ԴMAC��ַΪ%s�����ݱ���Ŀ��MAC��ַΪ%s��������Ϊ%s\n", src, des, type);
    //std::cout << src[0] << src[1] << src[2] << src[3] << src[4] << src[5] << std::endl;
    //std::cout << des[0] << des[1] << des[2] << des[3] << des[4] << des[5] << std::endl;
    printf("���ݱ���ԴMAC��ַΪ��0x%x", IPPacket->FrameHeader.SrcMAC[0]);
    printf("%x", IPPacket->FrameHeader.SrcMAC[1]);
    printf("%x", IPPacket->FrameHeader.SrcMAC[2]);
    printf("%x", IPPacket->FrameHeader.SrcMAC[3]);
    printf("%x", IPPacket->FrameHeader.SrcMAC[4]);
    printf("%x\n", IPPacket->FrameHeader.SrcMAC[5]);

    printf("���ݱ���Ŀ��MAC��ַΪ��0x%x", IPPacket->FrameHeader.DesMAC[0]);
    printf("%x", IPPacket->FrameHeader.DesMAC[1]);
    printf("%x", IPPacket->FrameHeader.DesMAC[2]);
    printf("%x", IPPacket->FrameHeader.DesMAC[3]);
    printf("%x", IPPacket->FrameHeader.DesMAC[4]);
    printf("%x\n", IPPacket->FrameHeader.DesMAC[5]);





    printf("������Ϊ��0x%x\n", IPPacket->FrameHeader.FrameType);
    printf("------------------------------------------------------\n");


}
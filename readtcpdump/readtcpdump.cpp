#include<stdio.h>
#include<malloc.h>
#include<netinet/in.h>
#include<time.h>
#include<stdlib.h>
#include<string.h>
#include"net.h"
#include"ceph.h"
#include"message.h"
#include "parsepacket.h"

#define IS_CEPH(x) ((x) == 6789 || ((x) >= 6800 && ((x) < 7100)) )
#define GET_IP(x) (((x)&0xff000000) >> 24)
#define GET_PORT(x) (((x)&0xff00) >> 8| ((x)&0xff) << 8)

extern u_int16 tcp_data( struct IPHeader_t * ip_hdr);
/*{

	return ((((ip_hdr->TotalLen << 8) & 0xff00) | ((ip_hdr->TotalLen >> 8) & 0xff)) - \
		((ip_hdr->Ver_HLen & 0xf) << 2));
}*/

int main(int argc, char** argv){

	struct network_packet p_network;

	int pkt_count = 0;
	int pkt_offset = 0;
	int tcp_headlen;
	//int port_s,port_d;
	u_int16 tcp_datalen;
	FILE *fd;
	//char buf[BUFSIZE];
	u_char *buf=NULL;
	int bufsize=0;
	int headersize;

	p_network.file_hdr = (struct pcap_file_header *)malloc(sizeof(struct pcap_file_header));
	p_network.pkt_hdr = (struct pkthdr *)malloc(sizeof(struct pkthdr));
	p_network.eth_hdr = (struct FramHeader_t *)malloc(sizeof(struct FramHeader_t));
	p_network.ip_hdr = (struct IPHeader_t *) malloc(sizeof(struct IPHeader_t));
	p_network.tcp_hdr = (struct TCPHeader_t *)malloc(sizeof(struct TCPHeader_t));

	headersize=sizeof(struct FramHeader_t)+sizeof(struct IPHeader_t)+sizeof(struct TCPHeader_t);

	if((fd = fopen(argv[1],"r")) == NULL ){
		printf("Error: Can not open the file!\n");
		exit(0);
	}

	if( fread(p_network.file_hdr, sizeof(struct pcap_file_header), 1, fd) != 1){
		printf("Error: .file_hdr read fail!\n");
		fclose(fd);
		exit(0);
	}else{
		pkt_offset += sizeof(struct pcap_file_header);
	//	printf("Magic: %p\n",(void *)p_network.file_hdr->magic);
	}

	//memset(total_op,0,sizeof(total_op));

	//set the begin time as a
	fseek(fd, pkt_offset, SEEK_SET);
	fread(p_network.pkt_hdr, sizeof(struct pkthdr), 1, fd);

	unsigned short src_port,dst_port;


	while(fseek(fd, pkt_offset, SEEK_SET) == 0){

		pkt_count++;
		if(fread(p_network.pkt_hdr, sizeof(struct pkthdr), 1, fd) != 1){
			// 读取每一个pcap的包头
			if(feof(fd))
			  break;
			printf("Error: Can not open %d pocket\n", pkt_count);
			//printf("%d \n", sizeof(p_network.pkt_hdr->ts));
			break;
		}

		//计算下一个pcap包头的位置
		pkt_offset += sizeof(struct pkthdr) + p_network.pkt_hdr->caplen;

		//记录pcap包的时间戳
//		g_time.t_sec = p_network.pkt_hdr->ts_sec;
//		g_time.t_usec = p_network.pkt_hdr->ts_usec;
		//printf("t_sec:%d,t_usec:%d\n",g_time.t_sec, g_time.t_usec);
		if(fread(p_network.eth_hdr, sizeof(struct FramHeader_t), 1, fd) != 1)
		  continue;

		//printf("eth protocl %d\n", p_network.eth_hdr->FrameType);
		//读取以太网报文头部
		if( !(p_network.eth_hdr->FrameType & 0x08) )
		  continue;
		//判断是否是ipv4报文
		if(fread(p_network.ip_hdr, sizeof(struct IPHeader_t), 1, fd) != 1)
		  continue;

		//printf("IP protocl %d\n", p_network.ip_hdr->Protocol);
		if( !(p_network.ip_hdr->Protocol & 0x06) )
		  continue;
		//判断是否是TCP协议
		if(fread(p_network.tcp_hdr, sizeof(struct TCPHeader_t), 1, fd) != 1)
		  continue;
		//printf("From: %d.%d.%d.%d\n",(p_network.ip_hdr->SrcIP >> 24),(p_network.ip_hdr->SrcIP >> 16) & 0x00ff,(p_network.ip_hdr->SrcIP & 0xff00) >> 8,(p_network.ip_hdr->SrcIP&0xff));
		dst_port = GET_PORT(p_network.tcp_hdr->DstPort);
		src_port = GET_PORT(p_network.tcp_hdr->SrcPort);
		if( !(IS_CEPH(dst_port ) ||  IS_CEPH(src_port)))
		  continue;
		//判断是否是ceph协议
		//printf("\n%d, %d\n",port_d, port_s);
		tcp_datalen = tcp_data( p_network.ip_hdr );
		tcp_headlen = p_network.tcp_hdr->HeaderLen >> 2; //计算tcp头部长度
		int	ceph_msg_len = tcp_datalen - tcp_headlen;
		if( ceph_msg_len ){
                if (buf==NULL)
                {
                    buf=(unsigned char *)malloc(headersize+tcp_datalen);
                    bufsize=headersize+tcp_datalen;
                } else if (bufsize<headersize+tcp_datalen)
                {
                    if (buf!=NULL) free(buf);
                    buf=(unsigned char *)malloc(headersize+tcp_datalen);
                    bufsize=headersize+tcp_datalen;
                }
                if (buf==NULL)
                {
                    printf("Can not malloc memory, exit.");
                    break;
                }

                memset(buf,0,bufsize);

                int offset=0;
                memcpy(buf,p_network.eth_hdr,sizeof(struct FramHeader_t));
                offset+=sizeof(struct FramHeader_t);
                memcpy(buf+offset,p_network.ip_hdr,sizeof(struct IPHeader_t));
                offset+=sizeof(struct IPHeader_t);
                memcpy(buf+offset,p_network.tcp_hdr,sizeof(struct TCPHeader_t));
                offset+=sizeof(struct TCPHeader_t);


                fread(buf+offset, tcp_datalen, 1, fd);//读取tcp的数据
                const pcap_pkthdr *constp;
                constp=(pcap_pkthdr *)p_network.pkt_hdr;
                got_packet("T",constp,buf);

		}
	}
	/*
	int i;
	for(i = 0; i < OP_NUM; i++)
		printf("type:%X\t%d-%lf\n", total_op[i].type, total_op[i].count, \
							interval_t(total_op[i].start, total_op[i].end));
	*/
	//printf("Total %d pockets\n",--pkt_count );
	if (buf!=NULL) free(buf);
	free(p_network.file_hdr);
	free(p_network.pkt_hdr);
	free(p_network.eth_hdr);
	free(p_network.ip_hdr);
	free(p_network.tcp_hdr);
	fclose(fd);
	return 0;
}

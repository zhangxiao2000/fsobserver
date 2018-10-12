#include<stdio.h>
#include<malloc.h>
#include<netinet/in.h>
#include<time.h>
#include<stdlib.h>
#include<string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include"net.h"
#include"ceph.h"
#include"message.h"

#define BUFSIZE (1<<12)
#define STRSIZE 1024
#define OP_NUM 31
#define SESSION_OP_NUM 11
#define MAX_USER_NUM 10
#define MILLION 1000000.0
#define MB 1048576.0
//1048576 = 1024^2

#define IS_CEPH(x) ((x) == 6789 || ((x) >= 6800 && ((x) < 7100)) )
#define GET_IP(x) (((x)&0xff000000) >> 24)
#define GET_PORT(x) (((x)&0xff00) >> 8| ((x)&0xff) << 8)


struct h_op
{

    time_s start, end;
    u_int64 transcation_id;
    u_int16 user_id;
    int first_time;
    struct h_op * next;
    struct ceph_entity_name src;
    double data_size_MB;//only used in osd_op
};

struct op_count
{

    time_s start,end;
    u_int32 type;
    int count;
    double total_time;
    struct h_op *link;
    double data_size_MB;//only used in osd_op
}total_op[OP_NUM];

struct se_op_count
{

    time_s start,end;
    u_int32 type;
    int count;
    double total_time;
}total_se_op[SESSION_OP_NUM];

struct user_op_count
{

    time_s start,end;
    unsigned int id;
    struct op_count total_op[OP_NUM];
    struct se_op_count total_se_op[SESSION_OP_NUM];

}user_op[MAX_USER_NUM];

struct time_s BEGIN_T, g_time;
//calculate interval time

u_int16 src_port,dst_port;

double interval_t(time_s s, time_s e)
{

    double sec, usec;
    double i;
    sec = (double)(e.t_sec - s.t_sec);
    usec = ((e.t_usec - s.t_usec) / MILLION);
    i = (sec + usec);
    //printf("%lf \n", sec);
    return (sec + usec);
}//calculate tcp data length

u_int16 tcp_data( struct IPHeader_t * ip_hdr)
{

    return ((((ip_hdr->TotalLen << 8) & 0xff00) | ((ip_hdr->TotalLen >> 8) & 0xff)) - \
            ((ip_hdr->Ver_HLen & 0xf) << 2));
}

void ceph_request(void *msg)
{

    struct ceph_mds_request_head * request_head = (struct ceph_mds_request_head *) \
                        (msg + sizeof(u_int8)+sizeof(struct ceph_msg_header));

    struct ceph_msgr_msg *ceph_msg = (struct ceph_msgr_msg *)msg;

    struct h_op * m_op = (struct h_op *)malloc(sizeof(struct h_op));
    struct h_op * tmp_op;
    int i;
    m_op->start = g_time;
    m_op->transcation_id = ceph_msg->header.tid;
    m_op->user_id = src_port;//使用端口号标记用户
    m_op->first_time = 0;
    m_op->next = NULL;
    m_op->data_size_MB = 0.0;
    for (i = 0; i < OP_NUM; i++)
{

        if (total_op[i].type == 0)
        {
            //第一次，将其定义并初始化
            total_op[i].type = request_head->op;
            total_op[i].link = m_op;
            total_op[i].total_time = 0.0;
            total_op[i].start = g_time;
            break;
        }

        if (total_op[i].type == request_head->op)
        {
            //此操作已出现过，被定义
            tmp_op = total_op[i].link;
            total_op[i].link = m_op;
            m_op->next = tmp_op;
            break;
        }// end of if

    }//end of for

}//end of this function

void ceph_reply(void *msg)
{

    struct ceph_mds_reply_head * reply_head = (struct ceph_mds_reply_head *) \
                        (msg + sizeof(u_int8)+sizeof(struct ceph_msg_header));
    struct ceph_msgr_msg *ceph_msg = (struct ceph_msgr_msg *)msg;

    struct h_op * pre_op, *tmp_op;
    double intv, time_line;
    int i;
    for (i = 0; i < OP_NUM; i++)
{

        if (total_op[i].type == reply_head->op)
        {

            tmp_op = total_op[i].link;
            pre_op = tmp_op;
            while (tmp_op)
            {
                //遍历通过匹配transaction_id进行匹配

                if (tmp_op->transcation_id == ceph_msg->header.tid &&\
                        tmp_op->user_id == dst_port)
                {
                    if (tmp_op->first_time == 0)
                    {

                        //this operation is not re-send;
                        total_op[i].count++;
                    }
                    tmp_op->first_time++;
                    tmp_op->end = g_time;
                    intv = interval_t(tmp_op->start, tmp_op->end);
                    total_op[i].total_time += intv;
                    tmp_op->start = g_time;
                    //将开始时间设置为本次结束时间，因为重传后时间需要重新计算
                    //(t2 - t1) + (t3 - t2),如果不设置就变为(t2 - t1)+(t3 - t1),多计算了时间
                    total_op[i].end = g_time;
                    //print result
                    time_line = interval_t(BEGIN_T, g_time);
                    printf("%lf,%X,%llu,%lf,%d,", time_line, total_op[i].type,\
                           tmp_op->transcation_id, intv, tmp_op->first_time);

                    printf("%u,%llu,%lf\n", tmp_op->src.type, tmp_op->src.num, \
                           tmp_op->data_size_MB);
                    return;

                }
                else
                {
                    tmp_op = tmp_op->next;
                }//end of if else
            }//end of while
        }//end of is
    }//end of for
    //printf("id: %ld ", ceph_msg->header.tid);
    //printf("type: %X\n", reply_head->op);
    //printf("Resquest not found!\n");
    return;
}

void ceph_osd_request(void *msg)
{

    struct ceph_msgr_msg *ceph_msg = (struct ceph_msgr_msg *)msg;
    struct ceph_osd_op_request *ceph_request = (struct ceph_osd_op_request *)\
                        (msg + sizeof(u_int8) + sizeof(struct ceph_msg_header));
    struct h_op *m_op = (struct h_op *)malloc(sizeof(struct h_op));
    struct h_op *tmp_op;
    u_int32 type;
    int i;
    char flag = 'N';
    if (ceph_request->OSD_FLAG & OSD_FLAG_OP_WRITE)
{
        flag = 'W';
        type = CEPH_OSD_OP_WRITE;
    }
    else if (ceph_request->OSD_FLAG & OSD_FLAG_OP_READ)
    {
        flag = 'R';
        type = CEPH_OSD_OP_READ;
    }

    if (flag == 'N')
        return;

    m_op->start = g_time;
    m_op->transcation_id = ceph_msg->header.tid;
    m_op->user_id = src_port;
    m_op->first_time = 0;
    m_op->next = NULL;

    if (flag == 'W')
        //if it is a wirte op
        //recorde the transcation data in request datagram,
        //read op will be record in reply datagram.
        m_op->data_size_MB = ceph_msg->header.data_len / MB;
    else
        m_op->data_size_MB = 0.0;

    for (i = 0; i < OP_NUM; i++)
    {

        if (total_op[i].type == 0)
        {
            // first, and initialize it
            total_op[i].data_size_MB += m_op->data_size_MB;
            total_op[i].type = type;
            total_op[i].start = m_op->start;
            total_op[i].link = m_op;
            total_op[i].total_time = 0.0;
            break;
        }

        if (total_op[i].type == type)
        {
            //already in the chain
            total_op[i].data_size_MB += m_op->data_size_MB;
            tmp_op = total_op[i].link;
            total_op[i].link = m_op;
            m_op->next = tmp_op;
            break;
        }
    }

    return;

}


void ceph_osd_reply(void *msg)
{

    struct ceph_msgr_msg *ceph_msg = (struct ceph_msgr_msg *)msg;
    u_int32 *offset_obj_id_len = (u_int32 *)(msg + sizeof(u_int8) + \
                                 sizeof(struct ceph_msg_header));


    struct ceph_osd_op_reply *reply_head = (struct ceph_osd_op_reply *)\
                                                       (msg + sizeof(u_int8) + sizeof(struct ceph_msg_header) +\
                                                        sizeof(u_int32) + (*offset_obj_id_len));

    struct h_op * pre_op, *tmp_op;
    double intv, time_line;
    int i;
    u_int32 type;
    char flag = 'N';
    //printf("%X --test\t", reply_head->OSD_FLAG);
    //printf("%llu--test\n", ceph_msg->header.tid);
    if (reply_head->OSD_FLAG & OSD_FLAG_OP_WRITE)
{
        flag = 'W';
        type = CEPH_OSD_OP_WRITE;
    }
    else if (reply_head->OSD_FLAG & OSD_FLAG_OP_READ)
    {
        flag = 'R';
        type = CEPH_OSD_OP_READ;
    }

    if (flag == 'N')
    {

        return;
    }

    //printf("%c\t%llu,%lf,%X\n",flag, ceph_msg->header.tid, ceph_msg->header.data_len/MB,reply_head->OSD_FLAG);
    for (i = 0; i < OP_NUM; i++)
    {

        if (total_op[i].type == type)
        {

            tmp_op = total_op[i].link;
            while (tmp_op)
            {

                if (tmp_op->transcation_id == ceph_msg->header.tid) /*&& \
							tmp_op->user_id == dst_port)*/
                {

                    if (tmp_op->first_time == 0)
                    {
                        //this msg isn't re-send;
                        total_op[i].count++;
                    }

                    tmp_op->first_time++;
                    if (flag == 'R')
                        total_op[i].data_size_MB += tmp_op->data_size_MB / MB;
                    tmp_op->end = g_time;
                    tmp_op->src = ceph_msg->header.src;
                    time_line = interval_t(BEGIN_T, g_time);
                    intv = interval_t(tmp_op->start, tmp_op->end);
                    total_op[i].total_time += intv;
                    tmp_op->start = g_time;

                    printf("%lf,%X,%llu,%lf,", time_line, type, tmp_op->transcation_id,\
                           intv);
                    printf("%d,%u,%llu,%lf\n",tmp_op->first_time, tmp_op->src.type, \
                           tmp_op->src.num, tmp_op->data_size_MB);
                    break;
                }
                else
                {
                    tmp_op = tmp_op->next;
                }
            }

            break;
        }
    }//end of for i
}


void analyse_msg(u_int8 *raw_data)
{

    struct ceph_msgr_msg *msg = (struct ceph_msgr_msg *) raw_data;

    printf("msg->tag %d\n",msg->tag);

    switch (msg->header.type)
    {

    case CEPH_MSG_CLIENT_SESSION:
        //printf("client session");
        break;

    case CEPH_MSG_CLIENT_REQUEST:
        //printf("client requset");
        ceph_request((void *) msg);
        break;

    case CEPH_MSG_CLIENT_REPLY:
        //printf("client reply");
        ceph_reply((void *) msg);
        break;

    case CEPH_OSD_OP:
        //printf("ceph os op \n");
        ceph_osd_request((void *) msg);
        break;

    case CEPH_OSD_OPREPLY:
        //print("ceph os op reply \n");
        ceph_osd_reply((void *) msg);
        break;

    case CEPH_MSG_CLIENT_CAPS:
        //printf("client capabilities");
        break;
    default:
        //	printf("type: %X\t", msg->header.type);
        break;

    }

}

void dissect_ceph( char *raw_data , u_int32 msg_len)
{

    u_int8 *p_offset = (u_int8 *)raw_data;
    u_int32 head_len = sizeof(struct ceph_msg_header);
    u_int32 foot_len = sizeof(struct ceph_msg_footer);
    struct ceph_msg_header *head_p;
    u_int32 len = msg_len;
    while ( len && len <= msg_len)
    {
        //msg_len is a unsigned num, so it cannot be
        //more than it's orginal length
        //printf("%p,%d\n", p_offset, msg_len);
        u_int8	ceph_tag = *((u_int8 *)p_offset);
        printf("Ceph_tag %d\n",ceph_tag);
        switch (ceph_tag)
        {

        case CEPH_MSGR_TAG_MSG:
            analyse_msg(p_offset);
            head_p = (struct ceph_msg_header *)(p_offset + sizeof(u_int8));
            len -= (sizeof(u_int8) + head_len + head_p->front_len + foot_len);
            if (len > msg_len)
                return;
            p_offset += (sizeof(u_int8) + head_len + head_p->front_len + foot_len);

            if ((u_int64)p_offset > 0x800000000000)
                return;//Just in case!
            break;

        case CEPH_MSGR_TAG_ACK:
            len -= sizeof(struct ceph_msgr_ack);
            p_offset += sizeof(struct ceph_msgr_ack);
            //printf(" ack  ");
            break;

        default:
            //printf("other type, type number:%d\n",ceph_tag);
            return;
        }
    }

    return;
}

int main(int argc, char** argv)
{

    struct network_packet p_network;

    int pkt_count = 0;
    int pkt_offset = 0;
    int tcp_headlen;
    //int port_s,port_d;
    u_int16 tcp_datalen;
    FILE *fd, *output;
    char buf[BUFSIZE];
    //char * buf=(char *)malloc(BUFSIZE);
    char *tcp_data_buf;
    p_network.file_hdr = (struct pcap_file_header *)malloc(sizeof(struct pcap_file_header));
    p_network.pkt_hdr = (struct pkthdr *)malloc(sizeof(struct pkthdr));
    p_network.eth_hdr = (struct FramHeader_t *)malloc(sizeof(struct FramHeader_t));
    p_network.ip_hdr = (struct IPHeader_t *) malloc(sizeof(struct IPHeader_t));
    p_network.tcp_hdr = (struct TCPHeader_t *)malloc(sizeof(struct TCPHeader_t));

    if ((fd = fopen(argv[1],"r")) == NULL )
    {
        printf("Error: Can not open the fail!\n");
        exit(0);
    }

    if ( fread(p_network.file_hdr, sizeof(struct pcap_file_header), 1, fd) != 1)
    {
        printf("Error: .file_hdr read fail!\n");
        fclose(fd);
        exit(0);
    }
    else
    {
        pkt_offset += sizeof(struct pcap_file_header);
        //	printf("Magic: %p\n",(void *)p_network.file_hdr->magic);
    }

    //memset(total_op,0,sizeof(total_op));

    //set the begin time as a
    fseek(fd, pkt_offset, SEEK_SET);
    fread(p_network.pkt_hdr, sizeof(struct pkthdr), 1, fd);
    BEGIN_T.t_sec = p_network.pkt_hdr->ts_sec;
    BEGIN_T.t_usec = p_network.pkt_hdr->ts_usec;

    while (fseek(fd, pkt_offset, SEEK_SET) == 0)
    {

        pkt_count++;
        memset(buf, 0, sizeof(BUFSIZE));

        if (fread(p_network.pkt_hdr, sizeof(struct pkthdr), 1, fd) != 1)
        {
            // 读取每一个pcap的包头
            if (feof(fd))
                break;
            printf("Error: Can not open %d pocket\n", pkt_count);
            //printf("%d \n", sizeof(p_network.pkt_hdr->ts));
            break;
        }

        //计算下一个pcap包头的位置
        pkt_offset += sizeof(struct pkthdr) + p_network.pkt_hdr->caplen;

        //记录pcap包的时间戳
        g_time.t_sec = p_network.pkt_hdr->ts_sec;
        g_time.t_usec = p_network.pkt_hdr->ts_usec;
        //printf("t_sec:%d,t_usec:%d\n",g_time.t_sec, g_time.t_usec);
        if (fread(p_network.eth_hdr, sizeof(struct FramHeader_t), 1, fd) != 1)
            continue;

        //printf("eth protocl %d\n", p_network.eth_hdr->FrameType);
        //读取以太网报文头部
        if ( !(p_network.eth_hdr->FrameType & 0x08) )
            continue;
        //判断是否是ipv4报文
        if (fread(p_network.ip_hdr, sizeof(struct IPHeader_t), 1, fd) != 1)
            continue;

        //printf("IP protocl %d\n", p_network.ip_hdr->Protocol);
        if ( !(p_network.ip_hdr->Protocol & 0x06) )
            continue;
        //判断是否是TCP协议
        if (fread(p_network.tcp_hdr, sizeof(struct TCPHeader_t), 1, fd) != 1)
            continue;
        dst_port = GET_PORT(p_network.tcp_hdr->DstPort);
        src_port = GET_PORT(p_network.tcp_hdr->SrcPort);
        if ( !(IS_CEPH(dst_port ) ||  IS_CEPH(src_port)))
            continue;
        //判断是否是ceph协议
//        printf("From: %d.%d.%d.%d:%d To:%d.%d.%d.%d:%d\n",(p_network.ip_hdr->SrcIP >> 24),(p_network.ip_hdr->SrcIP >> 16) & 0x00ff,(p_network.ip_hdr->SrcIP & 0xff00) >> 8,(p_network.ip_hdr->SrcIP&0xff),src_port,\
//        (p_network.ip_hdr->DstIP >> 24),(p_network.ip_hdr->DstIP >> 16) & 0x00ff,(p_network.ip_hdr->DstIP & 0xff00) >> 8,(p_network.ip_hdr->DstIP&0xff),dst_port);
       in_addr  *src_ip,*dst_ip;
       src_ip=(in_addr *)&(p_network.ip_hdr->SrcIP);
       dst_ip=(in_addr *)&(p_network.ip_hdr->DstIP);
       char src_buf[20],dst_buf[20];
       strcpy(src_buf,inet_ntoa(*src_ip));
       strcpy(dst_buf,inet_ntoa(*dst_ip));

        printf("From: %s:%d To:%s:%d\n",src_buf,src_port,dst_buf,dst_port);
        
        //printf("\n%d, %d\n",dst_port, src_port);
        tcp_datalen = tcp_data( p_network.ip_hdr );
        tcp_headlen = p_network.tcp_hdr->HeaderLen >> 2; //计算tcp头部长度
        int	ceph_msg_len = tcp_datalen - tcp_headlen;
        if ( ceph_msg_len )
        {

            //printf("This is a ceph protocol,No.%d\n", pkt_count);
            //	printf("NO.%d ", pkt_count);
            //	printf(" %d \n", tcp_datalen);
            char *dynabuff=NULL;
            if (tcp_datalen<BUFSIZE)
            {
                fread(buf, tcp_datalen, 1, fd);//读取tcp的数据
                //char * ipsrc = inet_ntoa(p_network.ip_hdr->SrcIP);
                //char * ipdst = inet_ntoa(p_network.ip_hdr->DstIP);
                //printf("%s, %s", ipsrc,ipdst);
                //	printf("%d to %d ,", GET_IP(p_network.ip_hdr->SrcIP), GET_IP(p_network.ip_hdr->DstIP));
                tcp_data_buf = buf;
            }
            else
            {
                dynabuff=(char *)malloc(tcp_datalen);
                fread(dynabuff, tcp_datalen, 1, fd);//读取tcp的数据
                tcp_data_buf = dynabuff;
            }
            tcp_data_buf +=(tcp_headlen - sizeof(struct TCPHeader_t));//跳过多余头部
            dissect_ceph(tcp_data_buf, ceph_msg_len);

            if (dynabuff!=NULL)
            {
                free(dynabuff);
                dynabuff=NULL;
            }

            //	printf("\n");
        }
    }
    /*
    int i;
    for(i = 0; i < OP_NUM; i++)
    	printf("type:%X\t%d-%lf\n", total_op[i].type, total_op[i].count, \
    						interval_t(total_op[i].start, total_op[i].end));
    */
    //printf("Total %d pockets\n",--pkt_count );
    free(p_network.file_hdr);
    free(p_network.pkt_hdr);
    free(p_network.eth_hdr);
    free(p_network.ip_hdr);
    free(p_network.tcp_hdr);
    //free(buf);
    fclose(fd);
    return 0;
}

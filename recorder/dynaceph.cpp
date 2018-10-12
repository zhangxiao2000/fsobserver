#include<stdio.h>
#include<malloc.h>
#include<netinet/in.h>
#include<time.h>
#include<stdlib.h>
#include<string.h>
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

#define IS_CEPH(x) ((x) == 6789 || ((x) >= 6800 && ((x) < 7300)) )
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


//calculate tcp data length

u_int16 tcp_data( struct IPHeader_t * ip_hdr)
{

    return ((((ip_hdr->TotalLen << 8) & 0xff00) | ((ip_hdr->TotalLen >> 8) & 0xff)) - \
            ((ip_hdr->Ver_HLen & 0xf) << 2));
}

void ceph_request(char *prefix, const u_char *msg, u_int32 msg_len)
{

    struct ceph_mds_request_head * request_head = (struct ceph_mds_request_head *) \
                        (msg + sizeof(u_int8)+sizeof(struct ceph_msg_header));

    struct ceph_msgr_msg *ceph_msg = (struct ceph_msgr_msg *)msg;

    //prefix,type,transid,length
    
    printf("%s,%d,0x%x,%llu,%u",prefix,ceph_msg->header.type,request_head->op,ceph_msg->header.tid,ceph_msg->header.data_len);

}//end of this function


void ceph_reply(char *prefix,const u_char *msg, u_int32 msg_len)
{

    struct ceph_mds_reply_head * reply_head = (struct ceph_mds_reply_head *) \
                        (msg + sizeof(u_int8)+sizeof(struct ceph_msg_header));
    struct ceph_msgr_msg *ceph_msg = (struct ceph_msgr_msg *)msg;

    //prefix,type,transid,length
    printf("%s,%d,0x%x,%llu,%u",prefix,ceph_msg->header.type,reply_head->op,ceph_msg->header.tid,ceph_msg->header.data_len);    

    return;
}


#define CEPH_OSD_FLAG_OP_WR (OSD_FLAG_OP_WRITE|OSD_FLAG_OP_READ)
#define C_SIZE_OSD_OP_MIN 34U //define a unsigned constant to reduce warning

void ceph_osd_request(char *prefix, const u_char *msg, u_int32 msg_len)
{

    struct ceph_msgr_msg *ceph_msg = (struct ceph_msgr_msg *)msg;
    struct ceph_msg_osd_op_request *ceph_request = (struct ceph_msg_osd_op_request *)(msg + sizeof(u_int8) + sizeof(struct ceph_msg_header));
    struct ceph_osd_op *p_op;
                
//    struct h_op *m_op = (struct h_op *)malloc(sizeof(struct h_op));
//    struct h_op *tmp_op;
//    u_int32 type;
    unsigned int i,count=1,opslen;
    unsigned int check_area;
    
    if (NULL==msg)     		
    	return;
    	
    //check available of first part
    check_area=sizeof(struct ceph_msgr_msg);
    if (msg_len<check_area)
	
    	return;
	
	
	 //check available of front_len(not include ops)
	  check_area+=ceph_msg->header.front_len;
	  //comment
   //if (ceph_msg->header.front_len<sizeof(struct ceph_msg_osd_op_request)||msg_len<check_area){
	//	printf("test error");
	 // 	return;
	//}
    
	  //printf("%s,%d,0x%x,%d,%d,%d",prefix,ceph_msg->header.type,ceph_request->osd_flag,ceph_msg->header.tid,ceph_msg->header.front_len,ceph_msg->header.data_len); 
	  printf("%s,0x%x,%d",prefix,ceph_request->osd_flag,ceph_msg->header.data_len); 
	 
	//check if it is a request about RW
   // if (0==(ceph_request->osd_flag&CEPH_OSD_FLAG_OP_WR))
    //	return;
	 

	   opslen=ceph_request->op_number;
	   //check available of ops areas
	   check_area+=opslen*sizeof(struct ceph_msg_osd_op_request);
	   //comment
    //	if (opslen > (ceph_msg->header.front_len-sizeof(struct ceph_msg_osd_op_request))/C_SIZE_OSD_OP_MIN||msg_len<check_area)
	//{
		/*
			If the size is huge (maybe it was mangled on the wire) we want to
			avoid allocating massive amounts of memory to handle it.  So, if
			it is larger then can possible fit in the rest of the message bail
			out.
		*/
		//printf("opslen, %d,%d,%lu",opslen,ceph_msg->header.front_len,sizeof(struct ceph_msg_osd_op_request));
		//return ;
	//}
	//print object id
//	printf(",%.*s",38,&ceph_request->obj_id[4]);

	  //prefix,type,transid,length
	  p_op=ceph_request->ops;
	  for(i=1;i<opslen+1;i++)
	  {
			switch (p_op->op)
				{
					case C_OSD_OP_READ:						
						printf(",%d,READ,%llu,%llu",count,p_op->extent.offset,p_op->extent.length);
						count++;
						break;
					case C_OSD_OP_WRITE:
						printf(",%d,WRITE,%llu,%llu",count,p_op->extent.offset,p_op->extent.length);
						count++;
						break;
					default:
						break;					
				}
			p_op++;
		}	  	
	  	
    return;
}


void ceph_osd_reply(char *prefix, const u_char *msg, u_int32 msg_len)
{

    struct ceph_msgr_msg *ceph_msg = (struct ceph_msgr_msg *)msg;
//    u_int32 *offset_obj_id_len = (u_int32 *)(msg + sizeof(u_int8) + sizeof(struct ceph_msg_header));
    struct ceph_msg_osd_op_reply *reply_head = (struct ceph_msg_osd_op_reply *)(msg + sizeof(u_int8) + sizeof(struct ceph_msg_header));
                 

//    struct h_op * pre_op, *tmp_op;
//    double intv, time_line;
//    int i;
//    u_int32 type;
    
    struct ceph_osd_op *p_op;
                        
//    struct h_op *m_op = (struct h_op *)malloc(sizeof(struct h_op));
//    struct h_op *tmp_op;
//    u_int32 type;
    unsigned int i,count=1,opslen;
    unsigned int check_area;
    
    if (NULL==msg)     		
    	return;
    	
    //check available of first part
    check_area=sizeof(struct ceph_msgr_msg);
    if (msg_len<check_area)
    	return;
	
	//check available of first part+front_part
    check_area+=ceph_msg->header.front_len;
	  if (ceph_msg->header.front_len<sizeof(struct ceph_msg_osd_op_reply)||msg_len<check_area)
	  	return;
    		
    //prefix,type,transid,length    
//    printf("%s,0x%x,%d",prefix,reply_head->osd_flag,ceph_msg->header.data_len);    	
    	    
    if (0==(reply_head->osd_flag&CEPH_OSD_FLAG_OP_WR))
    	return; 
	  
    	   opslen=reply_head->op_number;
     //check available for op part
     check_area+=opslen*(sizeof(struct ceph_msg_osd_op_reply));
  //  	if (opslen > (ceph_msg->header.front_len-sizeof(struct ceph_msg_osd_op_reply))/C_SIZE_OSD_OP_MIN||msg_len<check_area)
//	{
		/*
			If the size is huge (maybe it was mangled on the wire) we want to
			avoid allocating massive amounts of memory to handle it.  So, if
			it is larger then can possible fit in the rest of the message bail
			out.
		*/
//		printf("opslen,%d,%d,%lu",opslen,ceph_msg->header.front_len,sizeof(struct ceph_msg_osd_op_request));
//		return ;
//	}

	//print object id
//	printf(",%.*s",38,&reply_head->obj_id[4]);
	  	
	  p_op=reply_head->ops;
	  for(i=1;i<reply_head->op_number+1;i++)
	  {
			switch (p_op->op)
				{
					case C_OSD_OP_READ:						
						printf(",%d,READ_REPLY,%llu,%llu",count,p_op->extent.offset,p_op->extent.length);
						count++;
						break;
					case C_OSD_OP_WRITE:
						printf(",%d,WRITE_REPLY,%llu,%llu",count,p_op->extent.offset,p_op->extent.length);
						count++;
						break;
					default:
						//printf(",,%d,,",op->op);
						break;					
				}
			p_op++;
		}	    
    
    return ;

}

void analyse_msg(char *prefix, const u_char *payload,u_int32 size_payload)
{

    struct ceph_msgr_msg *msg = (struct ceph_msgr_msg *) payload;

    //printf("msg->tag %d\n",msg->tag);

    switch (msg->header.type)
    {

    case CEPH_MSG_CLIENT_SESSION:
        //printf("client session");
        break;

    case CEPH_MSG_CLIENT_REQUEST:
        //printf("client requset");
        ceph_request(prefix, payload, size_payload);
        break;

    case CEPH_MSG_CLIENT_REPLY:
        //printf("client reply");
        ceph_reply(prefix, payload, size_payload);
        break;

    case CEPH_OSD_OP:
        //printf("ceph os op \n");
        ceph_osd_request(prefix, payload, size_payload);
        break;

    case CEPH_OSD_OPREPLY:
        //printf("ceph os op reply \n");
        ceph_osd_reply(prefix, payload, size_payload);
        break;

    case CEPH_MSG_CLIENT_CAPS:
        //printf("client capabilities");
        break;
    default:
        //	printf("type: %X\t", msg->header.type);
        break;

    }

}

void dissect_ceph(char *prefix, const u_char *payload , u_int32 size_payload)
{

    u_int8 *p_offset = (u_int8 *)payload;
    u_int8	ceph_tag = *((u_int8 *)p_offset);
        //printf("Ceph_tag %d\n",ceph_tag);
    switch (ceph_tag)
    {

    case CEPH_MSGR_TAG_MSG:
        analyse_msg(prefix, payload, size_payload);
        break;

    case CEPH_MSGR_TAG_ACK:
        //printf(" ack  ");
        break;

    default:
        //printf("other type, type number:%d\n",ceph_tag);
        return;
    }    
}    

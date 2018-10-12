#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>

//#include <arpa/inet.h>

#include "ceph.h"
#include <linux/types.h>

void display_tag(char *p)
{
	printf("Message Type:\t%x\n\n",*p);
	return ;
}

	/* From ceph:/src/include/rados.h*/
	
struct ceph_timespec {
	__le32 tv_sec;
	__le32 tv_nsec;
} __attribute__ ((packed));

struct ceph_osd_op {
	__le16 op;           /* CEPH_OSD_OP_* */
	__le32 flags;        /* CEPH_OSD_OP_FLAG_* */
	union {
		struct {
			__le64 offset, length;
			__le64 truncate_size;
			__le32 truncate_seq;
		} __attribute__ ((packed)) extent;
		struct {
			__le32 name_len;
			__le32 value_len;
			__u8 cmp_op;       /* CEPH_OSD_CMPXATTR_OP_* */
			__u8 cmp_mode;     /* CEPH_OSD_CMPXATTR_MODE_* */
		} __attribute__ ((packed)) xattr;
		struct {
			__u8 class_len;
			__u8 method_len;
			__u8 argc;
			__le32 indata_len;
		} __attribute__ ((packed)) cls;
		struct {
			__le64 count;
			__le32 start_epoch; /* for the pgls sequence */
		} __attribute__ ((packed)) pgls;
	        struct {
		        __le64 snapid;
	        } __attribute__ ((packed)) snap;
		struct {
			__le64 cookie;
			__le64 ver;     /* no longer used */
			__u8 op;	/* CEPH_OSD_WATCH_OP_* */
			__u32 gen;      /* registration generation */
			__u32 timeout; /* connection timeout */
		} __attribute__ ((packed)) watch;
		struct {
			__le64 cookie;
		} __attribute__ ((packed)) notify;
		struct {
			__le64 unused;
			__le64 ver;
		} __attribute__ ((packed)) assert_ver;
		struct {
			__le64 offset, length;
			__le64 src_offset;
		} __attribute__ ((packed)) clonerange;
		struct {
			__le64 max;     /* max data in reply */
		} __attribute__ ((packed)) copy_get;
		struct {
			__le64 snapid;
			__le64 src_version;
			__u8 flags;
			/*
			 * __le32 flags: CEPH_OSD_OP_FLAG_FADVISE_: mean the fadvise flags for dest object
			 * src_fadvise_flags mean the fadvise flags for src object
			 */
			__le32 src_fadvise_flags;
		} __attribute__ ((packed)) copy_from;
		struct {
			struct ceph_timespec stamp;
		} __attribute__ ((packed)) hit_set_get;
		struct {
			__u8 flags;
		} __attribute__ ((packed)) tmap2omap;
		struct {
			__le64 expected_object_size;
			__le64 expected_write_size;
			__le32 flags;  /* CEPH_OSD_OP_ALLOC_HINT_FLAG_* */
		} __attribute__ ((packed)) alloc_hint;
		struct {
			__le64 offset;
			__le64 length;
			__le64 data_length;
		} __attribute__ ((packed)) writesame;
		struct {
			__le64 offset;
			__le64 length;
			__le32 chunk_size;
			__u8 type;              /* CEPH_OSD_CHECKSUM_OP_TYPE_* */
		} __attribute__ ((packed)) checksum;
	};
	__le32 payload_len;
} __attribute__ ((packed));
	

/*
 * placement group.
 * we encode this into one __le64.
 */
struct ceph_pg {
	__le16 preferred; /* preferred primary osd */
	__le16 ps;        /* placement seed */
	__le32 pool;      /* object pool */
} __attribute__ ((packed));

/*
 * object layout - how a given object should be stored.
 */
struct ceph_object_layout {
	struct ceph_pg ol_pgid;   /* raw pg, with _full_ ps precision. */
	__le32 ol_stripe_unit;    /* for per-object parity, if any */
} __attribute__ ((packed));

/*
 * compound epoch+version, used by storage layer to serialize mutations
 */
struct ceph_eversion {
	__le32 epoch;
	__le64 version;
} __attribute__ ((packed));
	
//according to MOSDOp.h and packet_ceph.c in wireshark
//line 5078
struct ceph_msg_osd_op_request{
	__le32 client_inc;                /* client incarnation */
	__le32 osdmap_epoch;	
	__le32 flags;	
	u_int64 send_time; //little endian
	//c_dissect_eversion
	u_int64 version_t;//little endian
	u_int32 epoch_t;
	char    object_locator[22];
	char    pg[17];
        char    unknown[54];
	char    obj_id[42];//int + 38 chars string
	u_int16 op_number;
	struct ceph_osd_op ops[0]; //depends on the op_number;
	u_int32 I_DO_NOT_CARE;
}__attribute__((packed));

//according to 	/* ceph:/src/messages/MOSDOpReply.h */
//line 5182

struct ceph_msg_osd_op_reply{
	char obj_id[42];//int + 38 chars string
	char pg[17];
	u_int32 osd_flag;
	u_int32 reserved;
	u_int32 result;
	//c_dissect_eversion
	u_int64 version_t;//little endian
	u_int32 epoch_t;
	u_int32 osd_map_epoch;
	
	u_int32 op_number; //different with request, very stange
	struct ceph_osd_op ops[0];  /* ops[], object */
} __attribute__ ((packed));
	

//struct ceph_osd_reply_head {
//	__le32 client_inc;                /* client incarnation */
//	__le32 flags;
//	struct ceph_object_layout layout;
//	__le32 osdmap_epoch;
//	struct ceph_eversion reassert_version; /* for replaying uncommitted */
//
//	__le32 result;                    /* result code */
//
//	__le32 object_len;                /* length of object name */
//	__le32 num_ops;
//	struct ceph_osd_op ops[0];  /* ops[], object */
//} __attribute__ ((packed));
//


//from packet-ceph.c
#define C_OSD_OP_TYPE_DATA  0x0200
#define C_OSD_OP_MODE_RD    0x1000
#define C_OSD_OP_READ       (C_OSD_OP_MODE_RD|C_OSD_OP_TYPE_DATA|0x01)

#define C_OSD_OP_MODE_WR    0x2000
#define C_OSD_OP_WRITE (C_OSD_OP_MODE_WR|C_OSD_OP_TYPE_DATA|0x01)

#define C_CEPH_MSG_OSD_OP 		     (0x002A) //, "C_CEPH_MSG_OSD_OP")		  
#define C_CEPH_MSG_OSD_OPREPLY     (0x002B) //, "C_CEPH_MSG_OSD_OPREPLY")		  \



void display_ceph_osd_op_request(struct ceph_msg_osd_op_request *p)
{
	struct ceph_osd_op *op;
	int i;
	char *object_id=p->obj_id+4;//remove size of int
	
	printf("Information of struct ceph_msg_osd_op_request:\n");
	printf("sizeof struct:%d\n",sizeof(struct ceph_msg_osd_op_request)+sizeof(struct ceph_osd_op)*(p->op_number));
	printf("object id:%.*s\n",38,object_id);
	printf("osd_flag:\t0x%x\n",p->flags);
	printf("version_t:\t0x%x\n",p->version_t);
	printf("epoch_t:\t0x%x\n",p->epoch_t);
	printf("op_number:\t%d\n",p->op_number);
	op=p->ops;
	for(i=0;i<p->op_number;i++){
			printf("op_%d:\t0x%x\n",i,op->op);
			switch (op->op)
				{
					case C_OSD_OP_READ:						
						printf("read offset:%d,length:\t%d\n",op->extent.offset,op->extent.length);
						break;
					case C_OSD_OP_WRITE:
						printf("write offset:%d,length:\t%d\n",op->extent.offset,op->extent.length);
						break;
					default:
						break;					
				}
			op++;
	}

	return;	
	
} 

void display_ceph_osd_op_reply(struct ceph_msg_osd_op_reply *p)
{
	struct ceph_osd_op *op;
	int i;
	char *object_id=p->obj_id+4;//remove size of int
	
	printf("Information of struct ceph_osd_reply_head:\n");
	printf("sizeof struct:%d\n",sizeof(struct ceph_msg_osd_op_reply)+sizeof(struct ceph_osd_op)*(p->op_number));
	printf("object id:%.*s\n",38,object_id);
printf("osd_flag:\t0x%x\n",p->osd_flag);
	printf("version_t:\t0x%x\n",p->version_t);
	printf("epoch_t:\t0x%x\n",p->epoch_t);
	printf("op_number:\t%d\n",p->op_number);
	op=p->ops;
	for(i=0;i<p->op_number;i++){
			printf("op_%d:\t0x%x\n",i,op->op);
			switch (op->op)
				{
					case C_OSD_OP_READ:
						printf("read reply offset:%d,length:\t%d\n",op->extent.offset,op->extent.length);
						break;
					case C_OSD_OP_WRITE:
						printf("write reply offset:%d,length:\t%d\n",op->extent.offset,op->extent.length);
						break;
					default:
						break;					
				}
			op++;
	}

	return;		
}

void display_ceph_msg_header(struct ceph_msg_header *p)
{
	printf("Information of struct ceph_msg_header:\n");
	printf("sizeof struct:%d\n",sizeof(struct ceph_msg_header));
	printf("seq:\t0x%x\n",p->seq);
	printf("tid:\t0x%x\n",p->tid);
	printf("type:\t0x%x\n",p->type);
	printf("priority:\t%d\n",p->priority);
	printf("version:\t%d\n",p->version);
	printf("front_len:\t%d\n",p->front_len);
	printf("middle_len:\t%d\n",p->middle_len);
	printf("data_len:\t%d\n",p->data_len);
	printf("data_off:\t%d\n",p->data_off);
	printf("ceph_entity_name.type:\t0x%x\n",p->src.type);
	printf("ceph_entity_name.num:\t0x%x\n",p->src.num);
	printf("compat_version:\t%x\n",p->compat_version);	
	
	return;
}

void printusage()
{
	printf("ppacket packetname\n");
	printf("  Print the packet content of Ceph.\n");
	return ;	
}

int main(int argc,char **argv)
{
	char *filename;
	int size,ret;
	
	if (argc<2)
		{
			printusage();
			return -1;
		}
	
	filename=argv[1];
	
	struct stat st;
	ret=stat(filename, &st);
	if (0!=ret) {
		printf("stat file(%s) failed, errno=%d",filename,errno);
		return -1;
	}
	
	size = st.st_size;

	FILE *fp=fopen(filename,"rb");
	
	if (NULL==fp)
		{
			printf("Can not open file(%s).\n",filename);
			return -1;
		}
		
	void *pbuf=malloc(size);
	
	ret=fread(pbuf,size,1,fp);
	
	void *p=pbuf,*p_payload;
	
	display_tag((char *)p);
	display_ceph_msg_header((struct ceph_msg_header*)(p+1));

	short type=((struct ceph_msg_header*)(p+1))->type;
	p_payload = p+sizeof(struct ceph_msg_header)+1;
	switch (type)
	{
		case C_CEPH_MSG_OSD_OP:
			display_ceph_osd_op_request((struct ceph_msg_osd_op_request *)p_payload);
			break;
		case C_CEPH_MSG_OSD_OPREPLY:
			display_ceph_osd_op_reply((struct ceph_msg_osd_op_reply *)p_payload);
			break;
		default:
			break;
	}
	
	free(pbuf);
	fclose(fp);
	
}

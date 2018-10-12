#ifndef CEPH_H
#define CEPH_H

#include <linux/types.h>
#include"net.h"



/* used by message exchange protocol */
#define CEPH_MSGR_TAG_READY         1  /* server->client: ready for messages */
#define CEPH_MSGR_TAG_RESETSESSION  2  /* server->client: reset, try again */
#define CEPH_MSGR_TAG_WAIT          3  /* server->client: wait for racing incoming connection */
#define CEPH_MSGR_TAG_RETRY_SESSION 4  /* server->client + cseq: try again with higher cseq */
#define CEPH_MSGR_TAG_RETRY_GLOBAL  5  /* server->client + gseq: try again with higher gseq */
#define CEPH_MSGR_TAG_CLOSE         6  /* closing pipe */
#define CEPH_MSGR_TAG_MSG           7  /* message */
#define CEPH_MSGR_TAG_ACK           8  /* message ack */
#define CEPH_MSGR_TAG_KEEPALIVE     9  /* just a keepalive byte! */
#define CEPH_MSGR_TAG_BADPROTOVER  10  /* bad protocol version */
#define CEPH_MSGR_TAG_BADAUTHORIZER 11 /* bad authorizer */
#define CEPH_MSGR_TAG_FEATURES      12 /* insufficient features */
#define CEPH_MSGR_TAG_SEQ           13 /* 64-bit int follows with seen seq number */
#define CEPH_MSGR_TAG_KEEPALIVE2     14
#define CEPH_MSGR_TAG_KEEPALIVE2_ACK 15  /* keepalive reply */

//ceph message type
/* misc */
#define CEPH_MSG_SHUTDOWN               1
#define CEPH_MSG_PING                   2

/* client <-> monitor */
#define CEPH_MSG_MON_MAP                4
#define CEPH_MSG_MON_GET_MAP            5
#define CEPH_MSG_MON_GET_OSDMAP         6
#define CEPH_MSG_STATFS                 13
#define CEPH_MSG_STATFS_REPLY           14
#define CEPH_MSG_MON_SUBSCRIBE          15
#define CEPH_MSG_MON_SUBSCRIBE_ACK      16
#define CEPH_MSG_AUTH					17
#define CEPH_MSG_AUTH_REPLY				18
#define CEPH_MSG_MON_GET_VERSION        19
#define CEPH_MSG_MON_GET_VERSION_REPLY  20

/* client <-> mds */
#define CEPH_MSG_MDS_MAP                21

#define CEPH_MSG_CLIENT_SESSION         22
#define CEPH_MSG_CLIENT_RECONNECT       23

#define CEPH_MSG_CLIENT_REQUEST         24
#define CEPH_MSG_CLIENT_REQUEST_FORWARD 25
#define CEPH_MSG_CLIENT_REPLY           26
#define CEPH_MSG_CLIENT_CAPS            0x310
#define CEPH_MSG_CLIENT_LEASE           0x311
#define CEPH_MSG_CLIENT_SNAP            0x312
#define CEPH_MSG_CLIENT_CAPRELEASE      0x313
#define CEPH_MSG_CLIENT_QUOTA           0x314

/* pool ops */
#define CEPH_MSG_POOLOP_REPLY           48
#define CEPH_MSG_POOLOP                 49


/* osd */
#define CEPH_MSG_OSD_MAP                41
#define CEPH_MSG_OSD_OP                 42
#define CEPH_MSG_OSD_OPREPLY            43
#define CEPH_MSG_WATCH_NOTIFY           44

#define CEPH_OSD_OP_WRITE		0x2ABC
#define CEPH_OSD_OP_READ		0x1ABC
#define OSD_FLAG_OP_WRITE		0x00000020
#define OSD_FLAG_OP_READ		0x00000010
#define CEPH_OSD_OP				0x002A
#define CEPH_OSD_OPREPLY		0x002B

//mds operation
enum {
		CEPH_MDS_OP_LOOKUP     = 0x00100,
		CEPH_MDS_OP_GETATTR    = 0x00101,
		CEPH_MDS_OP_LOOKUPHASH = 0x00102,
		CEPH_MDS_OP_LOOKUPPARENT = 0x00103,
		CEPH_MDS_OP_LOOKUPINO  = 0x00104,
		CEPH_MDS_OP_LOOKUPNAME = 0x00105,
		CEPH_MDS_OP_SETXATTR   = 0x01105,
		CEPH_MDS_OP_RMXATTR    = 0x01106,
		CEPH_MDS_OP_SETLAYOUT  = 0x01107,
		CEPH_MDS_OP_SETATTR    = 0x01108,
		CEPH_MDS_OP_SETFILELOCK= 0x01109,
		CEPH_MDS_OP_GETFILELOCK= 0x00110,
		CEPH_MDS_OP_SETDIRLAYOUT=0x0110a,
		CEPH_MDS_OP_MKNOD      = 0x01201,
		CEPH_MDS_OP_LINK       = 0x01202,
		CEPH_MDS_OP_UNLINK     = 0x01203,
		CEPH_MDS_OP_RENAME     = 0x01204,
		CEPH_MDS_OP_MKDIR      = 0x01220,
		CEPH_MDS_OP_RMDIR      = 0x01221,
		CEPH_MDS_OP_SYMLINK    = 0x01222,
		CEPH_MDS_OP_CREATE     = 0x01301,
		CEPH_MDS_OP_OPEN       = 0x00302,
		CEPH_MDS_OP_READDIR    = 0x00305,
		CEPH_MDS_OP_LOOKUPSNAP = 0x00400,
		CEPH_MDS_OP_MKSNAP     = 0x01400,
		//internal op
		CEPH_MDS_OP_RMSNAP     = 0x01401,
		CEPH_MDS_OP_LSSNAP     = 0x00402,
		CEPH_MDS_OP_FRAGMENTDIR= 0x01500,
		CEPH_MDS_OP_EXPORTDIR  = 0x01501,
		CEPH_MDS_OP_VALIDATE   = 0x01502,
		CEPH_MDS_OP_FLUSH      = 0x01503
};

enum{
		CEPH_SESSION_REQUEST_OPEN,
		CEPH_SESSION_OPEN,
		CEPH_SESSION_REQUEST_CLOSE,
		CEPH_SESSION_CLOSE,
		CEPH_SESSION_REQUEST_RENEWCAPS,
		CEPH_SESSION_RENEWCAPS,
		CEPH_SESSION_STALE,
		CEPH_SESSION_RECALL_STATE,
		CEPH_SESSION_FLUSHMSG,
		CEPH_SESSION_FLUSHMSG_ACK,
		CEPH_SESSION_FORCE_RO,
};


struct ceph_entity_name {
		u_int8 type;      /* CEPH_ENTITY_TYPE_* */
		u_int64 num;
}__attribute__((packed));
//CEPH_ENTITY_TYPE:
#define CEPH_ENTITY_TYPE_MON    0x01
#define CEPH_ENTITY_TYPE_MDS    0x02
#define CEPH_ENTITY_TYPE_OSD    0x04
#define CEPH_ENTITY_TYPE_CLIENT 0x08
#define CEPH_ENTITY_TYPE_AUTH   0x20

#define CEPH_ENTITY_TYPE_ANY    0xFF

struct ceph_msg_header {
	        u_int64 seq;       // Sequence number.
			u_int64 tid;       // Transaction ID.
			u_int16 type;      // Message type (CEPH_MSG_* or MSG_*).
			u_int16 priority;  // Priority (higher is more important).
			u_int16 version;   // Version of message encoding.
			u_int32 front_len;  // The size of the front section.
			u_int32 middle_len; // The size of the middle section.
			u_int32 data_len;   // The size of the data section.
			u_int16 data_off;   // The way data should be aligned by the reciever.
			struct ceph_entity_name src; // Information about the sender.
			u_int16 compat_version; // Oldest compatible encoding version.
			u_int16 reserved;       // Unused.
			u_int32 crc;            // CRC of header.
}__attribute__((packed));

struct ceph_msg_footer {
	        u_int32 front_crc;  // Checksums of the various sections.
			u_int32 middle_crc; //
			u_int32 data_crc;   //
			u_int64 sig; // Crypographic signature.
			u_int8  flags;
}__attribute__((packed));

/*
struct ceph_msgr_msg {
	        u_int8 tag;
			struct ceph_msg_header header;
			u_int8 front [header.front_len];
			u_int8 middle[header.middle_len];
			u_int8 data  [.data_len];
			struct ceph_msg_footer footer;
};
*/
struct ceph_msgr_msg {
	        u_int8 tag;
			struct ceph_msg_header header;
			u_int8 *front;
			u_int8 *middle;
			u_int8 *data;
			struct ceph_msg_footer footer;
}__attribute__((packed));

struct ceph_msgr_ack {
	        u_int8  tag;
			u_int64 seq; // The sequence number of the message being acknowledged.
}__attribute__((packed));
struct ceph_msgr_keepalive {
			u_int8 tag;
			u_int8 data[]; // No data.
}__attribute__((packed));
		
struct ceph_msgr_keepalive2 {
			u_int8 tag;
			u_int64 timestamp;
}__attribute__((packed));

struct ceph_msgr_keepalive2_ack {
			u_int8 tag;
			u_int64 timestamp;
}__attribute__((packed));

union ceph_mds_request_args {
		struct {
				u_int32 mask;                 /* CEPH_CAP_* */
					} __attribute__ ((packed)) getattr;
		struct {
			u_int32 mode;
			u_int32 uid;
			u_int32 gid;
			//struct ceph_timespec mtime;
			//struct ceph_timespec atime;
			u_int64 size, old_size;       /* old_size needed by truncate */
			u_int32 mask;                 /* CEPH_SETATTR_* */
		} __attribute__ ((packed)) setattr;
		struct {
			u_int32 frag;                 /* which dir fragment */
			u_int32 max_entries;          /* how many dentries to grab */
			u_int32 max_bytes;
		} __attribute__ ((packed)) readdir;
		struct {
			u_int32 mode;
			u_int32 rdev;
		} __attribute__ ((packed)) mknod;
		struct {
			u_int32 mode;
		} __attribute__ ((packed)) mkdir;
		struct {
			
			u_int32 flags;
			u_int32 mode;
			u_int32 stripe_unit;          /* layout for newly created file */
			u_int32 stripe_count;         /* ... */
			u_int32 object_size;
			u_int32 pool;                 /* if >= 0 and CREATEPOOLID feature */
			u_int32 unused;               /* used to be preferred */
			u_int64 old_size;             /* if O_TRUNC */
		} __attribute__ ((packed)) open;
		struct {
			u_int32 flags;
		} __attribute__ ((packed)) setxattr;
		struct {
			//struct ceph_file_layout layout;
		}__attribute__ ((packed)) setlayout;
		struct {
			u_int8 rule; /* currently fcntl or flock */
			u_int8 type; /* shared, exclusive, remove*/
			u_int64 owner; /* who requests/holds the lock */
			u_int64 pid; /* process id requesting the lock */
			u_int64 start; /* initial location to lock */
			u_int64 length; /* num bytes to lock from start */
			u_int8 wait; /* will caller wait for lock to become available? */
		} __attribute__ ((packed)) filelock_change;
} __attribute__ ((packed));


struct ceph_mds_request_head {
		u_int64 oldest_client_tid;
		u_int32 mdsmap_epoch;           /* on client */
		u_int32 flags;                  /* CEPH_MDS_FLAG_* */
		u_int8 num_retry, num_fwd;       /* count retry, fwd attempts */
		u_int16 num_releases;           /* # include cap/lease release records */
		u_int32 op;                     /* mds op code */
		u_int32 caller_uid, caller_gid;
		u_int64 ino;                    /* use this ino for openc, mkdir, mknod,
										  etc. (if replaying) */
		union ceph_mds_request_args args;
} __attribute__((packed));


/* client reply */
struct ceph_mds_reply_head {
		u_int32 op;
		u_int32 result;
		u_int32 mdsmap_epoch;
		u_int8 safe;                     /* true if committed to disk */
		u_int8 is_dentry, is_target;     /* true if dentry, target inode records
										  are included with reply */
} __attribute__((packed));

/*
struct ceph_osd_op_request{
	u_int32 clinet_Icn;
	u_int32 OSD_MAP_EPOCH;
	u_int32 OSD_FLAG;
	u_int32 I_DO_NOT_CARE;
}__attribute__((packed));

struct ceph_osd_op_reply{
	u_int8 placement_group_id[17];
	u_int32 OSD_FLAG;
	u_int32 I_DO_NOT_CARE;
}__attribute__((packed));

*/
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
	__le32 osd_flag;	
	u_int64 send_time; //little endian
	//c_dissect_eversion
	u_int64 version_t;//little endian
	u_int32 epoch_t;
	char    object_locator[22];
	char    pg[17];
//    char    unknown[54];
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


#endif  //endif of define CEPH_H

#define CEPH_MESSAGE

// monitor internal
#define MSG_MON_SCRUB              64
#define MSG_MON_ELECTION           65
#define MSG_MON_PAXOS              66
#define MSG_MON_PROBE              67
#define MSG_MON_JOIN               68
#define MSG_MON_SYNC		   69

/* monitor <-> mon admin tool */
#define MSG_MON_COMMAND            50
#define MSG_MON_COMMAND_ACK        51
#define MSG_LOG                    52
#define MSG_LOGACK                 53
//#define MSG_MON_OBSERVE            54
//#define MSG_MON_OBSERVE_NOTIFY     55
#define MSG_CLASS                  56
#define MSG_CLASS_ACK              57

#define MSG_GETPOOLSTATS           58
#define MSG_GETPOOLSTATSREPLY      59

#define MSG_MON_GLOBAL_ID          60

// #define MSG_POOLOP                 49
// #define MSG_POOLOPREPLY            48

#define MSG_ROUTE                  47
#define MSG_FORWARD                46

#define MSG_PAXOS                  40


// osd internal
#define MSG_OSD_PING         70
#define MSG_OSD_BOOT         71
#define MSG_OSD_FAILURE      72
#define MSG_OSD_ALIVE        73
#define MSG_OSD_MARK_ME_DOWN 74

#define MSG_OSD_SUBOP        76
#define MSG_OSD_SUBOPREPLY   77

#define MSG_OSD_PGTEMP       78

#define MSG_OSD_PG_NOTIFY      80
#define MSG_OSD_PG_QUERY       81
#define MSG_OSD_PG_SUMMARY     82
#define MSG_OSD_PG_LOG         83
#define MSG_OSD_PG_REMOVE      84
#define MSG_OSD_PG_INFO        85
#define MSG_OSD_PG_TRIM        86

#define MSG_PGSTATS            87
#define MSG_PGSTATSACK         88

#define MSG_OSD_PG_CREATE      89
#define MSG_REMOVE_SNAPS       90

#define MSG_OSD_SCRUB          91
#define MSG_OSD_PG_MISSING     92
#define MSG_OSD_REP_SCRUB      93

#define MSG_OSD_PG_SCAN        94
#define MSG_OSD_PG_BACKFILL    95

#define MSG_COMMAND            97
#define MSG_COMMAND_REPLY      98

#define MSG_OSD_BACKFILL_RESERVE 99
#define MSG_OSD_RECOVERY_RESERVE 150

#define MSG_OSD_PG_PUSH        105
#define MSG_OSD_PG_PULL        106
#define MSG_OSD_PG_PUSH_REPLY  107

#define MSG_OSD_EC_WRITE       108
#define MSG_OSD_EC_WRITE_REPLY 109
#define MSG_OSD_EC_READ        110
#define MSG_OSD_EC_READ_REPLY  111

#define MSG_OSD_REPOP         112
#define MSG_OSD_REPOPREPLY    113


// *** MDS ***

#define MSG_MDS_BEACON             100  // to monitor
#define MSG_MDS_SLAVE_REQUEST      101
#define MSG_MDS_TABLE_REQUEST      102

                                // 150 already in use (MSG_OSD_RECOVERY_RESERVE)

#define MSG_MDS_RESOLVE            0x200
#define MSG_MDS_RESOLVEACK         0x201
#define MSG_MDS_CACHEREJOIN        0x202
#define MSG_MDS_DISCOVER           0x203
#define MSG_MDS_DISCOVERREPLY      0x204
#define MSG_MDS_INODEUPDATE        0x205
#define MSG_MDS_DIRUPDATE          0x206
#define MSG_MDS_CACHEEXPIRE        0x207
#define MSG_MDS_DENTRYUNLINK       0x208
#define MSG_MDS_FRAGMENTNOTIFY     0x209
#define MSG_MDS_OFFLOAD_TARGETS    0x20a
#define MSG_MDS_DENTRYLINK         0x20c
#define MSG_MDS_FINDINO            0x20d
#define MSG_MDS_FINDINOREPLY       0x20e
#define MSG_MDS_OPENINO            0x20f
#define MSG_MDS_OPENINOREPLY       0x210

#define MSG_MDS_LOCK               0x300
#define MSG_MDS_INODEFILECAPS      0x301

#define MSG_MDS_EXPORTDIRDISCOVER     0x449
#define MSG_MDS_EXPORTDIRDISCOVERACK  0x450
#define MSG_MDS_EXPORTDIRCANCEL       0x451
#define MSG_MDS_EXPORTDIRPREP         0x452
#define MSG_MDS_EXPORTDIRPREPACK      0x453
#define MSG_MDS_EXPORTDIRWARNING      0x454
#define MSG_MDS_EXPORTDIRWARNINGACK   0x455
#define MSG_MDS_EXPORTDIR             0x456
#define MSG_MDS_EXPORTDIRACK          0x457
#define MSG_MDS_EXPORTDIRNOTIFY       0x458
#define MSG_MDS_EXPORTDIRNOTIFYACK    0x459
#define MSG_MDS_EXPORTDIRFINISH       0x460

#define MSG_MDS_EXPORTCAPS            0x470
#define MSG_MDS_EXPORTCAPSACK         0x471
#define MSG_MDS_GATHERCAPS            0x472

#define MSG_MDS_HEARTBEAT          0x500  // for mds load balancer

// *** generic ***
#define MSG_TIMECHECK             0x600
#define MSG_MON_HEALTH            0x601

// *** Message::encode() crcflags bits ***
#define MSG_CRC_DATA           (1 << 0)
#define MSG_CRC_HEADER         (1 << 1)
#define MSG_CRC_ALL            (MSG_CRC_DATA | MSG_CRC_HEADER)

// Xio Testing
#define MSG_DATA_PING		  0x602

// Xio intends to define messages 0x603..0x606

// Special
#define MSG_NOP                   0x607

// ======================================================

// abstract Message class

// XioMessenger conditional trace flags
#define MSG_MAGIC_XIO          0x0002
#define MSG_MAGIC_TRACE_XCON   0x0004
#define MSG_MAGIC_TRACE_DTOR   0x0008
#define MSG_MAGIC_TRACE_HDR    0x0010
#define MSG_MAGIC_TRACE_XIO    0x0020
#define MSG_MAGIC_TRACE_XMSGR  0x0040
#define MSG_MAGIC_TRACE_CTR    0x0080

// XioMessenger diagnostic "ping pong" flag (resend msg when send completes)
#define MSG_MAGIC_REDUPE       0x0100

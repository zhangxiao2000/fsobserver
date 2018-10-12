

#include "parsepacket.h"


/*
 * app name/banner
 */
void
print_app_banner(void)
{

	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");

return;
}

/*
 * print help text
 */
void
print_app_usage(void)
{

	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

int handle_packets=0;
/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */

	/* declare pointers to packet headers */
	//const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const u_char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;

	//printf("\nPacket number %d:\n", count);
	count++;

	/* define ethernet header */
	//ethernet = (struct sniff_ethernet*)(packet);

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	//printf("       From: %s\n", inet_ntoa(ip->ip_src));
	//printf("         To: %s\n", inet_ntoa(ip->ip_dst));

	/* determine protocol */
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			//printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			//printf("   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			//printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			//printf("   Protocol: IP\n");
			return;
		default:
			//printf("   Protocol: unknown\n");
			return;
	}

	/*
	 *  OK, this packet is TCP.
	 */

	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	short src_port=ntohs(tcp->th_sport);
	short dst_port=ntohs(tcp->th_dport);

	//printf("   Src port: %d\n", ntohs(tcp->th_sport));
	//printf("   Dst port: %d\n", ntohs(tcp->th_dport));

	if ( !(IS_CEPH(dst_port ) ||  IS_CEPH(src_port)))
		{
			 //printf("Not a ceph packet.Src_port=%d,Dst_port=%d\n",src_port,dst_port);
       return ;
     }

  const struct timeval *ts = &(header->ts);
  char prefix[255];
  char srcip[20];
  char dstip[20];
  strcpy(srcip,inet_ntoa(ip->ip_src));
  strcpy(dstip,inet_ntoa(ip->ip_dst));

  sprintf(prefix,"\n%ld.%ld,%s,%d,=>,%s,%d",ts->tv_sec,ts->tv_usec,srcip,ntohs(tcp->th_sport),dstip,ntohs(tcp->th_dport));

	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	 handle_packets++;
	 dissect_ceph(prefix, payload, size_payload);
/*	if (size_payload > 0) {
		printf("   Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload);
	}*/

return;
}

	int get_ip_from_devname(char *eth, char *ipaddr)
{
 int sock_fd;
 struct  sockaddr_in my_addr;
 struct ifreq ifr;

 /**//* Get socket file descriptor */
 if ((sock_fd = socket(PF_INET, SOCK_DGRAM, 0)) == -1)
 {
  perror("socket");
  return -1;
 }

 /**//* Get IP Address */
 strncpy(ifr.ifr_name, eth, IF_NAMESIZE);
// ifr.ifr_name[IFNAMSIZ-1]='/0'; zx modi 20180502
 ifr.ifr_name[IFNAMSIZ-1]=0;

 if (ioctl(sock_fd, SIOCGIFADDR, &ifr) < 0)
 {
  printf(":No Such Device %s/n",eth);
  return -1;
 }

 memcpy(&my_addr, &ifr.ifr_addr, sizeof(my_addr));
 strcpy(ipaddr, inet_ntoa(my_addr.sin_addr));
 close(sock_fd);
 return 0;
}



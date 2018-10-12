//http://www.tcpdump.org/pcap.html   offical website

//introduce how to set up the environment of libpcap
//https://frankfzw.wordpress.com/2014/08/19/libpcap-on-ubuntu-install-libpcap/

//https://stackoverflow.com/questions/14264371/how-to-get-nic-details-from-a-c-program
//get detail infor from device name


#include <stdio.h>
#include <stdlib.h>
 #include <sys/ioctl.h>
  #include <net/if.h>
 #include <sys/types.h>
 #include <sys/socket.h>
 
       #include <netinet/in.h>
       #include <arpa/inet.h>
       
       #include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <string.h>
#include <errno.h>


	
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
 ifr.ifr_name[IFNAMSIZ-1]='/0';

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

int main()
{
	char ip[20];
	get_ip_from_devname("enp3s0",ip);
	printf("%s",ip);
}
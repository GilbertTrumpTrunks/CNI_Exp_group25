#include <pcap.h>
#include <Packet32.h>
#include <ntddndis.h>
#include "remote-ext.h"
#include <cstdlib>
#pragma comment(lib, "Packet")
#pragma comment(lib, "wpcap")
#pragma comment(lib, "WS2_32")
typedef struct ip_header {
	u_char ver_ihl; // Version (4 bits) + Internet header length(4 bits) 
		u_char tos; // Type of service
		u_short tlen; // Total length
		u_short identification; // Identification
		u_short flags_fo; // Flags (3 bits) + Fragment offset(13 bits) 
		u_char ttl; // Time to live
		u_char proto; // Protocol
		u_short crc; // Header checksum
		u_char saddr[4]; // Source address
		u_char daddr[4]; // Destination address
		u_int op_pad; // Option + Padding
} ip_header;
typedef struct mac_header {
	u_char dest_addr[6];
	u_char src_addr[6];
	u_char type[2];
} mac_header;
void packet_handler(u_char *param, const struct pcap_pkthdr
	*header, const u_char *pkt_data);
int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	u_int netmask;
	struct bpf_program fcode;
	char errbuf[PCAP_ERRBUF_SIZE];
	/* Retrieve the device list */
	if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &alldevs,errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs: %s\n",errbuf);
		exit(1);
	}
	/* Print the list */
	for (d = alldevs; d; d = d->next) {
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	if (i == 0) {
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
			return -1;
	}
	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);
	if (inum < 1 || inum > i) {
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);
	/* Open the adapter */

	if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL) {
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
			pcap_freealldevs(alldevs);
		return -1;
	}
	if (pcap_datalink(adhandle) != DLT_EN10MB) {
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
			pcap_freealldevs(alldevs);
		return -1;
	}
	if (d->addresses != NULL)
		netmask = ((struct sockaddr_in *)(d->addresses ->netmask))->sin_addr.S_un.S_addr;
	else
		netmask = 0xffffff;
	//compile the filter
	if (pcap_compile(adhandle, &fcode, "ip", 1, netmask) <0) {
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
			pcap_freealldevs(alldevs);
		return -1;
	}
	//set the filter
	if (pcap_setfilter(adhandle, &fcode)<0) {
		fprintf(stderr, "\nError setting the filter.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("\nlistening on %s...\n", d->description);
	/* At this point, we don't need any more the device list.
	Free it */
	pcap_freealldevs(alldevs);
	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
	system("pause");
	return 0;
}
void packet_handler(u_char *param, const struct pcap_pkthdr
	*header, const u_char *pkt_data)
{
	mac_header *mh;
	ip_header *ih;
	time_t local_tv_sec;
	struct tm time;
	char timestr[16];
	

	
	/* 将时间戳转换成可识别的格式 */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&time, &local_tv_sec);
	printf("%d/%d/%d ", time.tm_year + 1900, time.tm_mon + 1, time.tm_mday);
	printf("%d:%d:%d,",time.tm_hour,time.tm_min,time.tm_sec);
	
	mh = (mac_header*)pkt_data;

	ih = (ip_header *)(pkt_data + sizeof(mac_header)); //length of ethernet header

	
	for (int i = 0; i<5; i++) {
		printf("%02X-", mh->dest_addr[i]);
	}
	printf("%02X,", mh->dest_addr[5]);
	for (int i = 0; i<3; i++) {
		printf("%d.", ih->daddr[i]);	
	}
	printf("%d,", ih->daddr[3]);
	
	for (int i = 0; i<5; i++) {
		printf("%02X-", mh->src_addr[i]);
	}
	printf("%02X,", mh->src_addr[5]);

	for (int i = 0; i<3; i++) {
		printf("%d.", ih->saddr[i]);		
	}
	printf("%d,", ih->saddr[3]);
	printf("%d\n", header->len);
	printf("\n");
}
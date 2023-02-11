#include "packet.h"
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include "packet_tools.h"

void get_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	u_int size_ip;
	u_int size_tcp;
    u_int total_size;
	int proto;
	/* ethernet headers are always exactly 14 bytes */
	
	printf("\n************************************************\n");
	printf("************* Recieving new packet *************\n");
	printf("************************************************\n");

	if (!get_ethernet(packet))
		return;
	
	proto = get_ip(packet, &size_ip, &total_size);
	
	if (!proto)
		return;

	switch (proto)
	{
		case ICMP: 
            fprintf(stdout, "Proto: ICMP\n");
			break;
		case TCP:
            fprintf(stdout, "Proto: TCP\n");
			get_tcp(packet, &size_ip, &size_tcp, total_size);
			return;
		case UDP: 
            fprintf(stdout, "Proto: UDP\n");
			get_udp(packet, &size_ip, total_size);
			return;
		default:
			break;
	}
	
}

int get_ethernet(const u_char *packet){	
	const struct ethernet_hdr *ethernet; /* The ethernet header */	
	ethernet = (struct ethernet_hdr*)(packet);

	for(int i = 0; i < ETHER_ADDR_LEN; i++)
	{
		fprintf(stdout, "%.2X ", ethernet->ether_shost[i]);
	}
	fprintf(stdout, " -> ");
	for(int i = 0; i < ETHER_ADDR_LEN; i++)
	{
		fprintf(stdout, "%.2X ", ethernet->ether_dhost[i]);
	}
	fprintf(stdout, "\n");
	return 1;
}

int get_ip(const u_char *packet, u_int *size_ip, u_int *total_size){
	const struct ip_hdr *ip; /* The IP header */
	ip = (struct ip_hdr*)(packet + SIZE_ETHERNET);
	*size_ip = IP_HL(ip)*4;
    *total_size = ip->ip_len;
	if (*size_ip < 20) {
		return 0;
	}
	
	fprintf(stdout, "%s -> ", inet_ntoa(ip->ip_src));
	fprintf(stdout, "%s\n", inet_ntoa(ip->ip_dst));
		
	return ip->ip_p;
}

int get_tcp(const u_char *packet, u_int *size_ip ,u_int *size_tcp, u_int total_size){
	const struct tcp_hdr *tcp; 
	const char *payload; 
	char* flags;

	tcp = (struct tcp_hdr*)(packet + SIZE_ETHERNET + *size_ip);
	*size_tcp = TH_OFF(tcp)*4;

	if (*size_tcp < 20) {
		return 0;
	}

	fprintf(stdout, "%d -> %d \n", ntohs(tcp->th_sport), ntohs(tcp->th_dport));

	flags = get_tcp_flags(tcp->th_flags);

	fprintf(stdout, "Seq: %" PRIu32 " ; Ack: %" PRIu32 "\n", ntohl(tcp->th_seq), ntohl(tcp->th_ack));
	fprintf(stdout, "Flags: %s \n", flags);

	payload = (u_char *)(packet + SIZE_ETHERNET + *size_ip + *size_tcp);
    parse_payload(payload, total_size - *size_ip - *size_tcp);
	free(flags); 
	return 1;
}

int get_udp(const u_char *packet, u_int *size_ip, u_int total_size){
	const struct udp_hdr *udp; 
	const char *payload; 

	udp = (struct udp_hdr*)(packet + SIZE_ETHERNET + *size_ip);

	fprintf(stdout, "%d -> %d\n", ntohs(udp->uh_sport), ntohs(udp->uh_dport));
	
	payload = (u_char *)(packet + SIZE_ETHERNET + *size_ip + UDP_LEN);

    parse_payload(payload, total_size - *size_ip - UDP_LEN);

	return 1;
}

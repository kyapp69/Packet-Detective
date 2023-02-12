#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "packet_sniffer.h"

int do_sniff(char* filter, char* name){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *dev;
    pcap_t *handle;			/* Session handle */
	struct bpf_program fp;		/* The compiled filter */
	char* filter_exp = filter;	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	char * dev_name;

	if(name != NULL)
		dev_name = name;
	else {
		fprintf(stdout, "Interface not supplied. Trying default interface..\n");
		pcap_findalldevs(&dev, errbuf);

		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return -1;
		}
		dev_name = dev->name;
	}
	printf("Starting sniffer on device: %s\n", dev_name);
	
    handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
	    fprintf(stderr, "Couldn't open device %s: %s\n", dev_name, errbuf);
	    return -1;
    }

	if (filter){
	    /* Compile and apply the filter */
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return -1;
		}
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return -1;
		}
	}

	pcap_loop(handle, -1, get_packet, NULL);

	/* Close the session */
	pcap_close(handle);
	return 1;
 }
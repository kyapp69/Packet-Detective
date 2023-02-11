#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "packet.h"

int main(int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *dev;
    pcap_t *handle;			/* Session handle */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 53";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */


	pcap_findalldevs(&dev, errbuf);
	
    if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(-1);
	}
	printf("Device: %s\n", dev->name);

    handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
	    fprintf(stderr, "Couldn't open device %s: %s\n", dev->name, errbuf);
	    return(2);
    }

    /* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

//	pcap_set_timeout(handle, 100);
	pcap_loop(handle, -1, get_packet, NULL);

	/* And close the session */
	pcap_close(handle);

	return(0);
}

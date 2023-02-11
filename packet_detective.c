#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "packet_sniffer.h"


int main(int argc, char **argv) {
		
	printf("%s" , logo);
	char filter[256];
	printf("Set your filter or enter to continue without - \n");
	scanf("%10[0-9a-zA-Z ]", filter);
	do_sniff(filter);
	return(0);
}

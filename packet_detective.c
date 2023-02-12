#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "packet_sniffer.h"


int main(int argc, char **argv) {
	char* name = NULL;
	printf("%s" , logo);
	char filter[256] = {0};
	printf("Set your filter or enter to continue without - \n");
	scanf("%100[0-9a-zA-Z.-)(|& ]", filter);
	
	if(argc > 1)
		name = argv[1];
	do_sniff(filter, name);
	return(0);
}

#include "packet.h"
#include <string.h>
#include <stdlib.h>

char* get_tcp_flags(u_char flags){
	int flag_size = 4;
	
	char* all_flags = calloc(7 * flag_size, sizeof(char));
	if (flags & TH_FIN)
		strncat(all_flags, "FIN ", flag_size);
	if (flags & TH_SYN)
		strncat(all_flags, "SYN ", flag_size);	
	if (flags & TH_RST)
		strncat(all_flags, "RST ", flag_size);
	if (flags & TH_PUSH)
		strncat(all_flags, "PSH ", flag_size);
	if (flags & TH_ACK)
		strncat(all_flags, "ACK ", flag_size);
	if (flags & TH_URG)
		strncat(all_flags, "URG ", flag_size);
	if (flags & TH_ECE)
		strncat(all_flags, "ECE ", flag_size);
	if (flags & TH_CWR)
		strncat(all_flags, "CWR ", flag_size);
	return all_flags;
}

void parse_payload(const u_char * payload, u_int size)
{
    for(int i = 0; i < size; i++)
    {
        if(size - i > 5 && (strncmp(payload + i, "name=", 5) == 0 ||
                            strncmp(payload + i, "user=", 5) == 0))
        {
            fprintf(stdout, "\n************************************************\n");
            fprintf(stdout, "************************************************\n");
            fprintf(stdout, "********** Possible login details !! ***********\n");
            fprintf(stdout, "************************************************\n");
            fprintf(stdout, "************************************************\n");    
        }
        if (payload[i] == '\n' || payload[i] == '\0' || (payload[i] >= 32 && payload[i] < 127)){
            fprintf(stdout, "%c" , payload[i]);
        }
    }
}

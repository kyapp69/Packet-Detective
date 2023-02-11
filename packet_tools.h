#ifndef _PKT_TOOLS_
#define _PKT_TOOLS_

#include "packet_tools.h"

void parse_payload(const u_char * payload, u_int size);
char* get_tcp_flags(u_char flags);

#endif
#ifndef _PKT_SNIFFER
#define _PKT_SNIFFER

#include "packet.h"

#define logo "\n"\
		"______          _        _    ______     _            _   _           \n"\
		"| ___ \\        | |      | |   |  _  \\   | |          | | (_)          \n"\
		"| |_/ __ _  ___| | _____| |_  | | | |___| |_ ___  ___| |_ ___   _____ \n"\
		"|  __/ _` |/ __| |/ / _ | __| | | | / _ | __/ _ \\/ __| __| \\ \\ / / _ \\\n"\
		"| | | (_| | (__|   |  __| |_  | |/ |  __| ||  __| (__| |_| |\\ V |  __/\n"\
		"\\_|  \\__,_|\\___|_|\\_\\___|\\__| |___/ \\___|\\__\\___|\\___|\\__|_| \\_/ \\___|\n\n"\


int do_sniff(char* filter);

#endif
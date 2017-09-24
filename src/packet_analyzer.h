#ifndef __PACKET_ANALYZER_H__
#define __PACKET_ANALYZER_H__

#include <stdlib.h>

struct arguments {
    const char *protocol;
};

int get_arguments(int argc, char *argv[], struct arguments *args);
int packet_analyzer(struct arguments *args);
int print_tcp_packet(const unsigned char *packet, ssize_t packet_size);

#endif /* __PACKET_ANALYZER_H__ */

#ifndef __PACKET_ANALYZER_H__
#define __PACKET_ANALYZER_H__


#include <stdbool.h>


struct arguments {
    const char *protocol;
    const char *output_file;
    bool debug_mode;
};


void get_arguments(int argc, char *argv[], struct arguments *args);
int packet_analyzer(struct arguments *args);
int tcp_dump_packet(const unsigned char *packet);
int udp_dump_packet(const unsigned char *packet);


#endif /* __PACKET_ANALYZER_H__ */

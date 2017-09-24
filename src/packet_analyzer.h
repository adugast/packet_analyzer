#ifndef __PACKET_ANALYZER_H__
#define __PACKET_ANALYZER_H__

#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>

struct arguments {
    const char *protocol;
    const char *output_file;
    bool debug_mode;
};

int get_arguments(int argc, char *argv[], struct arguments *args);
int packet_analyzer(struct arguments *args);
int print_tcp_packet(const unsigned char *packet, ssize_t packet_size);
void set_signal(int signal);

#endif /* __PACKET_ANALYZER_H__ */

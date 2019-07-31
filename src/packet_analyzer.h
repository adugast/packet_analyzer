#ifndef __PACKET_ANALYZER_H__
#define __PACKET_ANALYZER_H__


#include <stdbool.h>

#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

struct arguments {
    const char *protocol;
    const char *output_file;
    bool debug_mode;
};


void get_arguments(int argc, char *argv[], struct arguments *args);
int packet_analyzer(struct arguments *args);


void tcp_dump_packet(const unsigned char *packet);
void udp_dump_packet(const unsigned char *packet);


// helper
const struct ethhdr *get_ethhdr(const unsigned char *packet);
const struct iphdr *get_iphdr(const unsigned char *packet);


#endif /* __PACKET_ANALYZER_H__ */

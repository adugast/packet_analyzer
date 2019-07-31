#include <stdio.h>

#include "packet_analyzer.h"


static const struct udphdr *get_udphdr(const unsigned char *packet)
{
    const struct iphdr *ip = get_iphdr(packet);
    return (struct udphdr *)(packet + ip->ihl*4 + sizeof(struct ethhdr));
}


void udp_dump_packet(const unsigned char *packet)
{
    const struct udphdr *udph = get_udphdr(packet);

    printf("UDP Header\n");
    printf("\t|-source:%u\n", ntohs(udph->source));
    printf("\t|-destination:%u\n", ntohs(udph->dest));
    printf("\t|-len:%u\n", ntohs(udph->len));
    printf("\t|-checksum:%u\n", ntohs(udph->check));
}


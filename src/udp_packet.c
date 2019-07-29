#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/udp.h>


void udp_dump_packet(const unsigned char *packet)
{
    struct udphdr *udph = (struct udphdr *)packet;

    printf("UDP Header\n");
    printf("-source:%u\n", ntohs(udph->source));
    printf("-destination:%u\n", ntohs(udph->dest));
    printf("-len:%u\n", ntohs(udph->len));
    printf("-checksum:%u\n", ntohs(udph->check));
}


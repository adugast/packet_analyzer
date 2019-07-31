#include <stdio.h>

#include "packet_analyzer.h"


static const struct tcphdr *get_tcphdr(const unsigned char *packet)
{
    const struct iphdr *ip = get_iphdr(packet);
    return (struct tcphdr *)(packet + ip->ihl*4 + sizeof(struct ethhdr));
}


void tcp_dump_packet(const unsigned char *packet)
{
    const struct tcphdr *tcph = get_tcphdr(packet);

    printf("TCP Header\n");
    printf("\t|-source:%u\n", ntohs(tcph->source));
    printf("\t|-destination:%u\n", ntohs(tcph->dest));
    printf("\t|-sequence number:%u\n", ntohl(tcph->seq));
    printf("\t|-acknowledge number:%u\n", ntohl(tcph->ack_seq));
    printf("\t|-data offset:%d bytes\n", tcph->doff * 4);
    printf("\t|-finish flag:%d\n", tcph->fin);
    printf("\t|-synchronize flag:%d\n", tcph->syn);
    printf("\t|-reset flag:%d\n", tcph->rst);
    printf("\t|-push flag:%d\n", tcph->psh);
    printf("\t|-acknowledgement flag:%d\n", tcph->ack);
    printf("\t|-urgent flag:%d\n", tcph->urg);
    printf("\t|-window size:%d\n", ntohs(tcph->window));
    printf("\t|-checksum:%d\n", ntohs(tcph->check));
    printf("\t|-urgent pointer:%d\n", ntohs(tcph->urg_ptr));
}


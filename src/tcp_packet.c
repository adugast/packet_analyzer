#include <stdio.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

int print_tcp_packet(const unsigned char *packet, ssize_t packet_size)
{
    struct tcphdr *tcph = (struct tcphdr *)packet;

    printf("TCP Header\n");
    printf("-Source Port:%u\n", ntohs(tcph->source));
    printf("-Destination Port:%u\n", ntohs(tcph->dest));
    printf("-Sequence Number:%u\n", ntohl(tcph->seq));
    printf("-Acknowledge Number:%u\n", ntohl(tcph->ack_seq));
    printf("-Header Length:%d DWORDS or %d BYTES\n", (unsigned int)tcph->doff, (unsigned int)tcph->doff * 4);
    printf("-Urgent Flag:%d\n", (unsigned int)tcph->urg);
    printf("-Acknowledgement Flag:%d\n", (unsigned int)tcph->ack);
    printf("-Push Flag:%d\n", (unsigned int)tcph->psh);
    printf("-Reset Flag:%d\n", (unsigned int)tcph->rst);
    printf("-Synchronise Flag:%d\n", (unsigned int)tcph->syn);
    printf("-Finish Flag:%d\n", (unsigned int)tcph->fin);
    printf("-Window:%d\n", ntohs(tcph->window));
    printf("-Checksum:%d\n", ntohs(tcph->check));
    printf("-Urgent Pointer:%d\n", tcph->urg_ptr);

    return 0;
}

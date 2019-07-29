#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>


void tcp_dump_packet(const unsigned char *packet)
{
    struct tcphdr *tcph = (struct tcphdr *)packet;

    printf("TCP Header\n");
    printf("-source:%u\n", ntohs(tcph->source));
    printf("-destination:%u\n", ntohs(tcph->dest));
    printf("-sequence number:%u\n", ntohl(tcph->seq));
    printf("-acknowledge number:%u\n", ntohl(tcph->ack_seq));
    printf("-data offset:%d bytes\n", (unsigned int)tcph->doff * 4);
    printf("-finish flag:%d\n", (unsigned int)tcph->fin);
    printf("-synchronize flag:%d\n", (unsigned int)tcph->syn);
    printf("-reset flag:%d\n", (unsigned int)tcph->rst);
    printf("-push flag:%d\n", (unsigned int)tcph->psh);
    printf("-acknowledgement flag:%d\n", (unsigned int)tcph->ack);
    printf("-urgent flag:%d\n", (unsigned int)tcph->urg);
    printf("-window size:%d\n", ntohs(tcph->window));
    printf("-checksum:%d\n", ntohs(tcph->check));
    printf("-urgent pointer:%d\n", ntohs(tcph->urg_ptr));
}


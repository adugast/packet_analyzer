#include <stdio.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

int print_tcp_packet(const unsigned char *packet)
{
    struct tcphdr *tcph = (struct tcphdr *)packet;

    printf("TCP Header\n");
    printf("-source port:%u\n", ntohs(tcph->source));
    printf("-destination Port:%u\n", ntohs(tcph->dest));
    printf("-sequence number:%u\n", ntohl(tcph->seq));
    printf("-acknowledge number:%u\n", ntohl(tcph->ack_seq));
    printf("-data offset:%d bytes\n", (unsigned int)tcph->doff * 4);
    printf("-urgent flag:%d\n", (unsigned int)tcph->urg);
    printf("-acknowledgement flag:%d\n", (unsigned int)tcph->ack);
    printf("-push flag:%d\n", (unsigned int)tcph->psh);
    printf("-reset flag:%d\n", (unsigned int)tcph->rst);
    printf("-synchronise flag:%d\n", (unsigned int)tcph->syn);
    printf("-finish flag:%d\n", (unsigned int)tcph->fin);
    printf("-window size:%d\n", ntohs(tcph->window));
    printf("-checksum:%d\n", ntohs(tcph->check));
    printf("-urgent pointer:%d\n", tcph->urg_ptr);

    return 0;
}

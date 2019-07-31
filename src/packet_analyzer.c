#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <poll.h>

#include "packet_analyzer.h"


// https://opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/
static int sock_raw_save_g = 0;
static void signal_handler(__attribute__((unused)) int signum)
{
    close(sock_raw_save_g);
    exit(EXIT_SUCCESS);
}


const struct ethhdr *get_ethhdr(const unsigned char *packet)
{
    return (const struct ethhdr *)(packet);
}


const struct iphdr *get_iphdr(const unsigned char *packet)
{
    return (const struct iphdr *)(packet + sizeof(struct ethhdr));
}


static void dump_ethernet_header(const struct ethhdr *eth)
{
    printf("Ethernet Header\n");
    printf("\t|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
            eth->h_source[0], eth->h_source[1], eth->h_source[2],
            eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("\t|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
            eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
            eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    printf("\t|-Protocol : %d\n\n", eth->h_proto);
}


static void dump_ip_header(const struct iphdr *ip)
{
    struct in_addr in_saddr = { .s_addr = ip->saddr };
    struct in_addr in_daddr = { .s_addr = ip->daddr };

    printf("IP Header\n");
    printf("\t|-Version : %d\n", (unsigned int)ip->version);
    printf("\t|-Internet Header Length : %d DWORDS or %d Bytes\n",
            (unsigned int)ip->ihl, ((unsigned int)(ip->ihl))*4);
    printf("\t|-Type Of Service : %d\n", (unsigned int)ip->tos);
    printf("\t|-Total Length : %d Bytes\n", ntohs(ip->tot_len));
    printf("\t|-Identification : %d\n", ntohs(ip->id));
    printf("\t|-Time To Live : %d\n", (unsigned int)ip->ttl);
    printf("\t|-Protocol : %d\n", (unsigned int)ip->protocol);
    printf("\t|-Header Checksum : %d\n", ntohs(ip->check));
    printf("\t|-Source IP : %s\n", inet_ntoa(in_saddr));
    printf("\t|-Destination IP : %s\n\n", inet_ntoa(in_daddr));
}


// protocol number read from /etc/protocols
static int process_packets(const unsigned char *network_packet)
{
    const struct ethhdr *eth = get_ethhdr(network_packet);
    const struct iphdr *ip = get_iphdr(network_packet);

    int protocol = ip->protocol;
    switch (protocol) {
        case IPPROTO_TCP: printf("\n********************TCP Packet********************\n"); break;
        case IPPROTO_UDP: printf("\n********************UDP Packet********************\n"); break;
        default: printf("\n********************UNKNOWN Packet********************\n"); break;
    }

    dump_ethernet_header(eth);
    dump_ip_header(ip);

    switch (protocol) {
        case IPPROTO_TCP: tcp_dump_packet(network_packet); break;
        case IPPROTO_UDP: udp_dump_packet(network_packet); break;
    }

    return 0;
}


#define PACKET_BUFFER_SIZE 2048
static int read_socket(int socket)
{
    unsigned char packet[PACKET_BUFFER_SIZE] = {0};
    ssize_t packet_size = recvfrom(socket, packet, PACKET_BUFFER_SIZE, 0, NULL, NULL);
    if (packet_size == -1) {
        printf("recvfrom(%d):failed\n", socket);
        return -1;
    }

    process_packets(packet);

    // Just a sleep to limit the speed of the loop
    // Can be remove or modified without impact
    sleep(1);

    return 0;
}


static int poll_socket(int socket)
{
    struct pollfd pfd = {
        .fd = socket,
        .events = POLLIN,
    };

    while (1) {
        switch (poll(&pfd, 1, -1)) {
            case -1: perror("poll"); break;
            case 0: printf("Poll call timed out or no file descriptor ready\n"); break;
            default: (pfd.revents & POLLIN) ? read_socket(socket) : 0;
        }
    }

    return 0;
}


int packet_analyzer(struct arguments *args)
{
    struct sigaction action = {
        .sa_handler = signal_handler
    };

    if (sigaction(SIGINT, &action, NULL) == -1) {
        perror("sigaction");
        return -1;
    }

    struct protoent *protocol = getprotobyname(args->protocol);
    if (!protocol) {
        fprintf(stderr, "getprotobyname(%s):failed\n", args->protocol);
        return -1;
    }

    int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw == -1) {
        fprintf(stderr, "socket(%d):%s\n", sock_raw, strerror(errno));
        return -1;
    }
    sock_raw_save_g = sock_raw;

    poll_socket(sock_raw);

    close(sock_raw);

    return 0;
}


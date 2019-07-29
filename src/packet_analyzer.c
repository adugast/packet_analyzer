#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include <poll.h>

#include "packet_analyzer.h"


// https://opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/
static int sock_raw_save_g = 0;
static void signal_handler(__attribute__((unused)) int signum)
{
    close(sock_raw_save_g);
    exit(EXIT_SUCCESS);
}


// protocol number read from /etc/protocols
static int process_packet_protocols(const unsigned char *network_packet)
{
    struct iphdr *ip = (struct iphdr *)(network_packet + sizeof(struct ethhdr));

    switch (ip->protocol) {
        case 6: tcp_dump_packet(network_packet); break;
        case 17: udp_dump_packet(network_packet); break;
    }

    return 0;
}


static void dump_ethernet_header(const unsigned char *network_packet)
{
    struct ethhdr *eth = (struct ethhdr *)(network_packet);

    printf("Ethernet Header\n");
    printf("-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
            eth->h_source[0], eth->h_source[1], eth->h_source[2],
            eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
            eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
            eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    printf("-Protocol : %d\n", eth->h_proto);
}


static void dump_ip_header(const unsigned char *network_packet)
{
    struct iphdr *ip = (struct iphdr *)(network_packet + sizeof(struct ethhdr));
    struct in_addr in_saddr = { .s_addr = ip->saddr };
    struct in_addr in_daddr = { .s_addr = ip->daddr };

    printf("Ip Header\n");
    printf("-Version : %d\n", (unsigned int)ip->version);
    printf("-Internet Header Length : %d DWORDS or %d Bytes\n",
            (unsigned int)ip->ihl, ((unsigned int)(ip->ihl))*4);
    printf("-Type Of Service : %d\n", (unsigned int)ip->tos);
    printf("-Total Length : %d Bytes\n", ntohs(ip->tot_len));
    printf("-Identification : %d\n", ntohs(ip->id));
    printf("-Time To Live : %d\n", (unsigned int)ip->ttl);
    printf("-Protocol : %d\n", (unsigned int)ip->protocol);
    printf("-Header Checksum : %d\n", ntohs(ip->check));
    printf("-Source IP : %s\n", inet_ntoa(in_saddr));
    printf("-Destination IP : %s\n", inet_ntoa(in_daddr));
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

    dump_ethernet_header(packet);
    dump_ip_header(packet);
    process_packet_protocols(packet);

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


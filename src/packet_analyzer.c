#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include <netdb.h>

#include "packet_analyzer.h"

#define PACKET_BUFFER_SIZE 512

int sock_raw = 0;

void sighandler(int signal)
{
    if (signal == 2) {
        printf("\nSignal SIGINT %d catched.\n", signal);
    } else {
        printf("\nSignal %d catched but not interpreted.\n", signal);
    }

    if (close(sock_raw) == 0) {
        printf("close(%d):%s\n", sock_raw, strerror(errno));
    } else {
        printf("close(%d):%s\n", sock_raw, strerror(errno));
    }

    exit(EXIT_SUCCESS);
}

int process_packet(const unsigned char *packet, ssize_t packet_size)
{
    struct iphdr *ip_header = (struct iphdr *)packet;

    printf("ip_header->protocol[%d]\n", ip_header->protocol);
    switch (ip_header->protocol) {
        case 6: print_tcp_packet(packet, packet_size); break;
        default: break;
    }

    return 0;
}

int sniffer(int socket)
{
    unsigned char packet[PACKET_BUFFER_SIZE] = {0};
    ssize_t packet_size = 0;

//    struct sockaddr src_addr;
//    socklen_t addrlen = sizeof(src_addr);

    unsigned int time_sec = 0;
    while (time_sec < 10) {

        packet_size = recvfrom(socket, packet, PACKET_BUFFER_SIZE, 0, NULL/*&src_addr*/, 0/*&addrlen*/);
        if (packet_size == -1) {
            printf("recvfrom(%d):failed\n", socket);
        }

        printf("packet_size[%zd]\n", packet_size);

        //process the packet
        process_packet(packet, packet_size);

        sleep(1);
        time_sec++;
    }

    return 0;
}

int packet_analyzer(struct arguments *args)
{
    //set ctrl+c handler to exit properly
    signal(SIGINT, sighandler);

    //get protocol number
    struct protoent *protocol = NULL;

    protocol = getprotobyname(args->protocol);
    if (protocol == NULL) {
        printf("getprotobyname(%s):failed\n", args->protocol);
    } else {
        printf("getprotobyname(%s):success\n", args->protocol);
        printf("%s:p_name[%s]:p_proto[%d]\n",
            args->protocol, protocol->p_name, protocol->p_proto);
    }

    //for every packet every proto: sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_raw == -1) {
        printf("socket(%d):%s\n", sock_raw, strerror(errno));
    } else {
        printf("socket(%d):%s\n", sock_raw, strerror(errno));
    }

    sniffer(sock_raw);

    if (close(sock_raw) == 0) {
        printf("close(%d):%s\n", sock_raw, strerror(errno));
    } else {
        printf("close(%d):%s\n", sock_raw, strerror(errno));
    }

    return 0;
}

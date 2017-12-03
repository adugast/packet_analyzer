#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>

#include "packet_analyzer.h"


#define PACKET_BUFFER_SIZE 512


static int sock_raw = 0;


static void signal_handler(__attribute__((unused)) int signum)
{
    close(sock_raw);
    exit(EXIT_SUCCESS);
}


int process_packet(const unsigned char *packet)
{
    struct iphdr *ip_header = (struct iphdr *)packet;

    printf("ip_header->protocol[%d]\n", ip_header->protocol);
    switch (ip_header->protocol) {
        case 6: print_tcp_packet(packet); break;
        // TODO add case for UDP
        default: break;
    }

    return 0;
}


int sniffer(int socket)
{
    unsigned char packet[PACKET_BUFFER_SIZE] = {0};
    ssize_t packet_size = 0;
    unsigned int time_sec = 0;

    while (time_sec < 10) {

        packet_size = recvfrom(socket, packet, PACKET_BUFFER_SIZE, 0, NULL, NULL);
        if (packet_size == -1) {
            printf("recvfrom(%d):failed\n", socket);
        }

        printf("packet_size[%zd]\n", packet_size);

        //process the packet
        process_packet(packet);

        sleep(1);
        time_sec++;
    }

    return 0;
}


int packet_analyzer(struct arguments *args)
{
    int ret = -1;

    // set signal handler to exit properly
    struct sigaction action = {0};

    action.sa_handler = signal_handler;
    ret = sigaction(SIGINT, &action, NULL);
    if (ret == -1) {
        perror("sigaction");
        return -1;
    }

    // get protocol number
    struct protoent *protocol = NULL;

    protocol = getprotobyname(args->protocol);
    if (protocol == NULL) {
        fprintf(stderr, "getprotobyname(%s):failed\n", args->protocol);
        return -1;
    }

    printf("getprotobyname(%s):success\n", args->protocol);
    printf("%s:p_name[%s]:p_proto[%d]\n", args->protocol, protocol->p_name, protocol->p_proto);

    // for every packet every proto: sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_raw == -1) {
        fprintf(stderr, "socket(%d):%s\n", sock_raw, strerror(errno));
        return -1;
    }

    sniffer(sock_raw);

    close(sock_raw);

    return 0;
}

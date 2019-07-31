#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "packet_analyzer.h"


static void print_help(const char *binary_name)
{
    printf("Usage: %s [ -p protocol ] [ -o output_file ] [ -d ]\n", binary_name);
    printf("-p, --protocol [protocol]       : available protocol:tcp, udp\n");
    printf("-o, --output [output_file]      : log info in output_file\n");
    printf("-d, --debug                     : activate the debug mode\n");
    printf("-v, --version                   : Show version information\n");
    printf("-h, --help                      : Display this help and exit\n");
}


static void print_version()
{
    printf("packet_analyzer, version \?.\?.\?\?(\?)-release\n");
    printf("Linux packet analyzer - Wireshark mimic\n");
    printf("Copyright (C) 2019 pestbuns\n");
    printf("MIT License: <https://opensource.org/licenses/MIT>\n");
    printf("Git Repository: <https://github.com/pestbuns/packet_analyzer>\n");
    printf("\n");
    printf("This is free software; you are free to change and redistribute it.\n");
    printf("There is NO WARRANTY, to the extent permitted by law.\n");
}


static void set_default_config(struct arguments *args)
{
    args->protocol = "tcp";
    args->output_file = "";
    args->debug_mode = false;
}


void get_arguments(int argc, char *argv[], struct arguments *args)
{
    set_default_config(args);

    static struct option long_options[] = {
        {"protocol",    required_argument, 0, 'p'},
        {"output",      required_argument, 0, 'o'},
        {"debug",       no_argument, 0, 'd'},
        {"version",     no_argument, 0, 'v'},
        {"help",        no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    const char *option_string = "p:o:dvh";
    int c = 0;
    while ((c = getopt_long(argc, argv, option_string, long_options, NULL)) != -1) {
        switch (c) {
            case 'p': args->protocol = optarg; break;
            case 'o': args->output_file = optarg; break;
            case 'd': args->debug_mode = true; break;
            case 'v': print_version(); exit(EXIT_SUCCESS);
            case 'h': print_help(argv[0]); exit(EXIT_SUCCESS);
            default: print_help(argv[0]); exit(EXIT_SUCCESS);
        }
    }
}


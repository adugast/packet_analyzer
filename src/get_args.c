#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "packet_analyzer.h"

static void print_usage(const char *binary_name)
{
    printf("Usage: %s [ -p protocol ] [ -o output_file ] [ -d ]\n", binary_name);
}

static void print_help(const char *binary_name)
{
    printf("Usage: %s [ -p protocol ] [ -o output_file ] [ -d ]\n", binary_name);
    printf("-p [protocol] : Available protocol:TCP, UDP\n");
    printf("-o [output_file] : Log info in output_file\n");
    printf("-d : Activate the debug mode\n");
}

static void set_default_config(struct arguments *args)
{
    args->protocol = "TCP";
    args->output_file = "";
    args->debug_mode = false;
}

int get_arguments(int argc, char *argv[], struct arguments *args)
{
    int c = 0;

    set_default_config(args);

    while ((c = getopt(argc, argv, "hp:o:d")) != -1) {
        switch (c) {
            case 'p': args->protocol = optarg; break;
            case 'o': args->output_file = optarg; break;
            case 'd': args->debug_mode = true; break;
            case 'h': print_help(argv[0]); exit(EXIT_SUCCESS);
            default: print_usage(argv[0]); exit(EXIT_FAILURE);
        }
    }

    return 0;
}

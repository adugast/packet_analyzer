#include <stdio.h>

#include "packet_analyzer.h"

static void print_config(struct arguments *args)
{
    printf("---config_used---\n");
    printf("protocol[%s]\n", args->protocol);
    printf("path_file[%s]\n", args->output_file);
    printf("-----------------\n");
}

int main(int argc, char *argv[])
{
    struct arguments args;

    get_arguments(argc, argv, &args);

    print_config(&args);

    packet_analyzer(&args);

    return 0;
}

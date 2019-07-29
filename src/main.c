#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "packet_analyzer.h"


static void print_config(struct arguments *args)
{
    printf("---config_used---\n");
    printf("protocol[%s]\n", args->protocol);
    printf("path_file[%s]\n", args->output_file);
    printf("debug_mode[%d]\n", args->debug_mode);
    printf("-----------------\n");
}


void check_root_user()
{
    if (getuid() != 0) {
        printf("You must be root to run this program\n");
        exit(0);
    }
}


int main(int argc, char *argv[])
{
    check_root_user();

    struct arguments args;

    get_arguments(argc, argv, &args);
    if (args.debug_mode == true) {
        print_config(&args);
    }

    packet_analyzer(&args);

    return 0;
}

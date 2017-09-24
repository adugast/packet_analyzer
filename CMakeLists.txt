#########
# CMAKE #
#########

cmake_minimum_required(VERSION 2.8.3)

project(packet_analyzer)

## Target
add_executable(
    packet_analyzer
    src/main.c
    src/get_args.c
    src/packet_analyzer.c
    src/tcp_packet.c
)

#########
# CMAKE #
#########

cmake_minimum_required(VERSION 3.5.1)

project(packet_analyzer)

## set compilation flags
set(CMAKE_C_FLAGS "-W -Wall -Werror -pedantic")

## set the target name and source
add_executable(
    packet_analyzer
    src/main.c
    src/get_args.c
    src/packet_analyzer.c
    src/tcp_packet.c
    src/udp_packet.c
)

#########
# CMAKE #
#########

cmake_minimum_required(VERSION 2.8.3)

project(packet_analyzer)

## Target
add_executable(
    packet_analyzer
    src/main.c
)

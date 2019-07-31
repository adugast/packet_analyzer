# packet_analyzer [![Language: C](https://img.shields.io/badge/Language-C-brightgreen.svg)](https://en.wikipedia.org/wiki/C_(programming_language))  [![Library: ncurses](https://img.shields.io/badge/Library-ncurses-brightgreen.svg)](https://www.gnu.org/software/ncurses/)  [![Builder: CMake](https://img.shields.io/badge/Builder-CMake-brightgreen.svg)](https://cmake.org/)  [![License: MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://opensource.org/licenses/MIT)

## Introduction

## Program description:

## Setting up seashell

Clone the project to retrieve the sources:
```
$>git clone https://github.com/pestbuns/packet_analyzer.git
```

Go in the build directory of seashell:
```
$>cd packet_analyzer/build/
```

Build the project using CMake (from the build directory):
```
$>cmake ..
```

Finally, use make to compile the sources and so generate the binary (still from the build directory):
```
$>make
```

## Usage:
Launch packet_analyzer:

You must be root to launch packet_analyzer as it uses a raw socket

```
$>sudo ./packet_analyzer
```

## Output:

```
********************TCP Packet********************
Ethernet Header
    |-Source Address : 02-42-AD-11-01-13
    |-Destination Address : 02-42-AC-11-00-0C
    |-Protocol : 8

IP Header
    |-Version : 4
    |-Internet Header Length : 5 DWORDS or 20 Bytes
    |-Type Of Service : 0
    |-Total Length : 60 Bytes
    |-Identification : 0
    |-Time To Live : 64
    |-Protocol : 6
    |-Header Checksum : 38438
    |-Source IP : 10.128.212.11
    |-Destination IP : 192.12.20.12

TCP Header
    |-source:9299
    |-destination:41276
    |-sequence number:2598912214
    |-acknowledge number:3140846082
    |-data offset:40 bytes
    |-finish flag:0
    |-synchronize flag:1
    |-reset flag:0
    |-push flag:0
    |-acknowledgement flag:1
    |-urgent flag:0
    |-window size:22960
    |-checksum:42190
    |-urgent pointer:0
```

## Help:

```
Usage: ./packet_analyzer [ -p protocol ] [ -o output_file ] [ -d ]
Available params:
 -p, --protocol : Select a protocol in particular, tcp, udp, all (by default all)
 -o, --output   : Log packet dump into a file
 -d, --debug    : Activate debug mode
 -v, --version  : Show version information
 -h, --help     : Display this help and exit
```

## How packet_analyzer works:

TODO:
explain raw socket, protocols, osi model, encapsulation and network packets

Description of the headers in linux system:

/usr/include/linux/if_ether.h
/usr/include/netinet/ip.h
/usr/include/netinet/tcp.h
/usr/include/netinet/udp.h

## More info:

* [Wikipedia: OSI Model](https://en.wikipedia.org/wiki/OSI_model) - OSI model overview
* [Wikipedia: Encapsulation (networking)](https://en.wikipedia.org/wiki/Encapsulation_(networking)) - Packets encapsulation overview
* [RAW Socket](https://opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/) - A guide to using raw sockets

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details


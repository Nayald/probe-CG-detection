#include <iostream>
#include <csignal>
#include <cstring>
extern "C" {
    #include <pcap.h>
}

#include "packetparser.h"
#include "windowparser.h"
#include "logger.h"

void packet_handler(u_char *const args, const pcap_pkthdr *const header, const u_char *const packet) {
    ((PacketParser*)args)->handle(header, packet);
}

pcap_t *handle;
void signal_handler(int signum){
    printf("received signal %d, breaking sniffing loop\n", signum);
    if (handle) {
        pcap_breakloop(handle);
    }
}

int main(int argc, char *argv[]) {
    if (argc <= 3) {
        printf("usage: %s bind_interface remote_address remote_port\n", argv[0]);
        return 1;
    }

    const char *const face = argv[1];
    const char *const addr = argv[2];
    const uint16_t port = std::stoul(argv[3]);

    signal(SIGINT, signal_handler);

    char errbuf[PCAP_ERRBUF_SIZE];
    // limit capture to UDP over IPv4, capture only first fragment if any
    const char *const filter_exp = "ip and ip[6:2] & 0x1fff = 0 and udp";
    bpf_program filter;
    int timeout_limit = 1000; /* In milliseconds */

    handle = pcap_open_live(face, SNAPSIZE, 0, timeout_limit, errbuf);
    if (!handle) {
        printf("can't sniff on device %s -> %s\n", face, errbuf);
        return 1;
    }

    if (pcap_compile(handle, &filter, filter_exp, 1, 0) != 0) {
        printf("bad filter - %s\n", pcap_geterr(handle));
        return 1;
    }

    if (pcap_setfilter(handle, &filter) != 0) {
        printf("error setting filter - %s\n", pcap_geterr(handle));
        return 1;
    }

    WindowParser window_parser(addr, port, 1 << 10);
    PacketParser packet_parser(window_parser, 1 << 16);
    window_parser.start();
    packet_parser.start();
    pcap_loop(handle, -1, packet_handler, (u_char*const)&packet_parser);

    pcap_stat stat;
    pcap_stats(handle, &stat);
    pcap_close(handle);
    packet_parser.stop();
    window_parser.stop();
    printf("pcap capture stats: recv = %u pkts, drop = %u pkts, ifdrop = %u pkts\n", stat.ps_recv, stat.ps_drop, stat.ps_ifdrop);
    return 0;
}

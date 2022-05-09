#include <iostream>
#include <csignal>
#include <cstring>
extern "C" {
    #include <pcap.h>
}

#include "packetparser.h"
#include "windowparser.h"
#include "logger.h"

void packet_handler(u_char *const args, const pcap_pkthdr *header, const u_char *packet) {
    static packet_msg msg;
    // verify we have at least the length of Eth + IP + UDP header, commented because trust in pcap filter
    /*if (header->caplen < 42) {
        return;
    }*/

    msg.time = header->ts;
    msg.size = header->len;
    std::memcpy(msg.packet, packet, header->caplen);
    ((PacketParser*)args)->handle(msg);
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
        printf("usage: ./sniff bind_interface remote_address remote_port");
        return 1;
    }

    char *face = argv[1];
    char *addr = argv[2];
    uint16_t port = std::stoul(argv[3]);

    signal(SIGINT, signal_handler);

    char errbuf[PCAP_ERRBUF_SIZE];
    //const char *filter_exp = "ether proto \\ip and ip proto \\udp";
    const char *filter_exp = "ip and udp";
    bpf_program filter;
    int timeout_limit = 1000; /* In milliseconds */

    handle = pcap_open_live(face, SNAPSIZE, 0, timeout_limit, errbuf);
    if (!handle) {
        printf("can't sniff on device %s -> %s", face, errbuf);
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

    WindowParser window_parser(addr, port, 1 << 8);
    PacketParser packet_parser(window_parser, 1 << 16);
    window_parser.start();
    packet_parser.start();
    pcap_loop(handle, -1, packet_handler, (u_char*const)&packet_parser);

    pcap_stat stat;
    pcap_stats(handle, &stat);
    pcap_close(handle);
    packet_parser.stop();
    window_parser.stop();
    printf("pcap capture stats: recv = %u pkts, drop = %u pkts, ifdrop = %u\n", stat.ps_recv, stat.ps_drop, stat.ps_ifdrop);
    return 0;
}

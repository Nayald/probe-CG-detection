#ifndef SNIFF_PACKETPARSER_H
#define SNIFF_PACKETPARSER_H

#include <vector>
#include <unordered_map>
#include <thread>
#include <iostream>

#include "abseil-cpp/absl/container/flat_hash_map.h"
#include "readerwriterqueue/readerwritercircularbuffer.h"
#include "windowsink.h"

constexpr size_t SNAPSIZE = 82;
constexpr timeval WINDOWTIME = {.tv_sec = 0, .tv_usec = 33000};

struct packet_msg {
    timeval time;
    uint32_t size;
    u_char packet[SNAPSIZE];
};

class PacketParser {
private:
    // may simplify ip usage
    union ip_pair {
        uint64_t hash;
        uint32_t addrs[2];
    };

    // for ip:port hash key, not needed for ip alone since it can fit in a uint64_t
    /*struct stream_key {
        uint32_t ip1;
        uint32_t ip2;
        uint16_t p1;
        uint16_t p2;

        bool operator==(const stream_key &k) const {
            return ip1 == k.ip1 && ip2 == k.ip2 && p1 == k.p1 && p2 == k.p2;
        }

        template <typename H>
        friend H AbslHashValue(H h, const stream_key& k) {
            return H::combine(std::move(h), k.ip1, k.ip2, k.p1, k.p2);
        }
    };*/

    struct stream {
        uint32_t src_addr = 0;
        uint32_t dst_addr = 0;
        uint16_t src_port = 0;
        uint16_t dst_port = 0;
        std::vector<int32_t, alignocator<int32_t, 32>> up_sizes;
        std::vector<int32_t, alignocator<int32_t, 32>> down_sizes;
        std::vector<int32_t, alignocator<int32_t, 32>> up_iats;
        std::vector<int32_t, alignocator<int32_t, 32>> down_iats;
        timeval up_last_time = {0};
        timeval down_last_time = {0};
        // end time instead of start time to reduce usage of timeradd
        timeval end_time = {0};

        stream() = default;
        explicit stream(uint32_t src_addr, uint32_t dst_addr, timeval iat_origin, timeval end_time) : src_addr(src_addr), dst_addr(dst_addr), up_last_time(iat_origin), down_last_time(iat_origin), end_time(end_time) {};
        explicit stream(uint32_t src_addr, uint32_t dst_addr, uint16_t src_port, uint16_t dst_port, timeval end_time, timeval iat_origin) : src_addr(src_addr), dst_addr(dst_addr), src_port(src_port), dst_port(dst_port), up_last_time(iat_origin), down_last_time(iat_origin), end_time(end_time) {};
        stream(stream &&s) = default;
    };

#ifdef DEBUG
    uint64_t sum_queue_size = 0;
    uint64_t last_sum_queue_size = 0;
    uint64_t sum_pkt = 0;
    uint64_t last_sum_pkt = 0;
    uint64_t sum_pkt_size = 0;
    uint64_t last_sum_pkt_size = 0;
    uint64_t sum_pkt_delay = 0;
    uint64_t last_sum_pkt_delay = 0;
    uint64_t sum_pkt_parsing = 0;
    uint64_t last_sum_pkt_parsing = 0;
    uint64_t sum_win = 0;
    uint64_t last_sum_win = 0;
    uint64_t sum_win_time_gap = 0;
    uint64_t last_sum_win_time_gap = 0;
    bool manager_stop_condition = true;
    std::thread manager_thread;
#endif

    bool parser_stop_condition = true;
    std::thread parser_thread;

    moodycamel::BlockingReaderWriterCircularBuffer<packet_msg> packet_queue;
    absl::flat_hash_map<uint64_t, stream> streams;

    WindowSink &sink;

public:
    explicit PacketParser(WindowSink &sink, int queue_capacity=2048);
    ~PacketParser();

    void start();
    void stop();

    void handle(const packet_msg &msg);
    void handle(packet_msg &&msg);

private:
#ifdef DEBUG
    void info();
#endif
    void parse();
};


#endif //SNIFF_PACKETPARSER_H

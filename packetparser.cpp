#include "packetparser.h"
#include <iostream>
#include <iomanip>
#include <numeric>
#include <sstream>
#include <cstring>
#include <unistd.h>
//#include <ctime>
#include <sys/time.h>
#include <byteswap.h>
#include <arpa/inet.h>

#include "logger.h"

PacketParser::PacketParser(WindowSink &sink, int queue_capacity) : packet_queue(queue_capacity), sink(sink) {

}

PacketParser::~PacketParser() {
    stop();
}

void PacketParser::start() {
#ifdef DEBUG
    manager_stop_condition = false;
    manager_thread = std::thread(&PacketParser::info, this);
#endif
    parser_threads.emplace_back(std::thread(&PacketParser::parse, this, parser_threads.size()));
}

void PacketParser::stop() {
#ifdef DEBUG
    if (!manager_stop_condition) {
        manager_stop_condition = true;
        manager_thread.join();
    }
#endif
    for (thread_context &e : parser_threads) {
        if (!e.stop_condition) {
            e.stop_condition = true;
            e.thread.join();
        }
    }
    parser_threads.clear();
}

void PacketParser::handle(const packet_msg &msg) {
#ifdef DEBUGPLUS
    if (!packet_queue.try_enqueue(msg)) {
        logger::log(logger::WARNING, "drop packet, queue is full");
    }
#else
    packet_queue.try_enqueue(msg);
#endif
}

void PacketParser::handle(packet_msg &&msg) {
#ifdef DEBUGPLUS
    if (!packet_queue.try_enqueue(std::forward<packet_msg>(msg))) {
        logger::log(logger::WARNING, "drop packet, queue is full");
    }
#else
    packet_queue.try_enqueue(std::forward<packet_msg>(msg));
#endif
}

#ifdef DEBUG
void PacketParser::info() {
    logger::log(logger::INFO, "packet parser starts a manager thread with pid ", gettid());
    /*size_t max_size = std::thread::hardware_concurrency() - 2;
    if (max_size < 3) {
        max_size = 3;
    }*/

    std::stringstream ss;
    while (!manager_stop_condition) {
        /*if (packet_queue.size_approx() > 1000 && parser_threads.size() < max_size) {
            parser_threads.emplace_back(std::thread(&PacketParser::parse, this, parser_threads.size()));
        } else if (packet_queue.size_approx() < 10 && parser_threads.size() > 3) {
            thread_context &tc = parser_threads.back();
            tc.stop_condition = true;
            tc.thread.join();
            parser_threads.pop_back();
        }*/

        uint64_t sum_queue_size = 0;
        uint64_t sum_pkt = 0;
        uint64_t sum_pkt_size = 0;
        uint64_t sum_pkt_delay = 0;
        uint64_t sum_pkt_parsing = 0;
        uint64_t sum_pkt_mapping = 0;
        uint64_t sum_win = 0;
        uint64_t sum_win_time_gap = 0;
        uint64_t sum_win_delay = 0;
        for (thread_context &tc : parser_threads) {
            sum_queue_size += tc.sum_queue_size - tc.last_sum_queue_size;
            tc.last_sum_queue_size = tc.sum_queue_size;
            sum_pkt += tc.sum_pkt - tc.last_sum_pkt;
            tc.last_sum_pkt = tc.sum_pkt;
            sum_pkt_size += tc.sum_pkt_size - tc.last_sum_pkt_size;
            tc.last_sum_pkt_size = tc.sum_pkt_size;
            sum_pkt_delay += tc.sum_pkt_delay - tc.last_sum_pkt_delay;
            tc.last_sum_pkt_delay = tc.sum_pkt_delay;
            sum_pkt_parsing += tc.sum_pkt_parsing - tc.last_sum_pkt_parsing;
            tc.last_sum_pkt_parsing = tc.sum_pkt_parsing;
            sum_pkt_mapping += tc.sum_pkt_mapping - tc.last_sum_pkt_mapping;
            tc.last_sum_pkt_mapping = tc.sum_pkt_mapping;
            sum_win += tc.sum_win - tc.last_sum_win;
            tc.last_sum_win = tc.sum_win;
            sum_win_time_gap += tc.sum_win_time_gap - tc.last_sum_win_time_gap;
            tc.last_sum_win_time_gap = tc.sum_win_time_gap;
            sum_win_delay += tc.sum_win_delay - tc.last_sum_win_delay;
            tc.last_sum_win_delay = tc.sum_win_delay;
        }

        ss << "packet parser info" << std::endl
           << "\taverage packet parser queue size = " << (sum_queue_size ? sum_queue_size / (double)sum_pkt : 0) << " / " << packet_queue.max_capacity() << std::endl
           << "\tcurrent packet parser table size = " << streams.size() << std::endl;

        ss << std::fixed << std::setprecision(0) << "\tcurrent parsing pace = " << sum_pkt / (double)MANAGERSLEEPTIME.count() << " pkts/s (~" << (sum_pkt_size >> 7) / (double)MANAGERSLEEPTIME.count() << " Kbps)" << std::endl;
        if (sum_pkt > 0) {
            ss << std::fixed << std::setprecision(2) << "\taverage packet waiting time = " << sum_pkt_delay / (double)sum_pkt << " us" << std::endl;
            ss << std::fixed << std::setprecision(2) << "\taverage packet parsing time = " << sum_pkt_parsing / (double)sum_pkt << " ns (~" << sum_pkt_parsing / 10'000'000 << "%)" << std::endl;
            ss << std::fixed << std::setprecision(2) << "\taverage packet insert time = " << sum_pkt_mapping / (double)sum_pkt << " ns (~" << sum_pkt_mapping / 10'000'000 << "%)" << std::endl;
            ss << std::fixed << std::setprecision(0) << "\testimated packet compute capacity = " << sum_pkt / (double)MANAGERSLEEPTIME.count() << " / " << 1'000'000'000 * (sum_pkt / (double)(sum_pkt_parsing + sum_pkt_mapping + sum_win_delay)) << std::endl;
        }

        if (sum_win > 0) {
            ss << std::fixed << std::setprecision(2) << "\taverage window time gap = " << sum_win_time_gap / (double)sum_win << " us" << std::endl;
            ss << std::fixed << std::setprecision(2) << "\taverage window compute time = " << sum_win_delay / (double)sum_win << " ns (~" << sum_win_delay / 10'000'000 << "%)"  << std::endl;
            ss << std::fixed << std::setprecision(0) << "\testimated window compute capacity = " << sum_win / (double)MANAGERSLEEPTIME.count() << " / " << 1'000'000'000 * (sum_win / (double)(sum_pkt_parsing + sum_pkt_mapping + sum_win_delay)) << std::endl;
        }

        logger::log(logger::INFO, ss.str());
        ss.str({});
        ss.clear();

        std::this_thread::sleep_for(MANAGERSLEEPTIME);
    }
    logger::log(logger::INFO, "packet parser stops a manager thread with pid ", gettid());
}
#endif


void PacketParser::parse(const size_t i) {
    logger::log(logger::INFO, "packet parser starts a parse thread with pid ", gettid());
#ifdef DEBUG
    std::stringstream ss;
    char src_addr[INET_ADDRSTRLEN];
    char dst_addr[INET_ADDRSTRLEN];
#endif
    timeval now, t;
    std::chrono::steady_clock::time_point start, last_purge;
    packet_msg msg;
    while (!parser_threads[i].stop_condition) {
        if (!packet_queue.wait_dequeue_timed(msg, 5000)) {
            if ((start = std::chrono::steady_clock::now()) - last_purge > HOUSEKEEPERSLEEPTIME) {
#ifdef DEBUG
                ss << "start purging old data" << std::endl;
#endif
                gettimeofday(&now, NULL);
                for (auto it = streams.begin(); it != streams.end();) {
                    timersub(&now, &it->second.end_time, &t);
                    if (timercmp(&t, &PURGETIME, >=)) {
#ifdef DEBUG
                        inet_ntop(AF_INET, &it->second.src_addr, src_addr, INET_ADDRSTRLEN);
                        inet_ntop(AF_INET, &it->second.dst_addr, dst_addr, INET_ADDRSTRLEN);
                        ss << "\tremoves an old stream (" << src_addr << ":" << bswap_16(it->second.src_port)
                           << " -> " << dst_addr << ":" << bswap_16(it->second.dst_port) << ")" << std::endl;
#endif
                        streams.erase(it++);
                    } else {
                        it++;
                    }
                }
#ifdef DEBUG
                logger::log(logger::INFO, ss.str());
                ss.str({});
                ss.clear();
#endif
                last_purge = start;
            }

            continue;
        }

#ifdef DEBUG
        gettimeofday(&t, NULL);
        timersub(&t, &msg.time, &t);
        parser_threads[i].sum_queue_size += packet_queue.size_approx();
        ++parser_threads[i].sum_pkt;
        parser_threads[i].sum_pkt_size += msg.size;
        parser_threads[i].sum_pkt_delay += 1'000'000 * t.tv_sec + t.tv_usec;
        start = std::chrono::steady_clock::now();
#endif

        // check if contains IP header, commented because trust in pcap filter
        /*const uint16_t eth_prot = (msg.packet[12] << 8) + msg.packet[13];
        if (eth_prot != 0x0800) {
            continue;
        }*/

        //size_t offset = 14;
        //const uint8_t ihl = (msg.packet[offset] & 0xF) * 4;
        //const uint8_t ip_prot = msg.packet[offset + 9];
        // keep packet endianness for IPs, not useful for parsing
        ip_pair ips;
        //ips.hash = *(uint64_t*)(msg.packet + 26);
        std::memcpy(&ips, msg.packet + 26, 8 * sizeof(u_char));
        /*
        uint32_t src_addr;
        std::memcpy(&src_addr, msg.packet + offset + 12, 4 * sizeof(u_char));
        uint32_t dst_addr;
        std::memcpy(&dst_addr, msg.packet + offset + 16, 4 * sizeof(u_char));
        */
        // check if contains UDP header, commented because trust in pcap filter
        /*if (ip_prot != 17) {
            continue;
        }*/

        const size_t offset = 14 + (msg.packet[14] & 0xF) * 4;
        // keep packet endianness for ports, not useful for parsing
        //const uint16_t src_port = *(uint16_t*)(msg.packet + offset);
        //const uint16_t dst_port = *(uint16_t*)(msg.packet + offset + 2);
        //const uint16_t src_port = (msg.packet[offset] << 8) | msg.packet[offset + 1];
        //const uint16_t dst_port = (msg.packet[offset + 2] << 8) | msg.packet[offset + 3];
        const uint16_t udp_length = bswap_16(*(uint16_t*)(msg.packet + offset + 4));
        //const uint16_t udp_length = (msg.packet[offset + 4] << 8) | msg.packet[offset + 5];

#ifdef DEBUG
        parser_threads[i].sum_pkt_parsing += std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - start).count();
        start = std::chrono::steady_clock::now();
#endif

        //stream_key key_a = {.ip1 = src_addr, .ip2 = dst_addr, .p1 = src_port, .p2 = dst_port};
        // find or create entry
        auto &&it = streams.find(ips.hash);
        if (it == streams.end()) {
            // test the other direction
            //stream_key key_b = {.ip1 = dst_addr, .ip2 = src_addr, .p1 = dst_port, .p2 = src_port};
            it = streams.find((ips.hash << 32) | (ips.hash >> 32));
            if (it == streams.end()) {
                // end is first packet time + window time frame
                timeradd(&msg.time, &WINDOWTIME, &t);
                auto &&ret = streams.emplace(std::piecewise_construct,
                                             std::forward_as_tuple(ips.hash),
                                             std::forward_as_tuple(ips.addrs[0], ips.addrs[1], t));

                if (ret.second) {
                    it = ret.first;
                } else {
                    logger::log(logger::ERROR, "unable to insert new stream in table, drop packet");
                    continue;
                }

#ifdef DEBUG
                parser_threads[i].sum_pkt_mapping += std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - start).count();
#endif
            }
        }

        stream &s = it->second;

        // timeradd needed only if we store start time
        //timeradd(&s.end_time, &WINDOWTIME, &t);
        // verify if window is still in the interval
        if (timercmp(&msg.time, &s.end_time, <)) {
            // continue to append
            // select direction
            if (s.src_addr == ips.addrs[0]) {
                s.up_sizes.push_back(udp_length);
                if (!s.up_sizes.empty()) {
                    timersub(&msg.time, &s.up_last_time, &t);
                    // tv.sec not needed since window time < 1 second and logically iat too
                    s.up_iats.push_back(/*1'000'000 * t.tv_sec +*/ t.tv_usec);
                }
                s.up_last_time = msg.time;
            } else {
                s.down_sizes.push_back(udp_length);
                if (!s.down_sizes.empty()) {
                    timersub(&msg.time, &s.down_last_time, &t);
                    // tv.sec not needed since window time < 1 second and logically iat too
                    s.down_iats.push_back(/*1'000'000 * t.tv_sec +*/ t.tv_usec);
                }
                s.down_last_time = msg.time;
            }

#ifdef DEBUG
            parser_threads[i].sum_pkt_mapping += std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - start).count();
#endif

            continue;
        }

#ifdef DEBUG
        ++parser_threads[i].sum_win;
        timersub(&msg.time, &s.end_time, &t);
        parser_threads[i].sum_win_time_gap += t.tv_usec;
#endif

        // extract
        std::vector<uint16_t> up_sizes;
        up_sizes.reserve(s.up_sizes.capacity());
        std::vector<uint16_t> down_sizes;
        down_sizes.reserve(s.down_sizes.capacity());
        std::vector<uint16_t> up_iats;
        up_iats.reserve(s.up_sizes.capacity());
        std::vector<uint16_t> down_iats;
        down_iats.reserve(s.down_sizes.capacity());
        std::swap(up_sizes, s.up_sizes);
        std::swap(down_sizes, s.down_sizes);
        std::swap(up_iats, s.up_iats);
        std::swap(down_iats, s.down_iats);

        timeradd(&msg.time, &WINDOWTIME, &s.end_time);
        if (s.src_addr == ips.addrs[0]) {
            s.up_sizes.push_back(udp_length);
            s.up_last_time = msg.time;
        } else {
            s.down_sizes.push_back(udp_length);
            s.down_last_time = msg.time;
        }

#ifdef DEBUG
        parser_threads[i].sum_pkt_mapping += std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - start).count();
        start = std::chrono::steady_clock::now();
#endif

        // compute features, as integer for small speed up without much precision loss
        uint16_t up_size_mean = 0;
        uint32_t up_size_var = 0;
        if (!up_sizes.empty()) {
            up_size_mean = std::accumulate(up_sizes.begin(), up_sizes.end(), uint32_t{0}) / up_sizes.size();
            up_size_var = std::accumulate(up_sizes.begin(), up_sizes.end(), uint32_t{0},
                                          [mean = up_size_mean](uint32_t acc, uint16_t e) {
                                              return acc + (e - mean) * (e - mean);
                                          }) / up_sizes.size();
            // preference for payload length
            up_size_mean -= uint16_t{8};
        }

        uint16_t down_size_mean = 0;
        uint32_t down_size_var = 0;
        if (!down_sizes.empty()) {
            down_size_mean = std::accumulate(down_sizes.begin(), down_sizes.end(), uint32_t{0}) / down_sizes.size();
            down_size_var = std::accumulate(down_sizes.begin(), down_sizes.end(), uint32_t{0},
                                            [mean = down_size_mean](uint32_t acc, uint16_t e) {
                                                return acc + (e - mean) * (e - mean);
                                            }) / down_sizes.size();
            // preference for payload length
            down_size_mean -= uint16_t{8};
        }

        uint16_t up_iat_mean = 0;
        uint32_t up_iat_var = 0;
        if (!up_iats.empty()) {
            up_iat_mean = std::accumulate(up_iats.begin(), up_iats.end(), uint16_t{0}) / up_iats.size();
            up_iat_var = std::accumulate(up_iats.begin(), up_iats.end(), uint32_t{0},
                                         [mean = up_iat_mean](uint32_t acc, uint16_t e) {
                                             return acc + (e - mean) * (e - mean);
                                         }) / up_iats.size();
        }

        uint16_t down_iat_mean = 0;
        uint32_t down_iat_var = 0;
        if (!down_iats.empty()) {
            down_iat_mean = std::accumulate(down_iats.begin(), down_iats.end(), uint16_t{0}) / down_iats.size();
            down_iat_var = std::accumulate(down_iats.begin(), down_iats.end(), uint32_t{0},
                                           [mean = down_iat_mean](uint32_t acc, uint16_t e) {
                                               return acc + (e - mean) * (e - mean);
                                           }) / down_iats.size();
        }

        sink.handle({
            s.src_addr, s.dst_addr, s.src_port, s.dst_port,
            (uint32_t)up_sizes.size(), up_size_mean, up_iat_mean, up_size_var, up_iat_var,
            (uint32_t)down_sizes.size(), down_size_mean, down_iat_mean, down_size_var, down_iat_var
        });

#ifdef DEBUG
        parser_threads[i].sum_win_delay += std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - start).count();
#endif
    }
    logger::log(logger::INFO, "packet parser stops a parse thread with pid ", gettid());
}
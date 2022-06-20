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

constexpr timeval PURGETIME = {.tv_sec = 2, .tv_usec = 0};
constexpr std::chrono::seconds MANAGERSLEEPTIME{2};
constexpr std::chrono::seconds HOUSEKEEPERSLEEPTIME{15};

PacketParser::PacketParser(WindowSink &sink, int queue_capacity) : packet_queue(queue_capacity), sink(sink) {

}

PacketParser::~PacketParser() {
    stop();
}

void PacketParser::start() {
#ifdef DEBUG
    manager_stop_condition = false;
    manager_thread = std::thread(&PacketParser::runInfo, this);
#endif
#ifndef NO_PP_THREAD
    parser_stop_condition = false;
    parser_thread = std::thread(&PacketParser::runParser, this);
#endif
}

void PacketParser::stop() {
#ifdef DEBUG
    if (!manager_stop_condition) {
        manager_stop_condition = true;
        manager_thread.join();
    }
#endif
#ifndef NO_PP_THREAD
    if (!parser_stop_condition) {
        parser_stop_condition = true;
        parser_thread.join();
    }
#endif
}

void PacketParser::handle(const packet_msg &pmsg) {
#ifndef NO_PP_THREAD
#ifdef QUEUE_VERBOSE
    if (!packet_queue.try_enqueue(pmsg)) {
        logger::log(logger::WARNING, "drop packet, queue is full");
    }
#else
    packet_queue.try_enqueue(pmsg);
#endif
#else
    parse(pmsg);
    timersub(&pmsg.timestamp, &last_purge, &purge_delta);
    if (purge_delta.tv_sec >= HOUSEKEEPERSLEEPTIME.count()) {
        purge();
        last_purge = pmsg.timestamp;
    }
#endif
}

void PacketParser::handle(packet_msg &&pmsg) {
#ifndef NO_PP_THREAD
#ifdef QUEUE_VERBOSE
    if (!packet_queue.try_enqueue(std::forward<packet_msg>(msg))) {
        logger::log(logger::WARNING, "drop packet, queue is full");
    }
#else
    packet_queue.try_enqueue(std::forward<packet_msg>(pmsg));
#endif
#else
    parse(pmsg);
    timersub(&pmsg.timestamp, &last_purge, &purge_delta);
    if (purge_delta.tv_sec >= HOUSEKEEPERSLEEPTIME.count()) {
        purge();
        last_purge = pmsg.timestamp;
    }
#endif
}

void PacketParser::handle(const pcap_pkthdr *const header, const u_char *const packet) {
    packet_msg pmsg;
    pmsg.timestamp = header->ts;
    //pmsg.packet_size = header->len;

    // check if contains IP header, commented because trust in pcap filter
    /*const uint16_t eth_prot = (msg.packet[12] << 8) + msg.packet[13];
    if (eth_prot != 0x0800) {
        continue;
    }*/

    size_t offset = 14;
    const uint8_t ihl = (packet[offset] & 0xF) * 4;
    //const uint8_t ip_prot = msg.packet[offset + 9];
    // keep packet endianness for IPs, not useful for parsing
    //ips.hash = *(uint64_t*)(msg.packet + 26);
    std::memcpy(&pmsg.ips, packet + offset + 12, 8 * sizeof(u_char));
    // check if contains UDP header, commented because trust in pcap filter
    /*if (ip_prot != 17) {
        continue;
    }*/

    offset += ihl;
    // keep packet endianness for ports, not useful for parsing
    //const uint16_t src_port = *(uint16_t*)(msg.packet + offset);
    //const uint16_t dst_port = *(uint16_t*)(msg.packet + offset + 2);
    pmsg.udp_length = bswap_16(*(uint16_t*)(packet + offset + 4));

#ifndef NO_PP_THREAD
#ifdef QUEUE_VERBOSE
    if (!packet_queue.try_enqueue(pmsg)) {
        logger::log(logger::WARNING, "drop packet, queue is full");
    }
#else
    packet_queue.try_enqueue(pmsg);
#endif
#else
    parse(pmsg);
    timersub(&pmsg.timestamp, &last_purge, &purge_delta);
    if (purge_delta.tv_sec >= HOUSEKEEPERSLEEPTIME.count()) {
        purge();
        last_purge = pmsg.timestamp;
    }
#endif
}


#ifdef DEBUG
void PacketParser::runInfo() {
    logger::log(logger::INFO, "packet parser starts a manager thread with pid ", gettid());

    std::stringstream ss;
    while (!manager_stop_condition) {
#ifndef NO_PP_THREAD
        const uint64_t sum_queue_size_delta = sum_queue_size - last_sum_queue_size;
        last_sum_queue_size = sum_queue_size;
#endif
        const uint64_t sum_pkt_delta = sum_pkt - last_sum_pkt;
        last_sum_pkt = sum_pkt;
        const uint64_t sum_pkt_size_delta = sum_pkt_size - last_sum_pkt_size;
        last_sum_pkt_size = sum_pkt_size;
        const uint64_t sum_pkt_delay_delta = sum_pkt_delay - last_sum_pkt_delay;
        last_sum_pkt_delay = sum_pkt_delay;
        const uint64_t sum_pkt_parsing_delta = sum_pkt_parsing - last_sum_pkt_parsing;
        last_sum_pkt_parsing = sum_pkt_parsing;
        const uint64_t sum_win_delta = sum_win - last_sum_win;
        last_sum_win = sum_win;
        const uint64_t sum_win_time_gap_delta = sum_win_time_gap - last_sum_win_time_gap;
        last_sum_win_time_gap = sum_win_time_gap;

        ss << "packet parser info" << std::endl
#ifndef NO_PP_THREAD
           << "\taverage packet parser queue size = " << (sum_queue_size_delta ? sum_queue_size_delta / sum_pkt_delta : 0) << " / " << packet_queue.max_capacity() << std::endl
#endif
           << "\tcurrent packet parser table size = " << streams.size() << std::endl;

        ss << "\tcurrent parsing pace = " << sum_pkt_delta / MANAGERSLEEPTIME.count() << " pkts/s (~" << (sum_pkt_size_delta >> 7) / MANAGERSLEEPTIME.count() << " Kbps)" << std::endl;
        if (sum_pkt_delta > 0) {
            ss << std::fixed << std::setprecision(2) << "\t\taverage packet waiting time = " << static_cast<double>(sum_pkt_delay_delta) / static_cast<double>(sum_pkt_delta) << " us" << std::endl;
            ss << std::fixed << std::setprecision(2) << "\t\taverage packet handle time = " << static_cast<double>(sum_pkt_parsing_delta) / static_cast<double>(sum_pkt_delta) << " ns" << std::endl;
            ss << std::fixed << std::setprecision(0) << "\t\testimated packet compute capacity = " << 1'000'000'000 / (static_cast<double>(sum_pkt_parsing_delta) / static_cast<double>(sum_pkt_delta)) << " (~" << sum_pkt_parsing_delta / 10'000'000 << "%)" << std::endl;
        }

        if (sum_win_delta > 0) {
            ss << "\taverage window per second = " << sum_win_delta / MANAGERSLEEPTIME.count() << std::endl;
            ss << std::fixed << std::setprecision(2) << "\t\taverage window time gap = " << static_cast<double>(sum_win_time_gap_delta) / static_cast<double>(sum_win_delta) << " us" << std::endl;
        }

        logger::log(logger::INFO, ss.str());
        ss.str({});
        ss.clear();

        std::this_thread::sleep_for(MANAGERSLEEPTIME);
    }
    logger::log(logger::INFO, "packet parser stops a manager thread with pid ", gettid());
}
#endif

#ifndef NO_PP_THREAD
void PacketParser::runParser() {
    logger::log(logger::INFO, "packet parser starts a parse thread with pid ", gettid());

    packet_msg pmsg;
    std::chrono::steady_clock::time_point last_purge;
    while (!parser_stop_condition) {
        if (!packet_queue.wait_dequeue_timed(pmsg, 5000)) {
            if (auto start = std::chrono::steady_clock::now(); start - last_purge > HOUSEKEEPERSLEEPTIME) {
                purge();
                last_purge = start;
            }
        } else {
#ifdef DEBUG
            sum_queue_size += packet_queue.size_approx();
#endif
            parse(pmsg);
        }
    }
    logger::log(logger::INFO, "packet parser stops a parse thread with pid ", gettid());
}
#endif

void PacketParser::parse(const packet_msg &pmsg) {
    timeval t;
#ifdef DEBUG
    ++sum_pkt;
    sum_pkt_size += pmsg.udp_length;
    gettimeofday(&t, NULL);
    timersub(&t, &pmsg.timestamp, &t);
    sum_pkt_delay += 1'000'000 * t.tv_sec + t.tv_usec;
    const auto start = std::chrono::steady_clock::now();
#endif

    //stream_key key_a = {.ip1 = src_addr, .ip2 = dst_addr, .p1 = src_port, .p2 = dst_port};
    // find or create entry
    auto it = streams.find(pmsg.ips.hash);
    if (it == streams.end()) {
        // test the other direction
        //stream_key key_b = {.ip1 = dst_addr, .ip2 = src_addr, .p1 = dst_port, .p2 = src_port};
        it = streams.find((pmsg.ips.hash << 32) | (pmsg.ips.hash >> 32));
        if (it == streams.end()) {
            // end is first packet time + window time frame
            timeradd(&pmsg.timestamp, &WINDOWTIME, &t);
            auto ret = streams.emplace(std::piecewise_construct,
                                       std::forward_as_tuple(pmsg.ips.hash),
                                       std::forward_as_tuple(pmsg.ips.addrs[0], pmsg.ips.addrs[1], pmsg.timestamp, t));

            if (ret.second) {
                it = ret.first;
            } else {
                logger::log(logger::ERROR, "unable to insert new stream in table, drop packet");
#ifdef DEBUG
                sum_pkt_parsing += std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - start).count();
#endif
                return;
            }
        }
    }

    stream &s = it->second;

    // verify if window is still in the interval
    if (timercmp(&pmsg.timestamp, &s.end_time, <)) {
        // continue to append
        // select direction
        if (s.src_addr == pmsg.ips.addrs[0]) {
            s.up_sizes.push_back(pmsg.udp_length);
            // tv.sec not needed since window time < 1 second and logically iat too
            timersub(&pmsg.timestamp, &s.up_last_time, &t);
            s.up_iats.push_back(/*1'000'000 * t.tv_sec +*/ t.tv_usec);
            s.up_last_time = pmsg.timestamp;
        } else {
            s.down_sizes.push_back(pmsg.udp_length);
            // tv.sec not needed since window time < 1 second and logically iat too
            timersub(&pmsg.timestamp, &s.down_last_time, &t);
            s.down_iats.push_back(/*1'000'000 * t.tv_sec +*/ t.tv_usec);
            s.down_last_time = pmsg.timestamp;
        }
    } else {
#ifdef DEBUG
        ++sum_win;
        timersub(&pmsg.timestamp, &s.end_time, &t);
        sum_win_time_gap += 1'000'000 * t.tv_sec + t.tv_usec;
#endif

        // extract
        window_msg wmsg;
        wmsg.src_addr = s.src_addr;
        wmsg.dst_addr = s.dst_addr;
        wmsg.src_port = s.src_port;
        wmsg.dst_port = s.dst_port;

        wmsg.up_sizes.reserve(s.up_sizes.capacity());
        std::swap(wmsg.up_sizes, s.up_sizes);
        wmsg.down_sizes.reserve(s.down_sizes.capacity());
        std::swap(wmsg.down_sizes, s.down_sizes);
        wmsg.up_iats.reserve(s.up_iats.capacity());
        std::swap(wmsg.up_iats, s.up_iats);
        wmsg.down_iats.reserve(s.down_iats.capacity());
        std::swap(wmsg.down_iats, s.down_iats);

        sink.handle(std::move(wmsg));

        timeradd(&pmsg.timestamp, &WINDOWTIME, &s.end_time);
        if (s.src_addr == pmsg.ips.addrs[0]) {
            s.up_sizes.push_back(pmsg.udp_length);
            timersub(&pmsg.timestamp, &s.up_last_time, &t);
            s.up_iats.push_back(/*1'000'000 * t.tv_sec +*/ t.tv_usec);
            s.up_last_time = pmsg.timestamp;
        } else {
            s.down_sizes.push_back(pmsg.udp_length);
            timersub(&pmsg.timestamp, &s.down_last_time, &t);
            s.down_iats.push_back(/*1'000'000 * t.tv_sec +*/ t.tv_usec);
            s.down_last_time = pmsg.timestamp;
        }
    }
#ifdef DEBUG
        sum_pkt_parsing += std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - start).count();
#endif
}

void PacketParser::purge() {
    timeval now, t;
#ifdef DEBUG
    char src_addr[INET_ADDRSTRLEN];
    char dst_addr[INET_ADDRSTRLEN];
    std::stringstream ss;
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
#endif
}
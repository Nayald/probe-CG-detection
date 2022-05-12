#include <unistd.h>
#include <arpa/inet.h>
#include <sstream>
#include <byteswap.h>

#include "windowparser.h"
#include "logger.h"

WindowParser::WindowParser(const std::string addr, uint16_t port, int queue_capacity) : window_queue(queue_capacity) {
    remote.sin_family = AF_INET;
    remote.sin_port = htons(port);
    if (inet_pton(AF_INET, addr.c_str(), &(remote.sin_addr)) <= 0) {
        throw std::runtime_error("remote address is ill-formed");
    }
}

WindowParser::~WindowParser() {
    stop();
}

void WindowParser::start() {
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    while (sockfd < 0){
        logger::log(logger::ERROR, "unable to open UDP socket, wait 1s before retry");
        std::this_thread::sleep_for(std::chrono::seconds(1));
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    }

    if (connect(sockfd, (const sockaddr*)(&remote), sizeof(remote)) < 0) {
        logger::log(logger::ERROR, "function connect return error");
    }

    stop_condition = false;
    thread = std::thread(&WindowParser::run, this);
}

void WindowParser::stop() {
    if (!stop_condition) {
        stop_condition = true;
        thread.join();
    }
}

void WindowParser::handle(const window_msg &msg) {
#ifdef DEBUGPLUS
    if (!window_queue.try_enqueue(msg)) {
        logger::log(logger::WARNING, "drop window, queue is full");
    }
#else
    window_queue.try_enqueue(msg);
#endif
}

void WindowParser::handle(window_msg &&msg) {
#ifdef DEBUGPLUS
    if (!window_queue.try_enqueue(std::forward<window_msg>(msg))) {
        logger::log(logger::WARNING, "drop window, queue is full");
    }
#else
    window_queue.try_enqueue(std::forward<window_msg>(msg));
#endif
}

void WindowParser::run() {
    logger::log(logger::INFO, "window parser starts a parser thread with pid ", gettid());

    char buffer[1024];
    char src_addr[INET_ADDRSTRLEN];
    char dst_addr[INET_ADDRSTRLEN];
    window_msg msg;
    uint32_t count = 0;
    while (!stop_condition) {
        if (!window_queue.wait_dequeue_timed(msg, 100000)) {
            continue;
        }

        inet_ntop(AF_INET, &msg.src_addr, src_addr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &msg.dst_addr, dst_addr, INET_ADDRSTRLEN);

        send(sockfd, buffer, sprintf(buffer, R"(["%s",%hu,"%s",%hu,[%u,%hu,%u,%hu,%u],[%u,%hu,%u,%hu,%u]])",
             src_addr, bswap_16(msg.src_port), dst_addr, bswap_16(msg.dst_port),
             msg.up_pkt_cpt, msg.up_size_mean, msg.up_size_var, msg.up_iat_mean, msg.up_iat_var,
             msg.down_pkt_cpt, msg.down_size_mean, msg.down_size_var, msg.down_iat_mean, msg.down_iat_var), 0);
        ++count;
    }
    logger::log(logger::INFO, "window parser stops a parse thread with pid ", gettid());
    logger::log(logger::INFO, "window parser send ", count, " report(s) to remote");
}

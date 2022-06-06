#ifndef SNIFF_WINDOWPARSER_H
#define SNIFF_WINDOWPARSER_H

#include <thread>
#include <netinet/in.h>

#include "readerwriterqueue/readerwritercircularbuffer.h"
#include "windowsink.h"

class WindowParser : public WindowSink{
private:
    moodycamel::BlockingReaderWriterCircularBuffer<window_msg> window_queue;

#ifdef DEBUG
    uint64_t sum_queue_size = 0;
    uint64_t last_sum_queue_size = 0;
    uint64_t sum_win = 0;
    uint64_t last_sum_win = 0;
    uint64_t sum_win_parsing = 0;
    uint64_t last_sum_win_parsing = 0;
    bool info_stop_condition = true;
    std::thread info_thread;
#endif

    bool parser_stop_condition = true;
    std::thread parser_thread;

    sockaddr_in remote;
    int sockfd;

public:
    explicit WindowParser(const std::string &addr, uint16_t port, int queue_capacity=512);
    ~WindowParser() override;

    void start();
    void stop();

    void handle(const window_msg &msg) override;
    void handle(window_msg &&msg) override;

private:
#ifdef DEBUG
    void info();
#endif
    void run();
};


#endif //SNIFF_WINDOWPARSER_H

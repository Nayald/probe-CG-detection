#ifndef SNIFF_WINDOWPARSER_H
#define SNIFF_WINDOWPARSER_H

#include <thread>
#include <netinet/in.h>

#include "readerwriterqueue/readerwritercircularbuffer.h"
#include "windowsink.h"

class WindowParser : public WindowSink{
private:
    moodycamel::BlockingReaderWriterCircularBuffer<window_msg> window_queue;

    bool stop_condition = true;
    std::thread thread;

    sockaddr_in remote;

public:
    explicit WindowParser(const std::string addr, uint16_t port, int queue_capacity=512);
    ~WindowParser() override;

    void start();
    void stop();

    void handle(const window_msg &msg) override;
    void handle(window_msg &&msg) override;

private:
    void run();
};


#endif //SNIFF_WINDOWPARSER_H

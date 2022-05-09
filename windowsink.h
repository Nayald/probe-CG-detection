#ifndef SNIFF_WINDOWSINK_H
#define SNIFF_WINDOWSINK_H

#include <cstdint>

struct window_msg {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t up_size_mean;
    uint16_t up_iat_mean;
    uint32_t up_size_var;
    uint32_t up_iat_var;
    uint16_t down_size_mean;
    uint16_t down_iat_mean;
    uint32_t down_size_var;
    uint32_t down_iat_var;
};

class WindowSink {
public:
    WindowSink() = default;
    virtual ~WindowSink() = default;

    virtual void handle(const window_msg &msg) = 0;
    virtual void handle(window_msg &&msg) = 0;

};

#endif //SNIFF_WINDOWSINK_H

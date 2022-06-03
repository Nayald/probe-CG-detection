#ifndef SNIFF_WINDOWSINK_H
#define SNIFF_WINDOWSINK_H

#include <cstdint>
#include <vector>

#include "alignocator.h"

struct window_msg {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;

    std::vector<int32_t, alignocator<int32_t, 32>> up_sizes;
    std::vector<int32_t, alignocator<int32_t, 32>> down_sizes;
    std::vector<int32_t, alignocator<int32_t, 32>> up_iats;
    std::vector<int32_t, alignocator<int32_t, 32>> down_iats;
};

class WindowSink {
public:
    WindowSink() = default;
    virtual ~WindowSink() = default;

    virtual void handle(const window_msg &msg) = 0;
    virtual void handle(window_msg &&msg) = 0;
};

#endif //SNIFF_WINDOWSINK_H

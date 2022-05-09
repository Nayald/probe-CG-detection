#ifndef SNIFF_LOGGER_H
#define SNIFF_LOGGER_H

#include <iostream>
#include <fstream>
#include <array>

#include "spinlock.h"

namespace logger {
    enum Level {
        INFO,
        WARNING,
        ERROR,
    };

    extern spinlock lock;
    extern std::ofstream file;
    extern bool is_tee;
    extern Level level;

    void setFilename(const std::string &filename);

    void isTee(bool state);

    void setMinimalLogLevel(Level level);

    void log(Level l, const std::string &msg);

    template<typename ...Args>
    void log(Level l, Args &&...args) {
        static const std::array<std::string, 3> LEVEL_OUTPUT_STRINGS = {"[INFO] ", "[WARNING] ", "[ERROR] "};
        if (l >= level) {
            lock.lock();
            if (file.is_open()) {
                file << LEVEL_OUTPUT_STRINGS[l];
                (file << ... << args) << std::endl;
            }
            if (is_tee) {
                std::cout << LEVEL_OUTPUT_STRINGS[l];
                (std::cout << ... << args) << std::endl;
            }
            lock.unlock();
        }
    }
}

#endif //SNIFF_LOGGER_H
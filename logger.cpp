#include "logger.h"
#include <iostream>
#include <array>

namespace logger {
    spinlock lock;
    std::ofstream file;
    bool is_tee = true;
    Level level = INFO;
}

void logger::setFilename(const std::string &filename) {
    lock.lock();
    file.open(filename);
    if (!file) {
        std::cerr << "logger can't open this file" << std::endl;
    }
    lock.unlock();
}

void logger::isTee(bool state) {
    is_tee = state;
};

void logger::setMinimalLogLevel(Level l) {
    level = l;
}

void logger::log(Level l, const std::string &msg) {
    static const std::array<std::string, 3> LEVEL_OUTPUT_STRINGS = {"[INFO] ", "[WARNING] ", "[ERROR] "};
    lock.lock();
    if (l >= level) {
        if (file.is_open()) {
            file << LEVEL_OUTPUT_STRINGS[l] << msg << std::endl;
        }
        if (is_tee) {
            std::cout << LEVEL_OUTPUT_STRINGS[l] << msg << std::endl;
        }
    }
    lock.unlock();
}
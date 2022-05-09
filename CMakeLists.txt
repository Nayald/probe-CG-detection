cmake_minimum_required(VERSION 3.16)
project(sniffer)

set(CMAKE_CXX_STANDARD 17)
set(ABSL_PROPAGATE_CXX_STD ON)

add_compile_options(-Wall -Winline -std=c++17 -O2 -march=native -ftree-vectorize -fopt-info-vec-optimized)

add_definitions(-DDEBUG)

add_subdirectory(abseil-cpp)

include(FindPCAP.cmake)

find_package(Threads REQUIRED)

add_executable(sniffer main.cpp
        packetparser.cpp packetparser.h
        windowparser.cpp windowparser.h windowsink.h
        logger.cpp logger.h)

target_link_libraries(sniffer ${PCAP_LIBRARY} Threads::Threads absl::flat_hash_map)

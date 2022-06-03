cmake_minimum_required(VERSION 3.16)
project(sniffer)

set(CMAKE_CXX_STANDARD 17)
add_compile_options(-Wall -Winline -std=c++17 -O2 -march=native -ftree-vectorize -fopt-info-vec-optimized)

set(ABSL_PROPAGATE_CXX_STD ON)
add_subdirectory(abseil-cpp)

include(FindPCAP.cmake)
find_package(Threads REQUIRED)

add_definitions(-DDEBUG)
#add_definitions(-DCUSTOM_AVX)
#add_definitions(-DINT_MEAN_FEATURES)
add_definitions(-DINT_ALL_FEATURES)

add_executable(sniffer
        main.cpp
        logger.cpp logger.h
        packetparser.cpp packetparser.h
        windowparser.cpp windowparser.h windowsink.h
        )

target_link_libraries(sniffer ${PCAP_LIBRARY} Threads::Threads absl::flat_hash_map)

#include <unistd.h>
#include <arpa/inet.h>
#include <sstream>
#include <iomanip>
#include <byteswap.h>

#include "windowparser.h"
#include "logger.h"

#include <numeric>
#ifdef CUSTOM_AVX
#include <immintrin.h>
#include <tuple>
#include <cmath>

// https://stackoverflow.com/questions/6996764/fastest-way-to-do-horizontal-sse-vector-sum-or-other-reduction
inline float hsum256_ps(const __m256 &x) {
    __m128 sum128 = _mm_add_ps(_mm256_castps256_ps128(x), _mm256_extractf128_ps(x, 1));
    __m128 shuf = _mm_movehdup_ps(sum128); // broadcast elements 3,1 to 2,0
    __m128 sums = _mm_add_ps(sum128, shuf);
    shuf = _mm_movehl_ps(shuf, sums); // high half -> low half
    sums = _mm_add_ss(sums, shuf);
    return _mm_cvtss_f32(sums);
}

// https://stackoverflow.com/questions/60108658/fastest-method-to-calculate-sum-of-all-packed-32-bit-integers-using-avx512-or-av
inline int32_t hsum256_epi32(const __m256i &x) {
    __m128i sum128 = _mm_add_epi32(_mm256_castsi256_si128(x), _mm256_extracti128_si256(x, 1));
    __m128i hi64  = _mm_unpackhi_epi64(sum128, sum128); // 3-operand non-destructive AVX lets us save a byte without needing a movdqa
    __m128i sum64 = _mm_add_epi32(hi64, sum128);
    __m128i hi32  = _mm_shuffle_epi32(sum64, _MM_SHUFFLE(2, 3, 0, 1)); // Swap the low two elements
    __m128i sum32 = _mm_add_epi32(sum64, hi32);
    return _mm_cvtsi128_si32(sum32); // movd
}

#ifdef INT_ALL_FEATURES
std::tuple<int32_t, int32_t, int32_t , int32_t> avx2_compute(const std::vector<int32_t, alignocator<int32_t, 32>> &sizes, const std::vector<int32_t, alignocator<int32_t, 32>> &iats) {
#elif INT_MEAN_FEATURES
std::tuple<int32_t, int32_t, float , float> avx2_compute(const std::vector<int32_t, alignocator<int32_t, 32>> &sizes, const std::vector<int32_t, alignocator<int32_t, 32>> &iats) {
#else
std::tuple<float, float, float , float> avx2_compute(const std::vector<int32_t, alignocator<int32_t, 32>> &sizes, const std::vector<int32_t, alignocator<int32_t, 32>> &iats) {
#endif
    if (sizes.empty()) {
        return {0, 0, 0, 0};
    }

    size_t i, M, N;
    // loop unrolled 5 times
    M = 8 * 5;
    N = sizes.size() / M;

    __m256i s_size1 = _mm256_setzero_si256();
    __m256i s_iat1 = _mm256_setzero_si256();
    for (i = 0; i < N * M; i += M) {
        s_size1 = _mm256_add_epi32(s_size1, _mm256_load_si256((__m256i*)&sizes[i]));
        s_size1 = _mm256_add_epi32(s_size1, _mm256_load_si256((__m256i*)&sizes[i + 8]));
        s_size1 = _mm256_add_epi32(s_size1, _mm256_load_si256((__m256i*)&sizes[i + 8 * 2]));
        s_size1 = _mm256_add_epi32(s_size1, _mm256_load_si256((__m256i*)&sizes[i + 8 * 3]));
        s_size1 = _mm256_add_epi32(s_size1, _mm256_load_si256((__m256i*)&sizes[i + 8 * 4]));

        s_iat1 = _mm256_add_epi32(s_iat1, _mm256_load_si256((__m256i*)&iats[i]));
        s_iat1 = _mm256_add_epi32(s_iat1, _mm256_load_si256((__m256i*)&iats[i + 8]));
        s_iat1 = _mm256_add_epi32(s_iat1, _mm256_load_si256((__m256i*)&iats[i + 8 * 2]));
        s_iat1 = _mm256_add_epi32(s_iat1, _mm256_load_si256((__m256i*)&iats[i + 8 * 3]));
        s_iat1 = _mm256_add_epi32(s_iat1, _mm256_load_si256((__m256i*)&iats[i + 8 * 4]));
    }

    volatile int32_t &&tmp_size_mean = hsum256_epi32(s_size1);
    volatile int32_t &&tmp_iat_mean = hsum256_epi32(s_iat1);
    for (; i < sizes.size(); ++i) {
        tmp_size_mean += sizes[i];
        tmp_iat_mean += iats[i];
    }

#if defined(INT_ALL_FEATURES) || defined(INT_MEAN_FEATURES)
    const int32_t ret_size_mean = tmp_size_mean / sizes.size();
    const int32_t ret_iat_mean = tmp_iat_mean / sizes.size();
    const __m256i size_mean = _mm256_set1_epi32(ret_size_mean);
    const __m256i iat_mean = _mm256_set1_epi32(ret_iat_mean);
#else
    const float ret_size_mean = static_cast<float>(tmp_size_mean) / sizes.size();
    const float ret_iat_mean = static_cast<float>(tmp_iat_mean) / sizes.size();
    const __m256 size_mean = _mm256_set1_ps(ret_size_mean);
    const __m256 iat_mean = _mm256_set1_ps(ret_iat_mean);
#endif

    // loop unroll 3 times
    M = 8 * 3;
    N = sizes.size() / M;
#ifdef INT_ALL_FEATURES
    __m256i v_size1 = _mm256_setzero_si256();
    __m256i v_size2 = _mm256_setzero_si256();
    __m256i v_size3 = _mm256_setzero_si256();
    __m256i v_iat1 = _mm256_setzero_si256();
    __m256i v_iat2 = _mm256_setzero_si256();
    __m256i v_iat3 = _mm256_setzero_si256();
    for (i = 0; i < N * M; i += M) {
        const __m256i &&v1 = _mm256_sub_epi32(_mm256_load_si256((__m256i *)&sizes[i]), size_mean);
        const __m256i &&v2 = _mm256_sub_epi32(_mm256_load_si256((__m256i *)&sizes[i + 8]), size_mean);
        const __m256i &&v3 = _mm256_sub_epi32(_mm256_load_si256((__m256i *)&sizes[i + 8 * 2]), size_mean);
        v_size1 = _mm256_add_epi32(v_size1, _mm256_mullo_epi32(v1, v1));
        v_size2 = _mm256_add_epi32(v_size2, _mm256_mullo_epi32(v2, v2));
        v_size3 = _mm256_add_epi32(v_size3, _mm256_mullo_epi32(v3, v3));

        const __m256i &&v4 = _mm256_sub_epi32(_mm256_load_si256((__m256i*)&iats[i]), iat_mean);
        const __m256i &&v5 = _mm256_sub_epi32(_mm256_load_si256((__m256i*)&iats[i + 8]), iat_mean);
        const __m256i &&v6 = _mm256_sub_epi32(_mm256_load_si256((__m256i*)&iats[i + 8 * 2]), iat_mean);
        v_iat1 = _mm256_add_epi32(v_iat1, _mm256_mullo_epi32(v4, v4));
        v_iat2 = _mm256_add_epi32(v_iat2, _mm256_mullo_epi32(v5, v5));
        v_iat3 = _mm256_add_epi32(v_iat3, _mm256_mullo_epi32(v6, v6));
    }
    v_size1 = _mm256_add_epi32(_mm256_add_epi32(v_size1, v_size2), v_size3);
    v_iat1 = _mm256_add_epi32(_mm256_add_epi32(v_iat1, v_iat2), v_iat3);
#else
    __m256 v_size1 = _mm256_setzero_ps();
    __m256 v_size2 = _mm256_setzero_ps();
    __m256 v_size3 = _mm256_setzero_ps();
    __m256 v_iat1 = _mm256_setzero_ps();
    __m256 v_iat2 = _mm256_setzero_ps();
    __m256 v_iat3 = _mm256_setzero_ps();
    for (i = 0; i < N * M; i += M) {
#ifdef INT_MEAN_FEATURES
        const __m256 &&v1 = _mm256_cvtepi32_ps(_mm256_sub_epi32(_mm256_load_si256((__m256i*)&sizes[i]), size_mean));
        const __m256 &&v2 = _mm256_cvtepi32_ps(_mm256_sub_epi32(_mm256_load_si256((__m256i*)&sizes[i + 8]), size_mean));
        const __m256 &&v3 = _mm256_cvtepi32_ps(_mm256_sub_epi32(_mm256_load_si256((__m256i*)&sizes[i + 8 * 2]), size_mean));
#else
        const __m256 &&v1 = _mm256_sub_ps(_mm256_cvtepi32_ps(_mm256_load_si256((__m256i*)&sizes[i])), size_mean);
        const __m256 &&v2 = _mm256_sub_ps(_mm256_cvtepi32_ps(_mm256_load_si256((__m256i*)&sizes[i + 8])), size_mean);
        const __m256 &&v3 = _mm256_sub_ps(_mm256_cvtepi32_ps(_mm256_load_si256((__m256i*)&sizes[i + 8 * 2])), size_mean);
#endif
        v_size1 = _mm256_fmadd_ps(v1, v1, v_size1);
        v_size2 = _mm256_fmadd_ps(v2, v2, v_size2);
        v_size3 = _mm256_fmadd_ps(v3, v3, v_size3);

#ifdef INT_MEAN_FEATURES
        const __m256 &&v4 = _mm256_cvtepi32_ps(_mm256_sub_epi32(_mm256_load_si256((__m256i*)&iats[i]), iat_mean));
        const __m256 &&v5 = _mm256_cvtepi32_ps(_mm256_sub_epi32(_mm256_load_si256((__m256i*)&iats[i + 8]), iat_mean));
        const __m256 &&v6 = _mm256_cvtepi32_ps(_mm256_sub_epi32(_mm256_load_si256((__m256i*)&iats[i + 8 * 2]), iat_mean));
#else
        const __m256 &&v4 = _mm256_sub_ps(_mm256_cvtepi32_ps(_mm256_load_si256((__m256i*)&iats[i])), iat_mean);
        const __m256 &&v5 = _mm256_sub_ps(_mm256_cvtepi32_ps(_mm256_load_si256((__m256i*)&iats[i + 8])), iat_mean);
        const __m256 &&v6 = _mm256_sub_ps(_mm256_cvtepi32_ps(_mm256_load_si256((__m256i*)&iats[i + 8 * 2])), iat_mean);
#endif
        v_iat1 = _mm256_fmadd_ps(v4, v4, v_iat1);
        v_iat2 = _mm256_fmadd_ps(v5, v5, v_iat2);
        v_iat3 = _mm256_fmadd_ps(v6, v6, v_iat3);
    }
    v_size1 = _mm256_add_ps(v_size1, _mm256_add_ps(v_size2, v_size3));
    v_iat1 = _mm256_add_ps(v_iat1, _mm256_add_ps(v_iat2, v_iat3));
#endif

#if defined(INT_ALL_FEATURES) || defined(INT_MEAN_FEATURES)
    volatile int32_t &&tmp_size_var = 0;
    volatile int32_t &&tmp_iat_var = 0;
    for (; i < sizes.size(); ++i) {
        const int32_t &&size_sd = sizes[i] - ret_size_mean;
        tmp_size_var += size_sd * size_sd;
        const int32_t &&iat_sd = iats[i] - ret_iat_mean;
        tmp_iat_var += iat_sd * iat_sd;
    }

#if defined(INT_ALL_FEATURES)
    const int32_t ret_size_var = (hsum256_epi32(v_size1) + tmp_size_var) / sizes.size();
    const int32_t ret_iat_var = (hsum256_epi32(v_iat1) + tmp_iat_var) / sizes.size();
#else
    const float ret_size_var = (hsum256_ps(v_size1) + static_cast<float>(tmp_size_var)) / sizes.size();
    const float ret_iat_var = (hsum256_ps(v_iat1) + static_cast<float>(tmp_iat_var)) / sizes.size();
#endif
#else
    volatile float &&tmp_size_var = 0;
    volatile float &&tmp_iat_var = 0;
    for (; i < sizes.size(); ++i) {
        const float &&size_sd = static_cast<float>(sizes[i]) - ret_size_mean;
        tmp_size_var = std::fmaf(size_sd, size_sd, tmp_size_var);
        const float &&iat_sd = static_cast<float>(iats[i]) - ret_iat_mean;
        tmp_iat_var = std::fmaf(iat_sd, iat_sd, ret_iat_mean);
    }

    const float ret_size_var = (hsum256_ps(v_size1) + tmp_size_var) / sizes.size();
    const float ret_iat_var = (hsum256_ps(v_iat1) + tmp_iat_var) / sizes.size();
#endif

    return {ret_size_mean - 8 /*minus header size*/, ret_iat_mean, ret_size_var, ret_iat_var};
}
#endif

static constexpr std::chrono::seconds MANAGERSLEEPTIME{2};

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

#ifdef DEBUG
    info_stop_condition = false;
    info_thread = std::thread(&WindowParser::info, this);
#endif

    parser_stop_condition = false;
    parser_thread = std::thread(&WindowParser::run, this);
}

void WindowParser::stop() {
#ifdef DEBUG
    if (!info_stop_condition) {
        info_stop_condition = true;
        info_thread.join();
    }
#endif

    if (!parser_stop_condition) {
        parser_stop_condition = true;
        parser_thread.join();
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

#ifdef DEBUG
void WindowParser::info() {
    logger::log(logger::INFO, "window parser starts an info thread with pid ", gettid());

    std::stringstream ss;
    while (!parser_stop_condition) {
        const uint64_t &&sum_queue_size_delta = sum_queue_size - last_sum_queue_size;
        last_sum_queue_size = sum_queue_size;
        const uint64_t &&sum_win_delta = sum_win - last_sum_win;
        last_sum_win = sum_win;
        const uint64_t &&sum_win_parsing_delta = sum_win_parsing - last_sum_win_parsing;
        last_sum_win_parsing = sum_win_parsing;

        ss << "window parser info" << std::endl;
        ss << "\taverage window parser queue size = " << (sum_queue_size_delta ? sum_queue_size_delta / sum_win_delta : 0) << " / " << window_queue.max_capacity() << std::endl;

        ss << "\tcurrent parsing pace = " << sum_win_delta / MANAGERSLEEPTIME.count() << " wins/s" << std::endl;
        if (sum_win_delta > 0) {
            ss << std::fixed << std::setprecision(2) << "\t\taverage window handle time = " << static_cast<double>(sum_win_parsing_delta) / sum_win_delta << " ns" << std::endl;
            ss << std::fixed << std::setprecision(0) << "\t\testimated window compute capacity = " << 1'000'000'000. / (static_cast<double>(sum_win_parsing_delta) / sum_win_delta) << " (~" << sum_win_parsing_delta / 10'000'000 << "%)" << std::endl;
        }

        logger::log(logger::INFO, ss.str());
        ss.str({});
        ss.clear();

        std::this_thread::sleep_for(MANAGERSLEEPTIME);
    }
    logger::log(logger::INFO, "window parser stops an info thread with pid ", gettid());
}
#endif

void WindowParser::run() {
    logger::log(logger::INFO, "window parser starts a parser thread with pid ", gettid());

#ifdef CUSTOM_AVX
    logger::log(logger::INFO, "window parser will use customed AVX function for features");
#endif

#ifdef INT_ALL_FEATURES
    logger::log(logger::INFO, "window parser will compute mean and variance featues as integers");
    static const char *const pattern = R"(["%s",%hu,"%s",%hu,[%zu,%d,%d,%d,%d],[%zu,%d,%d,%d,%d]])";
#elif INT_MEAN_FEATURES
    logger::log(logger::INFO, "window parser will compute mean features as integers and variance as floats");
    static const char *const pattern = R"(["%s",%hu,"%s",%hu,[%zu,%d,%.8g,%d,%.8g],[%zu,%d,%.8g,%d,%.8g]])";
#else
    logger::log(logger::INFO, "window parser will compute mean and variance features as floats");
    static const char *const pattern = R"(["%s",%hu,"%s",%hu,[%zu,%.8g,%.8g,%.8g,%.8g],[%zu,%.8g,%.8g,%.8g,%.8g]])";
#endif

#ifdef DEBUG
    std::chrono::steady_clock::time_point start;
#endif

    char buffer[1024];
    char src_addr[INET_ADDRSTRLEN];
    char dst_addr[INET_ADDRSTRLEN];
    window_msg msg;
    uint32_t count = 0;
    while (!parser_stop_condition) {
        if (!window_queue.wait_dequeue_timed(msg, 100000)) {
            continue;
        }

#ifdef DEBUG
        sum_queue_size += window_queue.size_approx();
        ++sum_win;
        start = std::chrono::steady_clock::now();
#endif

#ifdef CUSTOM_AVX
        const auto [up_size_mean, up_iat_mean, up_size_var, up_iat_var] = avx2_compute(msg.up_sizes, msg.up_iats);
        const auto [down_size_mean, down_iat_mean, down_size_var, down_iat_var] = avx2_compute(msg.down_sizes, msg.down_iats);
#else
#if defined(INT_ALL_FEATURES) || defined(INT_MEAN_FEATURES)
        int32_t up_size_mean = 0;
        int32_t up_iat_mean = 0;
#else
        float up_size_mean = 0;
        float up_iat_mean = 0;
#endif
#ifdef INT_ALL_FEATURES
        uint32_t up_size_var = 0;
        uint32_t up_iat_var = 0;
#else
        float up_size_var = 0;
        float up_iat_var = 0;
#endif
        if (!msg.up_sizes.empty()) {
            const int32_t &&size_mean = std::accumulate(msg.up_sizes.cbegin(), msg.up_sizes.cend(), int32_t{0});
            const int32_t &&iat_mean = std::accumulate(msg.up_iats.cbegin(), msg.up_iats.cend(), int32_t{0});
#if defined(INT_ALL_FEATURES) || defined(INT_MEAN_FEATURES)
            up_size_mean = size_mean / msg.up_sizes.size();
            up_iat_mean = iat_mean / msg.up_sizes.size();
            const int32_t &&size_var = std::accumulate(msg.up_sizes.cbegin(), msg.up_sizes.cend(), int32_t{0},
                                          [mean = up_size_mean](int32_t acc, const int32_t e) {
                                              const int32_t &&diff = e - mean;
                                              return acc + diff * diff;
                                          });
            const int32_t &&iat_var = std::accumulate(msg.up_iats.cbegin(), msg.up_iats.cend(), int32_t{0},
                                         [mean = up_iat_mean](int32_t acc, const int32_t e) {
                                             const int32_t &&diff = e - mean;
                                             return acc + diff * diff;
                                         });
#ifdef INT_MEAN_FEATURES
            up_size_var = static_cast<float>(size_var) / msg.up_sizes.size();
            up_iat_var = static_cast<float>(iat_var) / msg.up_sizes.size();
#else
            up_size_var = size_var / msg.up_sizes.size();
            up_iat_var = iat_var / msg.up_sizes.size();
#endif
#else
            up_size_mean = static_cast<float>(size_mean) / msg.up_sizes.size();
            up_iat_mean = static_cast<float>(iat_mean) / msg.up_sizes.size();
            up_size_var = std::accumulate(msg.up_sizes.cbegin(), msg.up_sizes.cend(), float{0},
                                          [mean = up_size_mean](float acc, const int32_t e) {
                                              const float &&diff = e - mean;
                                              return acc + diff * diff;
                                          }) / msg.up_sizes.size();
            up_iat_var = std::accumulate(msg.up_iats.cbegin(), msg.up_iats.cend(), float{0},
                                          [mean = up_iat_mean](float acc, const int32_t e) {
                                              const float &&diff = e - mean;
                                              return acc + diff * diff;
                                          }) / msg.up_sizes.size();
#endif
            // preference for payload length
            up_size_mean -= 8;
        }

#if defined(INT_ALL_FEATURES) || defined(INT_MEAN_FEATURES)
        int32_t down_size_mean = 0;
        int32_t down_iat_mean = 0;
#else
        float down_size_mean = 0;
        float down_iat_mean = 0;
#endif
#ifdef INT_ALL_FEATURES
        uint32_t down_size_var = 0;
        uint32_t down_iat_var = 0;
#else
        float down_size_var = 0;
        float down_iat_var = 0;
#endif
        if (!msg.down_sizes.empty()) {
            const int32_t &&size_mean = std::accumulate(msg.down_sizes.cbegin(), msg.down_sizes.cend(), int32_t{0});
            const int32_t &&iat_mean = std::accumulate(msg.down_iats.cbegin(), msg.down_iats.cend(), int32_t{0});
#if defined(INT_ALL_FEATURES) || defined(INT_MEAN_FEATURES)
            down_size_mean = size_mean / msg.down_sizes.size();
            down_iat_mean = iat_mean / msg.down_sizes.size();
            const int32_t &&size_var = std::accumulate(msg.down_sizes.cbegin(), msg.down_sizes.cend(), int32_t{0},
                                          [mean = down_size_mean](int32_t acc, const int32_t e) {
                                              const int32_t &&diff = e - mean;
                                              return acc + diff * diff;
                                          });
            const int32_t &&iat_var = std::accumulate(msg.down_iats.cbegin(), msg.down_iats.cend(), int32_t{0},
                                          [mean = down_iat_mean](int32_t acc, const int32_t e) {
                                              const int32_t &&diff = e - mean;
                                              return acc + diff * diff;
                                          });
#ifdef INT_MEAN_FEATURES
            down_size_var = static_cast<float>(size_var) / msg.down_sizes.size();
            down_iat_var = static_cast<float>(iat_var) / msg.down_sizes.size();
#else
            down_size_var = size_var / msg.down_sizes.size();
            down_iat_var = iat_var / msg.down_sizes.size();
#endif
#else
            down_size_mean = static_cast<float>(size_mean) / msg.down_sizes.size();
            down_iat_mean = static_cast<float>(iat_mean) / msg.down_sizes.size();
            down_size_var = std::accumulate(msg.down_sizes.cbegin(), msg.down_sizes.cend(), float{0},
                                            [mean = down_size_mean](float acc, const int32_t e) {
                                                const auto &&diff = e - mean;
                                                return acc + diff * diff;
                                            }) / msg.down_sizes.size();
            down_iat_var = std::accumulate(msg.down_iats.cbegin(), msg.down_iats.cend(), float{0},
                                           [mean = down_iat_mean](float acc, const int32_t e) {
                                               const auto &&diff = e - mean;
                                               return acc + diff * diff;
                                           }) / msg.down_sizes.size();
#endif
            // preference for payload length
            down_size_mean -= 8;
        }
#endif

        inet_ntop(AF_INET, &msg.src_addr, src_addr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &msg.dst_addr, dst_addr, INET_ADDRSTRLEN);

        send(sockfd, buffer, sprintf(buffer, pattern,
             src_addr, bswap_16(msg.src_port), dst_addr, bswap_16(msg.dst_port),
             msg.up_sizes.size(), up_size_mean, up_size_var, up_iat_mean, up_iat_var,
             msg.down_sizes.size(), down_size_mean, down_size_var, down_iat_mean, down_iat_var), 0);
        ++count;

#ifdef DEBUG
    sum_win_parsing += std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - start).count();
#endif
    }
    logger::log(logger::INFO, "window parser stops a parse thread with pid ", gettid());
    logger::log(logger::INFO, "window parser send ", count, " report(s) to remote");
}

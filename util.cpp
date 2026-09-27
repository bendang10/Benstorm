#include "util.h"
#include <cstdlib>
#include <cerrno>
#include <stdexcept>

uint64_t parse_u64(const std::string& s) {
    if (s.empty()) throw std::runtime_error("parse_u64: empty string");
    errno = 0;
    char* end = nullptr;
    unsigned long long v = std::strtoull(s.c_str(), &end, 10);
    if (errno != 0 || end == s.c_str() || *end != '\0')
        throw std::runtime_error("parse_u64: bad number: " + s);
    return (uint64_t)v;
}

std::string hex_encode(const uint8_t* data, size_t len) {
    static const char* H = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(H[(data[i] >> 4) & 0x0F]);
        out.push_back(H[data[i] & 0x0F]);
    }
    return out;
}

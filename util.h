#pragma once
#include <cstdint>
#include <cstddef>
#include <string>

uint64_t parse_u64(const std::string& s);
std::string hex_encode(const uint8_t* data, size_t len);

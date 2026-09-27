#pragma once
#include <cstdint>
#include <cstddef>

void sha256(const uint8_t* data, size_t len, uint8_t out[32]);
void sha256d(const uint8_t* data, size_t len, uint8_t out[32]);
void ripemd160(const uint8_t* data, size_t len, uint8_t out[20]);

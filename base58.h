#pragma once
#include <cstdint>
#include <cstddef>
#include <string>

std::string base58check_encode(const uint8_t* payload, size_t len);

std::string pubkey_to_p2pkh_compressed(const uint8_t pub33[33]);
std::string pubkey_to_p2pkh_uncompressed(const uint8_t pub65[65]);
std::string pubkey_to_p2sh_compressed(const uint8_t pub33[33]);
std::string pubkey_to_p2sh_uncompressed(const uint8_t pub65[65]);

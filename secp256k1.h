#pragma once
#include <cstdint>

bool privkey_to_both_pubkeys(const uint8_t priv[32],
                              uint8_t pub33[33],
                              uint8_t pub65[65]);

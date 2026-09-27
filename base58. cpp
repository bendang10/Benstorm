#include "base58.h"
#include "crypto.h"
#include <cstring>
#include <vector>

static const char* B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static std::string base58_encode(const uint8_t* data, size_t len) {
    size_t zeros = 0;
    while (zeros < len && data[zeros] == 0) ++zeros;

    size_t size = (len - zeros) * 138 / 100 + 1;
    std::vector<uint8_t> b58(size, 0);
    size_t length = 0;

    for (size_t i = zeros; i < len; ++i) {
        int carry = data[i];
        size_t j = 0;
        for (auto it = b58.rbegin(); (carry != 0 || j < length) && it != b58.rend(); ++it, ++j) {
            carry += 256 * (*it);
            *it = (uint8_t)(carry % 58);
            carry /= 58;
        }
        length = j;
    }

    auto it = b58.begin() + (size - length);
    while (it != b58.end() && *it == 0) ++it;

    std::string out;
    out.reserve(zeros + (size_t)(b58.end() - it));
    out.assign(zeros, '1');
    for (; it != b58.end(); ++it) out.push_back(B58[*it]);
    return out;
}

std::string base58check_encode(const uint8_t* payload, size_t len) {
    uint8_t checksum[32];
    sha256d(payload, len, checksum);
    std::vector<uint8_t> buf(len + 4);
    std::memcpy(buf.data(), payload, len);
    std::memcpy(buf.data() + len, checksum, 4);
    return base58_encode(buf.data(), buf.size());
}

static std::string p2pkh_from_hash(const uint8_t h160[20]) {
    uint8_t payload[21];
    payload[0] = 0x00;
    std::memcpy(payload + 1, h160, 20);
    return base58check_encode(payload, 21);
}

static std::string p2sh_from_hash(const uint8_t h160[20]) {
    uint8_t payload[21];
    payload[0] = 0x05;
    std::memcpy(payload + 1, h160, 20);
    return base58check_encode(payload, 21);
}

static void hash160(const uint8_t* data, size_t len, uint8_t out[20]) {
    uint8_t h[32];
    sha256(data, len, h);
    ripemd160(h, 32, out);
}

std::string pubkey_to_p2pkh_compressed(const uint8_t pub33[33]) {
    uint8_t r[20];
    hash160(pub33, 33, r);
    return p2pkh_from_hash(r);
}

std::string pubkey_to_p2pkh_uncompressed(const uint8_t pub65[65]) {
    uint8_t r[20];
    hash160(pub65, 65, r);
    return p2pkh_from_hash(r);
}

static std::string p2sh_p2wpkh_from_pubkey(const uint8_t* pub, size_t plen) {
    uint8_t r[20];
    hash160(pub, plen, r);
    uint8_t script[22];
    script[0] = 0x00;
    script[1] = 0x14;
    std::memcpy(script + 2, r, 20);
    uint8_t r2[20];
    hash160(script, 22, r2);
    return p2sh_from_hash(r2);
}

std::string pubkey_to_p2sh_compressed(const uint8_t pub33[33]) {
    return p2sh_p2wpkh_from_pubkey(pub33, 33);
}

std::string pubkey_to_p2sh_uncompressed(const uint8_t pub65[65]) {
    return p2sh_p2wpkh_from_pubkey(pub65, 65);
}

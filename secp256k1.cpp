#include "secp256k1.h"
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>

namespace {

struct ThreadCtx {
    BN_CTX* ctx = nullptr;
    EC_GROUP* group = nullptr;
    BIGNUM* order = nullptr;

    ~ThreadCtx() { cleanup(); }

    void cleanup() {
        if (order) { BN_free(order); order = nullptr; }
        if (group) { EC_GROUP_free(group); group = nullptr; }
        if (ctx)   { BN_CTX_free(ctx);   ctx = nullptr; }
    }

    bool init() {
        if (ctx && group && order) return true;

        cleanup();

        ctx = BN_CTX_new();
        if (!ctx) return false;

        group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        if (!group) { cleanup(); return false; }

        order = BN_new();
        if (!order) { cleanup(); return false; }

        if (!EC_GROUP_get_order(group, order, ctx)) { cleanup(); return false; }

        return true;
    }
};

thread_local ThreadCtx tl_ctx;

} // namespace

bool privkey_to_both_pubkeys(const uint8_t priv[32],
                              uint8_t pub33[33],
                              uint8_t pub65[65]) {
    if (!tl_ctx.init()) return false;

    BIGNUM* d = BN_bin2bn(priv, 32, nullptr);
    if (!d) return false;

    if (BN_is_zero(d) || BN_cmp(d, tl_ctx.order) >= 0) {
        BN_free(d);
        return false;
    }

    EC_POINT* pub = EC_POINT_new(tl_ctx.group);
    if (!pub) { BN_free(d); return false; }

    if (!EC_POINT_mul(tl_ctx.group, pub, d, nullptr, nullptr, tl_ctx.ctx)) {
        EC_POINT_free(pub);
        BN_free(d);
        return false;
    }

    size_t n33 = EC_POINT_point2oct(tl_ctx.group, pub, POINT_CONVERSION_COMPRESSED,
                                     pub33, 33, tl_ctx.ctx);
    size_t n65 = EC_POINT_point2oct(tl_ctx.group, pub, POINT_CONVERSION_UNCOMPRESSED,
                                     pub65, 65, tl_ctx.ctx);

    EC_POINT_free(pub);
    BN_free(d);

    return (n33 == 33) && (n65 == 65);
}

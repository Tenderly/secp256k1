/**********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef lw_secp256k1_MODULE_ECDH_MAIN_H
#define lw_secp256k1_MODULE_ECDH_MAIN_H

#include "include/secp256k1_ecdh.h"
#include "ecmult_const_impl.h"

static int ecdh_hash_function_sha256(unsigned char *output, const unsigned char *x32, const unsigned char *y32, void *data) {
    unsigned char version = (y32[31] & 0x01) | 0x02;
    lw_secp256k1_sha256 sha;
    (void)data;

    lw_secp256k1_sha256_initialize(&sha);
    lw_secp256k1_sha256_write(&sha, &version, 1);
    lw_secp256k1_sha256_write(&sha, x32, 32);
    lw_secp256k1_sha256_finalize(&sha, output);

    return 1;
}

const lw_secp256k1_ecdh_hash_function lw_secp256k1_ecdh_hash_function_sha256 = ecdh_hash_function_sha256;
const lw_secp256k1_ecdh_hash_function lw_secp256k1_ecdh_hash_function_default = ecdh_hash_function_sha256;

int lw_secp256k1_ecdh(const lw_secp256k1_context* ctx, unsigned char *output, const lw_secp256k1_pubkey *point, const unsigned char *scalar, lw_secp256k1_ecdh_hash_function hashfp, void *data) {
    int ret = 0;
    int overflow = 0;
    lw_secp256k1_gej res;
    lw_secp256k1_ge pt;
    lw_secp256k1_scalar s;
    unsigned char x[32];
    unsigned char y[32];

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output != NULL);
    ARG_CHECK(point != NULL);
    ARG_CHECK(scalar != NULL);

    if (hashfp == NULL) {
        hashfp = lw_secp256k1_ecdh_hash_function_default;
    }

    lw_secp256k1_pubkey_load(ctx, &pt, point);
    lw_secp256k1_scalar_set_b32(&s, scalar, &overflow);

    overflow |= lw_secp256k1_scalar_is_zero(&s);
    lw_secp256k1_scalar_cmov(&s, &lw_secp256k1_scalar_one, overflow);

    lw_secp256k1_ecmult_const(&res, &pt, &s, 256);
    lw_secp256k1_ge_set_gej(&pt, &res);

    /* Compute a hash of the point */
    lw_secp256k1_fe_normalize(&pt.x);
    lw_secp256k1_fe_normalize(&pt.y);
    lw_secp256k1_fe_get_b32(x, &pt.x);
    lw_secp256k1_fe_get_b32(y, &pt.y);

    ret = hashfp(output, x, y, data);

    memset(x, 0, 32);
    memset(y, 0, 32);
    lw_secp256k1_scalar_clear(&s);

    return !!ret & !overflow;
}

#endif /* lw_secp256k1_MODULE_ECDH_MAIN_H */

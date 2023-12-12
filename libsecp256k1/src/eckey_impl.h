/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef lw_secp256k1_ECKEY_IMPL_H
#define lw_secp256k1_ECKEY_IMPL_H

#include "eckey.h"

#include "scalar.h"
#include "field.h"
#include "group.h"
#include "ecmult_gen.h"

static int lw_secp256k1_eckey_pubkey_parse(lw_secp256k1_ge *elem, const unsigned char *pub, size_t size) {
    if (size == 33 && (pub[0] == lw_secp256k1_TAG_PUBKEY_EVEN || pub[0] == lw_secp256k1_TAG_PUBKEY_ODD)) {
        lw_secp256k1_fe x;
        return lw_secp256k1_fe_set_b32(&x, pub+1) && lw_secp256k1_ge_set_xo_var(elem, &x, pub[0] == lw_secp256k1_TAG_PUBKEY_ODD);
    } else if (size == 65 && (pub[0] == lw_secp256k1_TAG_PUBKEY_UNCOMPRESSED || pub[0] == lw_secp256k1_TAG_PUBKEY_HYBRID_EVEN || pub[0] == lw_secp256k1_TAG_PUBKEY_HYBRID_ODD)) {
        lw_secp256k1_fe x, y;
        if (!lw_secp256k1_fe_set_b32(&x, pub+1) || !lw_secp256k1_fe_set_b32(&y, pub+33)) {
            return 0;
        }
        lw_secp256k1_ge_set_xy(elem, &x, &y);
        if ((pub[0] == lw_secp256k1_TAG_PUBKEY_HYBRID_EVEN || pub[0] == lw_secp256k1_TAG_PUBKEY_HYBRID_ODD) &&
            lw_secp256k1_fe_is_odd(&y) != (pub[0] == lw_secp256k1_TAG_PUBKEY_HYBRID_ODD)) {
            return 0;
        }
        return lw_secp256k1_ge_is_valid_var(elem);
    } else {
        return 0;
    }
}

static int lw_secp256k1_eckey_pubkey_serialize(lw_secp256k1_ge *elem, unsigned char *pub, size_t *size, int compressed) {
    if (lw_secp256k1_ge_is_infinity(elem)) {
        return 0;
    }
    lw_secp256k1_fe_normalize_var(&elem->x);
    lw_secp256k1_fe_normalize_var(&elem->y);
    lw_secp256k1_fe_get_b32(&pub[1], &elem->x);
    if (compressed) {
        *size = 33;
        pub[0] = lw_secp256k1_fe_is_odd(&elem->y) ? lw_secp256k1_TAG_PUBKEY_ODD : lw_secp256k1_TAG_PUBKEY_EVEN;
    } else {
        *size = 65;
        pub[0] = lw_secp256k1_TAG_PUBKEY_UNCOMPRESSED;
        lw_secp256k1_fe_get_b32(&pub[33], &elem->y);
    }
    return 1;
}

static int lw_secp256k1_eckey_privkey_tweak_add(lw_secp256k1_scalar *key, const lw_secp256k1_scalar *tweak) {
    lw_secp256k1_scalar_add(key, key, tweak);
    return !lw_secp256k1_scalar_is_zero(key);
}

static int lw_secp256k1_eckey_pubkey_tweak_add(const lw_secp256k1_ecmult_context *ctx, lw_secp256k1_ge *key, const lw_secp256k1_scalar *tweak) {
    lw_secp256k1_gej pt;
    lw_secp256k1_scalar one;
    lw_secp256k1_gej_set_ge(&pt, key);
    lw_secp256k1_scalar_set_int(&one, 1);
    lw_secp256k1_ecmult(ctx, &pt, &pt, &one, tweak);

    if (lw_secp256k1_gej_is_infinity(&pt)) {
        return 0;
    }
    lw_secp256k1_ge_set_gej(key, &pt);
    return 1;
}

static int lw_secp256k1_eckey_privkey_tweak_mul(lw_secp256k1_scalar *key, const lw_secp256k1_scalar *tweak) {
    int ret;
    ret = !lw_secp256k1_scalar_is_zero(tweak);

    lw_secp256k1_scalar_mul(key, key, tweak);
    return ret;
}

static int lw_secp256k1_eckey_pubkey_tweak_mul(const lw_secp256k1_ecmult_context *ctx, lw_secp256k1_ge *key, const lw_secp256k1_scalar *tweak) {
    lw_secp256k1_scalar zero;
    lw_secp256k1_gej pt;
    if (lw_secp256k1_scalar_is_zero(tweak)) {
        return 0;
    }

    lw_secp256k1_scalar_set_int(&zero, 0);
    lw_secp256k1_gej_set_ge(&pt, key);
    lw_secp256k1_ecmult(ctx, &pt, &pt, tweak, &zero);
    lw_secp256k1_ge_set_gej(key, &pt);
    return 1;
}

#endif /* lw_secp256k1_ECKEY_IMPL_H */

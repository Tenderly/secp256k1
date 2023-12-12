/**********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef lw_secp256k1_SCALAR_REPR_IMPL_H
#define lw_secp256k1_SCALAR_REPR_IMPL_H

#include "scalar.h"

#include <string.h>

lw_secp256k1_INLINE static int lw_secp256k1_scalar_is_even(const lw_secp256k1_scalar *a) {
    return !(*a & 1);
}

lw_secp256k1_INLINE static void lw_secp256k1_scalar_clear(lw_secp256k1_scalar *r) { *r = 0; }
lw_secp256k1_INLINE static void lw_secp256k1_scalar_set_int(lw_secp256k1_scalar *r, unsigned int v) { *r = v; }

lw_secp256k1_INLINE static unsigned int lw_secp256k1_scalar_get_bits(const lw_secp256k1_scalar *a, unsigned int offset, unsigned int count) {
    if (offset < 32)
        return ((*a >> offset) & ((((uint32_t)1) << count) - 1));
    else
        return 0;
}

lw_secp256k1_INLINE static unsigned int lw_secp256k1_scalar_get_bits_var(const lw_secp256k1_scalar *a, unsigned int offset, unsigned int count) {
    return lw_secp256k1_scalar_get_bits(a, offset, count);
}

lw_secp256k1_INLINE static int lw_secp256k1_scalar_check_overflow(const lw_secp256k1_scalar *a) { return *a >= EXHAUSTIVE_TEST_ORDER; }

static int lw_secp256k1_scalar_add(lw_secp256k1_scalar *r, const lw_secp256k1_scalar *a, const lw_secp256k1_scalar *b) {
    *r = (*a + *b) % EXHAUSTIVE_TEST_ORDER;
    return *r < *b;
}

static void lw_secp256k1_scalar_cadd_bit(lw_secp256k1_scalar *r, unsigned int bit, int flag) {
    if (flag && bit < 32)
        *r += ((uint32_t)1 << bit);
#ifdef VERIFY
    VERIFY_CHECK(bit < 32);
    /* Verify that adding (1 << bit) will not overflow any in-range scalar *r by overflowing the underlying uint32_t. */
    VERIFY_CHECK(((uint32_t)1 << bit) - 1 <= UINT32_MAX - EXHAUSTIVE_TEST_ORDER);
    VERIFY_CHECK(lw_secp256k1_scalar_check_overflow(r) == 0);
#endif
}

static void lw_secp256k1_scalar_set_b32(lw_secp256k1_scalar *r, const unsigned char *b32, int *overflow) {
    const int base = 0x100 % EXHAUSTIVE_TEST_ORDER;
    int i;
    *r = 0;
    for (i = 0; i < 32; i++) {
       *r = ((*r * base) + b32[i]) % EXHAUSTIVE_TEST_ORDER;
    }
    /* just deny overflow, it basically always happens */
    if (overflow) *overflow = 0;
}

static void lw_secp256k1_scalar_get_b32(unsigned char *bin, const lw_secp256k1_scalar* a) {
    memset(bin, 0, 32);
    bin[28] = *a >> 24; bin[29] = *a >> 16; bin[30] = *a >> 8; bin[31] = *a;
}

lw_secp256k1_INLINE static int lw_secp256k1_scalar_is_zero(const lw_secp256k1_scalar *a) {
    return *a == 0;
}

static void lw_secp256k1_scalar_negate(lw_secp256k1_scalar *r, const lw_secp256k1_scalar *a) {
    if (*a == 0) {
        *r = 0;
    } else {
        *r = EXHAUSTIVE_TEST_ORDER - *a;
    }
}

lw_secp256k1_INLINE static int lw_secp256k1_scalar_is_one(const lw_secp256k1_scalar *a) {
    return *a == 1;
}

static int lw_secp256k1_scalar_is_high(const lw_secp256k1_scalar *a) {
    return *a > EXHAUSTIVE_TEST_ORDER / 2;
}

static int lw_secp256k1_scalar_cond_negate(lw_secp256k1_scalar *r, int flag) {
    if (flag) lw_secp256k1_scalar_negate(r, r);
    return flag ? -1 : 1;
}

static void lw_secp256k1_scalar_mul(lw_secp256k1_scalar *r, const lw_secp256k1_scalar *a, const lw_secp256k1_scalar *b) {
    *r = (*a * *b) % EXHAUSTIVE_TEST_ORDER;
}

static int lw_secp256k1_scalar_shr_int(lw_secp256k1_scalar *r, int n) {
    int ret;
    VERIFY_CHECK(n > 0);
    VERIFY_CHECK(n < 16);
    ret = *r & ((1 << n) - 1);
    *r >>= n;
    return ret;
}

static void lw_secp256k1_scalar_sqr(lw_secp256k1_scalar *r, const lw_secp256k1_scalar *a) {
    *r = (*a * *a) % EXHAUSTIVE_TEST_ORDER;
}

static void lw_secp256k1_scalar_split_128(lw_secp256k1_scalar *r1, lw_secp256k1_scalar *r2, const lw_secp256k1_scalar *a) {
    *r1 = *a;
    *r2 = 0;
}

lw_secp256k1_INLINE static int lw_secp256k1_scalar_eq(const lw_secp256k1_scalar *a, const lw_secp256k1_scalar *b) {
    return *a == *b;
}

static lw_secp256k1_INLINE void lw_secp256k1_scalar_cmov(lw_secp256k1_scalar *r, const lw_secp256k1_scalar *a, int flag) {
    uint32_t mask0, mask1;
    mask0 = flag + ~((uint32_t)0);
    mask1 = ~mask0;
    *r = (*r & mask0) | (*a & mask1);
}

#endif /* lw_secp256k1_SCALAR_REPR_IMPL_H */

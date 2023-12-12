/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef lw_secp256k1_FIELD_IMPL_H
#define lw_secp256k1_FIELD_IMPL_H

#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif

#include "util.h"
#include "num.h"

#if defined(USE_FIELD_10X26)
#include "field_10x26_impl.h"
#elif defined(USE_FIELD_5X52)
#include "field_5x52_impl.h"
#else
#error "Please select field implementation"
#endif

lw_secp256k1_INLINE static int lw_secp256k1_fe_equal(const lw_secp256k1_fe *a, const lw_secp256k1_fe *b) {
    lw_secp256k1_fe na;
    lw_secp256k1_fe_negate(&na, a, 1);
    lw_secp256k1_fe_add(&na, b);
    return lw_secp256k1_fe_normalizes_to_zero(&na);
}

lw_secp256k1_INLINE static int lw_secp256k1_fe_equal_var(const lw_secp256k1_fe *a, const lw_secp256k1_fe *b) {
    lw_secp256k1_fe na;
    lw_secp256k1_fe_negate(&na, a, 1);
    lw_secp256k1_fe_add(&na, b);
    return lw_secp256k1_fe_normalizes_to_zero_var(&na);
}

static int lw_secp256k1_fe_sqrt(lw_secp256k1_fe *r, const lw_secp256k1_fe *a) {
    /** Given that p is congruent to 3 mod 4, we can compute the square root of
     *  a mod p as the (p+1)/4'th power of a.
     *
     *  As (p+1)/4 is an even number, it will have the same result for a and for
     *  (-a). Only one of these two numbers actually has a square root however,
     *  so we test at the end by squaring and comparing to the input.
     *  Also because (p+1)/4 is an even number, the computed square root is
     *  itself always a square (a ** ((p+1)/4) is the square of a ** ((p+1)/8)).
     */
    lw_secp256k1_fe x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t1;
    int j;

    VERIFY_CHECK(r != a);

    /** The binary representation of (p + 1)/4 has 3 blocks of 1s, with lengths in
     *  { 2, 22, 223 }. Use an addition chain to calculate 2^n - 1 for each block:
     *  1, [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]
     */

    lw_secp256k1_fe_sqr(&x2, a);
    lw_secp256k1_fe_mul(&x2, &x2, a);

    lw_secp256k1_fe_sqr(&x3, &x2);
    lw_secp256k1_fe_mul(&x3, &x3, a);

    x6 = x3;
    for (j=0; j<3; j++) {
        lw_secp256k1_fe_sqr(&x6, &x6);
    }
    lw_secp256k1_fe_mul(&x6, &x6, &x3);

    x9 = x6;
    for (j=0; j<3; j++) {
        lw_secp256k1_fe_sqr(&x9, &x9);
    }
    lw_secp256k1_fe_mul(&x9, &x9, &x3);

    x11 = x9;
    for (j=0; j<2; j++) {
        lw_secp256k1_fe_sqr(&x11, &x11);
    }
    lw_secp256k1_fe_mul(&x11, &x11, &x2);

    x22 = x11;
    for (j=0; j<11; j++) {
        lw_secp256k1_fe_sqr(&x22, &x22);
    }
    lw_secp256k1_fe_mul(&x22, &x22, &x11);

    x44 = x22;
    for (j=0; j<22; j++) {
        lw_secp256k1_fe_sqr(&x44, &x44);
    }
    lw_secp256k1_fe_mul(&x44, &x44, &x22);

    x88 = x44;
    for (j=0; j<44; j++) {
        lw_secp256k1_fe_sqr(&x88, &x88);
    }
    lw_secp256k1_fe_mul(&x88, &x88, &x44);

    x176 = x88;
    for (j=0; j<88; j++) {
        lw_secp256k1_fe_sqr(&x176, &x176);
    }
    lw_secp256k1_fe_mul(&x176, &x176, &x88);

    x220 = x176;
    for (j=0; j<44; j++) {
        lw_secp256k1_fe_sqr(&x220, &x220);
    }
    lw_secp256k1_fe_mul(&x220, &x220, &x44);

    x223 = x220;
    for (j=0; j<3; j++) {
        lw_secp256k1_fe_sqr(&x223, &x223);
    }
    lw_secp256k1_fe_mul(&x223, &x223, &x3);

    /* The final result is then assembled using a sliding window over the blocks. */

    t1 = x223;
    for (j=0; j<23; j++) {
        lw_secp256k1_fe_sqr(&t1, &t1);
    }
    lw_secp256k1_fe_mul(&t1, &t1, &x22);
    for (j=0; j<6; j++) {
        lw_secp256k1_fe_sqr(&t1, &t1);
    }
    lw_secp256k1_fe_mul(&t1, &t1, &x2);
    lw_secp256k1_fe_sqr(&t1, &t1);
    lw_secp256k1_fe_sqr(r, &t1);

    /* Check that a square root was actually calculated */

    lw_secp256k1_fe_sqr(&t1, r);
    return lw_secp256k1_fe_equal(&t1, a);
}

static void lw_secp256k1_fe_inv(lw_secp256k1_fe *r, const lw_secp256k1_fe *a) {
    lw_secp256k1_fe x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t1;
    int j;

    /** The binary representation of (p - 2) has 5 blocks of 1s, with lengths in
     *  { 1, 2, 22, 223 }. Use an addition chain to calculate 2^n - 1 for each block:
     *  [1], [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]
     */

    lw_secp256k1_fe_sqr(&x2, a);
    lw_secp256k1_fe_mul(&x2, &x2, a);

    lw_secp256k1_fe_sqr(&x3, &x2);
    lw_secp256k1_fe_mul(&x3, &x3, a);

    x6 = x3;
    for (j=0; j<3; j++) {
        lw_secp256k1_fe_sqr(&x6, &x6);
    }
    lw_secp256k1_fe_mul(&x6, &x6, &x3);

    x9 = x6;
    for (j=0; j<3; j++) {
        lw_secp256k1_fe_sqr(&x9, &x9);
    }
    lw_secp256k1_fe_mul(&x9, &x9, &x3);

    x11 = x9;
    for (j=0; j<2; j++) {
        lw_secp256k1_fe_sqr(&x11, &x11);
    }
    lw_secp256k1_fe_mul(&x11, &x11, &x2);

    x22 = x11;
    for (j=0; j<11; j++) {
        lw_secp256k1_fe_sqr(&x22, &x22);
    }
    lw_secp256k1_fe_mul(&x22, &x22, &x11);

    x44 = x22;
    for (j=0; j<22; j++) {
        lw_secp256k1_fe_sqr(&x44, &x44);
    }
    lw_secp256k1_fe_mul(&x44, &x44, &x22);

    x88 = x44;
    for (j=0; j<44; j++) {
        lw_secp256k1_fe_sqr(&x88, &x88);
    }
    lw_secp256k1_fe_mul(&x88, &x88, &x44);

    x176 = x88;
    for (j=0; j<88; j++) {
        lw_secp256k1_fe_sqr(&x176, &x176);
    }
    lw_secp256k1_fe_mul(&x176, &x176, &x88);

    x220 = x176;
    for (j=0; j<44; j++) {
        lw_secp256k1_fe_sqr(&x220, &x220);
    }
    lw_secp256k1_fe_mul(&x220, &x220, &x44);

    x223 = x220;
    for (j=0; j<3; j++) {
        lw_secp256k1_fe_sqr(&x223, &x223);
    }
    lw_secp256k1_fe_mul(&x223, &x223, &x3);

    /* The final result is then assembled using a sliding window over the blocks. */

    t1 = x223;
    for (j=0; j<23; j++) {
        lw_secp256k1_fe_sqr(&t1, &t1);
    }
    lw_secp256k1_fe_mul(&t1, &t1, &x22);
    for (j=0; j<5; j++) {
        lw_secp256k1_fe_sqr(&t1, &t1);
    }
    lw_secp256k1_fe_mul(&t1, &t1, a);
    for (j=0; j<3; j++) {
        lw_secp256k1_fe_sqr(&t1, &t1);
    }
    lw_secp256k1_fe_mul(&t1, &t1, &x2);
    for (j=0; j<2; j++) {
        lw_secp256k1_fe_sqr(&t1, &t1);
    }
    lw_secp256k1_fe_mul(r, a, &t1);
}

static void lw_secp256k1_fe_inv_var(lw_secp256k1_fe *r, const lw_secp256k1_fe *a) {
#if defined(USE_FIELD_INV_BUILTIN)
    lw_secp256k1_fe_inv(r, a);
#elif defined(USE_FIELD_INV_NUM)
    lw_secp256k1_num n, m;
    static const lw_secp256k1_fe negone = lw_secp256k1_FE_CONST(
        0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL,
        0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFEUL, 0xFFFFFC2EUL
    );
    /* secp256k1 field prime, value p defined in "Standards for Efficient Cryptography" (SEC2) 2.7.1. */
    static const unsigned char prime[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F
    };
    unsigned char b[32];
    int res;
    lw_secp256k1_fe c = *a;
    lw_secp256k1_fe_normalize_var(&c);
    lw_secp256k1_fe_get_b32(b, &c);
    lw_secp256k1_num_set_bin(&n, b, 32);
    lw_secp256k1_num_set_bin(&m, prime, 32);
    lw_secp256k1_num_mod_inverse(&n, &n, &m);
    lw_secp256k1_num_get_bin(b, 32, &n);
    res = lw_secp256k1_fe_set_b32(r, b);
    (void)res;
    VERIFY_CHECK(res);
    /* Verify the result is the (unique) valid inverse using non-GMP code. */
    lw_secp256k1_fe_mul(&c, &c, r);
    lw_secp256k1_fe_add(&c, &negone);
    CHECK(lw_secp256k1_fe_normalizes_to_zero_var(&c));
#else
#error "Please select field inverse implementation"
#endif
}

static void lw_secp256k1_fe_inv_all_var(lw_secp256k1_fe *r, const lw_secp256k1_fe *a, size_t len) {
    lw_secp256k1_fe u;
    size_t i;
    if (len < 1) {
        return;
    }

    VERIFY_CHECK((r + len <= a) || (a + len <= r));

    r[0] = a[0];

    i = 0;
    while (++i < len) {
        lw_secp256k1_fe_mul(&r[i], &r[i - 1], &a[i]);
    }

    lw_secp256k1_fe_inv_var(&u, &r[--i]);

    while (i > 0) {
        size_t j = i--;
        lw_secp256k1_fe_mul(&r[j], &r[i], &u);
        lw_secp256k1_fe_mul(&u, &u, &a[j]);
    }

    r[0] = u;
}

static int lw_secp256k1_fe_is_quad_var(const lw_secp256k1_fe *a) {
#ifndef USE_NUM_NONE
    unsigned char b[32];
    lw_secp256k1_num n;
    lw_secp256k1_num m;
    /* secp256k1 field prime, value p defined in "Standards for Efficient Cryptography" (SEC2) 2.7.1. */
    static const unsigned char prime[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F
    };

    lw_secp256k1_fe c = *a;
    lw_secp256k1_fe_normalize_var(&c);
    lw_secp256k1_fe_get_b32(b, &c);
    lw_secp256k1_num_set_bin(&n, b, 32);
    lw_secp256k1_num_set_bin(&m, prime, 32);
    return lw_secp256k1_num_jacobi(&n, &m) >= 0;
#else
    lw_secp256k1_fe r;
    return lw_secp256k1_fe_sqrt(&r, a);
#endif
}

static const lw_secp256k1_fe lw_secp256k1_fe_one = lw_secp256k1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1);

#endif /* lw_secp256k1_FIELD_IMPL_H */

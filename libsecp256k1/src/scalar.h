/**********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef lw_secp256k1_SCALAR_H
#define lw_secp256k1_SCALAR_H

#include "num.h"

#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif

#if defined(EXHAUSTIVE_TEST_ORDER)
#include "scalar_low.h"
#elif defined(USE_SCALAR_4X64)
#include "scalar_4x64.h"
#elif defined(USE_SCALAR_8X32)
#include "scalar_8x32.h"
#else
#error "Please select scalar implementation"
#endif

/** Clear a scalar to prevent the leak of sensitive data. */
static void lw_secp256k1_scalar_clear(lw_secp256k1_scalar *r);

/** Access bits from a scalar. All requested bits must belong to the same 32-bit limb. */
static unsigned int lw_secp256k1_scalar_get_bits(const lw_secp256k1_scalar *a, unsigned int offset, unsigned int count);

/** Access bits from a scalar. Not constant time. */
static unsigned int lw_secp256k1_scalar_get_bits_var(const lw_secp256k1_scalar *a, unsigned int offset, unsigned int count);

/** Set a scalar from a big endian byte array. The scalar will be reduced modulo group order `n`.
 * In:      bin:        pointer to a 32-byte array.
 * Out:     r:          scalar to be set.
 *          overflow:   non-zero if the scalar was bigger or equal to `n` before reduction, zero otherwise (can be NULL).
 */
static void lw_secp256k1_scalar_set_b32(lw_secp256k1_scalar *r, const unsigned char *bin, int *overflow);

/** Set a scalar from a big endian byte array and returns 1 if it is a valid
 *  seckey and 0 otherwise. */
static int lw_secp256k1_scalar_set_b32_seckey(lw_secp256k1_scalar *r, const unsigned char *bin);

/** Set a scalar to an unsigned integer. */
static void lw_secp256k1_scalar_set_int(lw_secp256k1_scalar *r, unsigned int v);

/** Convert a scalar to a byte array. */
static void lw_secp256k1_scalar_get_b32(unsigned char *bin, const lw_secp256k1_scalar* a);

/** Add two scalars together (modulo the group order). Returns whether it overflowed. */
static int lw_secp256k1_scalar_add(lw_secp256k1_scalar *r, const lw_secp256k1_scalar *a, const lw_secp256k1_scalar *b);

/** Conditionally add a power of two to a scalar. The result is not allowed to overflow. */
static void lw_secp256k1_scalar_cadd_bit(lw_secp256k1_scalar *r, unsigned int bit, int flag);

/** Multiply two scalars (modulo the group order). */
static void lw_secp256k1_scalar_mul(lw_secp256k1_scalar *r, const lw_secp256k1_scalar *a, const lw_secp256k1_scalar *b);

/** Shift a scalar right by some amount strictly between 0 and 16, returning
 *  the low bits that were shifted off */
static int lw_secp256k1_scalar_shr_int(lw_secp256k1_scalar *r, int n);

/** Compute the square of a scalar (modulo the group order). */
static void lw_secp256k1_scalar_sqr(lw_secp256k1_scalar *r, const lw_secp256k1_scalar *a);

/** Compute the inverse of a scalar (modulo the group order). */
static void lw_secp256k1_scalar_inverse(lw_secp256k1_scalar *r, const lw_secp256k1_scalar *a);

/** Compute the inverse of a scalar (modulo the group order), without constant-time guarantee. */
static void lw_secp256k1_scalar_inverse_var(lw_secp256k1_scalar *r, const lw_secp256k1_scalar *a);

/** Compute the complement of a scalar (modulo the group order). */
static void lw_secp256k1_scalar_negate(lw_secp256k1_scalar *r, const lw_secp256k1_scalar *a);

/** Check whether a scalar equals zero. */
static int lw_secp256k1_scalar_is_zero(const lw_secp256k1_scalar *a);

/** Check whether a scalar equals one. */
static int lw_secp256k1_scalar_is_one(const lw_secp256k1_scalar *a);

/** Check whether a scalar, considered as an nonnegative integer, is even. */
static int lw_secp256k1_scalar_is_even(const lw_secp256k1_scalar *a);

/** Check whether a scalar is higher than the group order divided by 2. */
static int lw_secp256k1_scalar_is_high(const lw_secp256k1_scalar *a);

/** Conditionally negate a number, in constant time.
 * Returns -1 if the number was negated, 1 otherwise */
static int lw_secp256k1_scalar_cond_negate(lw_secp256k1_scalar *a, int flag);

#ifndef USE_NUM_NONE
/** Convert a scalar to a number. */
static void lw_secp256k1_scalar_get_num(lw_secp256k1_num *r, const lw_secp256k1_scalar *a);

/** Get the order of the group as a number. */
static void lw_secp256k1_scalar_order_get_num(lw_secp256k1_num *r);
#endif

/** Compare two scalars. */
static int lw_secp256k1_scalar_eq(const lw_secp256k1_scalar *a, const lw_secp256k1_scalar *b);

#ifdef USE_ENDOMORPHISM
/** Find r1 and r2 such that r1+r2*2^128 = a. */
static void lw_secp256k1_scalar_split_128(lw_secp256k1_scalar *r1, lw_secp256k1_scalar *r2, const lw_secp256k1_scalar *a);
/** Find r1 and r2 such that r1+r2*lambda = a, and r1 and r2 are maximum 128 bits long (see lw_secp256k1_gej_mul_lambda). */
static void lw_secp256k1_scalar_split_lambda(lw_secp256k1_scalar *r1, lw_secp256k1_scalar *r2, const lw_secp256k1_scalar *a);
#endif

/** Multiply a and b (without taking the modulus!), divide by 2**shift, and round to the nearest integer. Shift must be at least 256. */
static void lw_secp256k1_scalar_mul_shift_var(lw_secp256k1_scalar *r, const lw_secp256k1_scalar *a, const lw_secp256k1_scalar *b, unsigned int shift);

/** If flag is true, set *r equal to *a; otherwise leave it. Constant-time. */
static void lw_secp256k1_scalar_cmov(lw_secp256k1_scalar *r, const lw_secp256k1_scalar *a, int flag);

#endif /* lw_secp256k1_SCALAR_H */

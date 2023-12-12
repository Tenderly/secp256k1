/**********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef lw_secp256k1_HASH_H
#define lw_secp256k1_HASH_H

#include <stdlib.h>
#include <stdint.h>

typedef struct {
    uint32_t s[8];
    uint32_t buf[16]; /* In big endian */
    size_t bytes;
} lw_secp256k1_sha256;

static void lw_secp256k1_sha256_initialize(lw_secp256k1_sha256 *hash);
static void lw_secp256k1_sha256_write(lw_secp256k1_sha256 *hash, const unsigned char *data, size_t size);
static void lw_secp256k1_sha256_finalize(lw_secp256k1_sha256 *hash, unsigned char *out32);

typedef struct {
    lw_secp256k1_sha256 inner, outer;
} lw_secp256k1_hmac_sha256;

static void lw_secp256k1_hmac_sha256_initialize(lw_secp256k1_hmac_sha256 *hash, const unsigned char *key, size_t size);
static void lw_secp256k1_hmac_sha256_write(lw_secp256k1_hmac_sha256 *hash, const unsigned char *data, size_t size);
static void lw_secp256k1_hmac_sha256_finalize(lw_secp256k1_hmac_sha256 *hash, unsigned char *out32);

typedef struct {
    unsigned char v[32];
    unsigned char k[32];
    int retry;
} lw_secp256k1_rfc6979_hmac_sha256;

static void lw_secp256k1_rfc6979_hmac_sha256_initialize(lw_secp256k1_rfc6979_hmac_sha256 *rng, const unsigned char *key, size_t keylen);
static void lw_secp256k1_rfc6979_hmac_sha256_generate(lw_secp256k1_rfc6979_hmac_sha256 *rng, unsigned char *out, size_t outlen);
static void lw_secp256k1_rfc6979_hmac_sha256_finalize(lw_secp256k1_rfc6979_hmac_sha256 *rng);

#endif /* lw_secp256k1_HASH_H */

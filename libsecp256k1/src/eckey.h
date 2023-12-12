/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef lw_secp256k1_ECKEY_H
#define lw_secp256k1_ECKEY_H

#include <stddef.h>

#include "group.h"
#include "scalar.h"
#include "ecmult.h"
#include "ecmult_gen.h"

static int lw_secp256k1_eckey_pubkey_parse(lw_secp256k1_ge *elem, const unsigned char *pub, size_t size);
static int lw_secp256k1_eckey_pubkey_serialize(lw_secp256k1_ge *elem, unsigned char *pub, size_t *size, int compressed);

static int lw_secp256k1_eckey_privkey_tweak_add(lw_secp256k1_scalar *key, const lw_secp256k1_scalar *tweak);
static int lw_secp256k1_eckey_pubkey_tweak_add(const lw_secp256k1_ecmult_context *ctx, lw_secp256k1_ge *key, const lw_secp256k1_scalar *tweak);
static int lw_secp256k1_eckey_privkey_tweak_mul(lw_secp256k1_scalar *key, const lw_secp256k1_scalar *tweak);
static int lw_secp256k1_eckey_pubkey_tweak_mul(const lw_secp256k1_ecmult_context *ctx, lw_secp256k1_ge *key, const lw_secp256k1_scalar *tweak);

#endif /* lw_secp256k1_ECKEY_H */

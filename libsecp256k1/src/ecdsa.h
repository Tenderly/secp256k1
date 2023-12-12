/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef lw_secp256k1_ECDSA_H
#define lw_secp256k1_ECDSA_H

#include <stddef.h>

#include "scalar.h"
#include "group.h"
#include "ecmult.h"

static int lw_secp256k1_ecdsa_sig_parse(lw_secp256k1_scalar *r, lw_secp256k1_scalar *s, const unsigned char *sig, size_t size);
static int lw_secp256k1_ecdsa_sig_serialize(unsigned char *sig, size_t *size, const lw_secp256k1_scalar *r, const lw_secp256k1_scalar *s);
static int lw_secp256k1_ecdsa_sig_verify(const lw_secp256k1_ecmult_context *ctx, const lw_secp256k1_scalar* r, const lw_secp256k1_scalar* s, const lw_secp256k1_ge *pubkey, const lw_secp256k1_scalar *message);
static int lw_secp256k1_ecdsa_sig_sign(const lw_secp256k1_ecmult_gen_context *ctx, lw_secp256k1_scalar* r, lw_secp256k1_scalar* s, const lw_secp256k1_scalar *seckey, const lw_secp256k1_scalar *message, const lw_secp256k1_scalar *nonce, int *recid);

#endif /* lw_secp256k1_ECDSA_H */

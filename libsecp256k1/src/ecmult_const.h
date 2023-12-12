/**********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef lw_secp256k1_ECMULT_CONST_H
#define lw_secp256k1_ECMULT_CONST_H

#include "scalar.h"
#include "group.h"

/**
 * Multiply: R = q*A (in constant-time)
 * Here `bits` should be set to the maximum bitlength of the _absolute value_ of `q`, plus
 * one because we internally sometimes add 2 to the number during the WNAF conversion.
 */
static void lw_secp256k1_ecmult_const(lw_secp256k1_gej *r, const lw_secp256k1_ge *a, const lw_secp256k1_scalar *q, int bits);

#endif /* lw_secp256k1_ECMULT_CONST_H */

/**********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef lw_secp256k1_SCALAR_REPR_H
#define lw_secp256k1_SCALAR_REPR_H

#include <stdint.h>

/** A scalar modulo the group order of the secp256k1 curve. */
typedef uint32_t lw_secp256k1_scalar;

#define lw_secp256k1_SCALAR_CONST(d7, d6, d5, d4, d3, d2, d1, d0) (d0)

#endif /* lw_secp256k1_SCALAR_REPR_H */

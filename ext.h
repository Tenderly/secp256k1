// Copyright 2015 Jeffrey Wilcke, Felix Lange, Gustav Simonsson. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

// lw_secp256k1_context_create_sign_verify creates a context for signing and signature verification.
static lw_secp256k1_context* lw_secp256k1_context_create_sign_verify() {
	return lw_secp256k1_context_create(lw_secp256k1_CONTEXT_SIGN | lw_secp256k1_CONTEXT_VERIFY);
}

// lw_secp256k1_ext_ecdsa_recover recovers the public key of an encoded compact signature.
//
// Returns: 1: recovery was successful
//          0: recovery was not successful
// Args:    ctx:        pointer to a context object (cannot be NULL)
//  Out:    pubkey_out: the serialized 65-byte public key of the signer (cannot be NULL)
//  In:     sigdata:    pointer to a 65-byte signature with the recovery id at the end (cannot be NULL)
//          msgdata:    pointer to a 32-byte message (cannot be NULL)
static int lw_secp256k1_ext_ecdsa_recover(
	const lw_secp256k1_context* ctx,
	unsigned char *pubkey_out,
	const unsigned char *sigdata,
	const unsigned char *msgdata
) {
	lw_secp256k1_ecdsa_recoverable_signature sig;
	lw_secp256k1_pubkey pubkey;

	if (!lw_secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &sig, sigdata, (int)sigdata[64])) {
		return 0;
	}
	if (!lw_secp256k1_ecdsa_recover(ctx, &pubkey, &sig, msgdata)) {
		return 0;
	}
	size_t outputlen = 65;
	return lw_secp256k1_ec_pubkey_serialize(ctx, pubkey_out, &outputlen, &pubkey, lw_secp256k1_EC_UNCOMPRESSED);
}

// lw_secp256k1_ext_ecdsa_verify verifies an encoded compact signature.
//
// Returns: 1: signature is valid
//          0: signature is invalid
// Args:    ctx:        pointer to a context object (cannot be NULL)
//  In:     sigdata:    pointer to a 64-byte signature (cannot be NULL)
//          msgdata:    pointer to a 32-byte message (cannot be NULL)
//          pubkeydata: pointer to public key data (cannot be NULL)
//          pubkeylen:  length of pubkeydata
static int lw_secp256k1_ext_ecdsa_verify(
	const lw_secp256k1_context* ctx,
	const unsigned char *sigdata,
	const unsigned char *msgdata,
	const unsigned char *pubkeydata,
	size_t pubkeylen
) {
	lw_secp256k1_ecdsa_signature sig;
	lw_secp256k1_pubkey pubkey;

	if (!lw_secp256k1_ecdsa_signature_parse_compact(ctx, &sig, sigdata)) {
		return 0;
	}
	if (!lw_secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeydata, pubkeylen)) {
		return 0;
	}
	return lw_secp256k1_ecdsa_verify(ctx, &sig, msgdata, &pubkey);
}

// lw_secp256k1_ext_reencode_pubkey decodes then encodes a public key. It can be used to
// convert between public key formats. The input/output formats are chosen depending on the
// length of the input/output buffers.
//
// Returns: 1: conversion successful
//          0: conversion unsuccessful
// Args:    ctx:        pointer to a context object (cannot be NULL)
//  Out:    out:        output buffer that will contain the reencoded key (cannot be NULL)
//  In:     outlen:     length of out (33 for compressed keys, 65 for uncompressed keys)
//          pubkeydata: the input public key (cannot be NULL)
//          pubkeylen:  length of pubkeydata
static int lw_secp256k1_ext_reencode_pubkey(
	const lw_secp256k1_context* ctx,
	unsigned char *out,
	size_t outlen,
	const unsigned char *pubkeydata,
	size_t pubkeylen
) {
	lw_secp256k1_pubkey pubkey;

	if (!lw_secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeydata, pubkeylen)) {
		return 0;
	}
	unsigned int flag = (outlen == 33) ? lw_secp256k1_EC_COMPRESSED : lw_secp256k1_EC_UNCOMPRESSED;
	return lw_secp256k1_ec_pubkey_serialize(ctx, out, &outlen, &pubkey, flag);
}

// lw_secp256k1_ext_scalar_mul multiplies a point by a scalar in constant time.
//
// Returns: 1: multiplication was successful
//          0: scalar was invalid (zero or overflow)
// Args:    ctx:      pointer to a context object (cannot be NULL)
//  Out:    point:    the multiplied point (usually secret)
//  In:     point:    pointer to a 64-byte public point,
//                    encoded as two 256bit big-endian numbers.
//          scalar:   a 32-byte scalar with which to multiply the point
int lw_secp256k1_ext_scalar_mul(const lw_secp256k1_context* ctx, unsigned char *point, const unsigned char *scalar) {
	int ret = 0;
	int overflow = 0;
	lw_secp256k1_fe feX, feY;
	lw_secp256k1_gej res;
	lw_secp256k1_ge ge;
	lw_secp256k1_scalar s;
	ARG_CHECK(point != NULL);
	ARG_CHECK(scalar != NULL);
	(void)ctx;

	lw_secp256k1_fe_set_b32(&feX, point);
	lw_secp256k1_fe_set_b32(&feY, point+32);
	lw_secp256k1_ge_set_xy(&ge, &feX, &feY);
	lw_secp256k1_scalar_set_b32(&s, scalar, &overflow);
	if (overflow || lw_secp256k1_scalar_is_zero(&s)) {
		ret = 0;
	} else {
		lw_secp256k1_ecmult_const(&res, &ge, &s, 256);
		lw_secp256k1_ge_set_gej(&ge, &res);
		/* Note: can't use lw_secp256k1_pubkey_save here because it is not constant time. */
		lw_secp256k1_fe_normalize(&ge.x);
		lw_secp256k1_fe_normalize(&ge.y);
		lw_secp256k1_fe_get_b32(point, &ge.x);
		lw_secp256k1_fe_get_b32(point+32, &ge.y);
		ret = 1;
	}
	lw_secp256k1_scalar_clear(&s);
	return ret;
}

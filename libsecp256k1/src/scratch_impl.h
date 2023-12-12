/**********************************************************************
 * Copyright (c) 2017 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _lw_secp256k1_SCRATCH_IMPL_H_
#define _lw_secp256k1_SCRATCH_IMPL_H_

#include "util.h"
#include "scratch.h"

static lw_secp256k1_scratch* lw_secp256k1_scratch_create(const lw_secp256k1_callback* error_callback, size_t size) {
    const size_t base_alloc = ((sizeof(lw_secp256k1_scratch) + ALIGNMENT - 1) / ALIGNMENT) * ALIGNMENT;
    void *alloc = checked_malloc(error_callback, base_alloc + size);
    lw_secp256k1_scratch* ret = (lw_secp256k1_scratch *)alloc;
    if (ret != NULL) {
        memset(ret, 0, sizeof(*ret));
        memcpy(ret->magic, "scratch", 8);
        ret->data = (void *) ((char *) alloc + base_alloc);
        ret->max_size = size;
    }
    return ret;
}

static void lw_secp256k1_scratch_destroy(const lw_secp256k1_callback* error_callback, lw_secp256k1_scratch* scratch) {
    if (scratch != NULL) {
        VERIFY_CHECK(scratch->alloc_size == 0); /* all checkpoints should be applied */
        if (memcmp(scratch->magic, "scratch", 8) != 0) {
            lw_secp256k1_callback_call(error_callback, "invalid scratch space");
            return;
        }
        memset(scratch->magic, 0, sizeof(scratch->magic));
        free(scratch);
    }
}

static size_t lw_secp256k1_scratch_checkpoint(const lw_secp256k1_callback* error_callback, const lw_secp256k1_scratch* scratch) {
    if (memcmp(scratch->magic, "scratch", 8) != 0) {
        lw_secp256k1_callback_call(error_callback, "invalid scratch space");
        return 0;
    }
    return scratch->alloc_size;
}

static void lw_secp256k1_scratch_apply_checkpoint(const lw_secp256k1_callback* error_callback, lw_secp256k1_scratch* scratch, size_t checkpoint) {
    if (memcmp(scratch->magic, "scratch", 8) != 0) {
        lw_secp256k1_callback_call(error_callback, "invalid scratch space");
        return;
    }
    if (checkpoint > scratch->alloc_size) {
        lw_secp256k1_callback_call(error_callback, "invalid checkpoint");
        return;
    }
    scratch->alloc_size = checkpoint;
}

static size_t lw_secp256k1_scratch_max_allocation(const lw_secp256k1_callback* error_callback, const lw_secp256k1_scratch* scratch, size_t objects) {
    if (memcmp(scratch->magic, "scratch", 8) != 0) {
        lw_secp256k1_callback_call(error_callback, "invalid scratch space");
        return 0;
    }
    if (scratch->max_size - scratch->alloc_size <= objects * (ALIGNMENT - 1)) {
        return 0;
    }
    return scratch->max_size - scratch->alloc_size - objects * (ALIGNMENT - 1);
}

static void *lw_secp256k1_scratch_alloc(const lw_secp256k1_callback* error_callback, lw_secp256k1_scratch* scratch, size_t size) {
    void *ret;
    size = ROUND_TO_ALIGN(size);

    if (memcmp(scratch->magic, "scratch", 8) != 0) {
        lw_secp256k1_callback_call(error_callback, "invalid scratch space");
        return NULL;
    }

    if (size > scratch->max_size - scratch->alloc_size) {
        return NULL;
    }
    ret = (void *) ((char *) scratch->data + scratch->alloc_size);
    memset(ret, 0, size);
    scratch->alloc_size += size;

    return ret;
}

#endif

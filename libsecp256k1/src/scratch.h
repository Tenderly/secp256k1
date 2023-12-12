/**********************************************************************
 * Copyright (c) 2017 Andrew Poelstra	                              *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _lw_secp256k1_SCRATCH_
#define _lw_secp256k1_SCRATCH_

/* The typedef is used internally; the struct name is used in the public API
 * (where it is exposed as a different typedef) */
typedef struct lw_secp256k1_scratch_space_struct {
    /** guard against interpreting this object as other types */
    unsigned char magic[8];
    /** actual allocated data */
    void *data;
    /** amount that has been allocated (i.e. `data + offset` is the next
     *  available pointer)  */
    size_t alloc_size;
    /** maximum size available to allocate */
    size_t max_size;
} lw_secp256k1_scratch;

static lw_secp256k1_scratch* lw_secp256k1_scratch_create(const lw_secp256k1_callback* error_callback, size_t max_size);

static void lw_secp256k1_scratch_destroy(const lw_secp256k1_callback* error_callback, lw_secp256k1_scratch* scratch);

/** Returns an opaque object used to "checkpoint" a scratch space. Used
 *  with `lw_secp256k1_scratch_apply_checkpoint` to undo allocations. */
static size_t lw_secp256k1_scratch_checkpoint(const lw_secp256k1_callback* error_callback, const lw_secp256k1_scratch* scratch);

/** Applies a check point received from `lw_secp256k1_scratch_checkpoint`,
 *  undoing all allocations since that point. */
static void lw_secp256k1_scratch_apply_checkpoint(const lw_secp256k1_callback* error_callback, lw_secp256k1_scratch* scratch, size_t checkpoint);

/** Returns the maximum allocation the scratch space will allow */
static size_t lw_secp256k1_scratch_max_allocation(const lw_secp256k1_callback* error_callback, const lw_secp256k1_scratch* scratch, size_t n_objects);

/** Returns a pointer into the most recently allocated frame, or NULL if there is insufficient available space */
static void *lw_secp256k1_scratch_alloc(const lw_secp256k1_callback* error_callback, lw_secp256k1_scratch* scratch, size_t n);

#endif

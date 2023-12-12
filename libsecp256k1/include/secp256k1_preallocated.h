#ifndef lw_secp256k1_PREALLOCATED_H
#define lw_secp256k1_PREALLOCATED_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The module provided by this header file is intended for settings in which it
 * is not possible or desirable to rely on dynamic memory allocation. It provides
 * functions for creating, cloning, and destroying secp256k1 context objects in a
 * contiguous fixed-size block of memory provided by the caller.
 *
 * Context objects created by functions in this module can be used like contexts
 * objects created by functions in secp256k1.h, i.e., they can be passed to any
 * API function that expects a context object (see secp256k1.h for details). The
 * only exception is that context objects created by functions in this module
 * must be destroyed using lw_secp256k1_context_preallocated_destroy (in this
 * module) instead of lw_secp256k1_context_destroy (in secp256k1.h).
 *
 * It is guaranteed that functions in this module will not call malloc or its
 * friends realloc, calloc, and free.
 */

/** Determine the memory size of a secp256k1 context object to be created in
 *  caller-provided memory.
 *
 *  The purpose of this function is to determine how much memory must be provided
 *  to lw_secp256k1_context_preallocated_create.
 *
 *  Returns: the required size of the caller-provided memory block
 *  In:      flags:    which parts of the context to initialize.
 */
lw_secp256k1_API size_t lw_secp256k1_context_preallocated_size(
    unsigned int flags
) lw_secp256k1_WARN_UNUSED_RESULT;

/** Create a secp256k1 context object in caller-provided memory.
 *
 *  The caller must provide a pointer to a rewritable contiguous block of memory
 *  of size at least lw_secp256k1_context_preallocated_size(flags) bytes, suitably
 *  aligned to hold an object of any type.
 *
 *  The block of memory is exclusively owned by the created context object during
 *  the lifetime of this context object, which begins with the call to this
 *  function and ends when a call to lw_secp256k1_context_preallocated_destroy
 *  (which destroys the context object again) returns. During the lifetime of the
 *  context object, the caller is obligated not to access this block of memory,
 *  i.e., the caller may not read or write the memory, e.g., by copying the memory
 *  contents to a different location or trying to create a second context object
 *  in the memory. In simpler words, the prealloc pointer (or any pointer derived
 *  from it) should not be used during the lifetime of the context object.
 *
 *  Returns: a newly created context object.
 *  In:      prealloc: a pointer to a rewritable contiguous block of memory of
 *                     size at least lw_secp256k1_context_preallocated_size(flags)
 *                     bytes, as detailed above (cannot be NULL)
 *           flags:    which parts of the context to initialize.
 *
 *  See also lw_secp256k1_context_randomize (in secp256k1.h)
 *  and lw_secp256k1_context_preallocated_destroy.
 */
lw_secp256k1_API lw_secp256k1_context* lw_secp256k1_context_preallocated_create(
    void* prealloc,
    unsigned int flags
) lw_secp256k1_ARG_NONNULL(1) lw_secp256k1_WARN_UNUSED_RESULT;

/** Determine the memory size of a secp256k1 context object to be copied into
 *  caller-provided memory.
 *
 *  Returns: the required size of the caller-provided memory block.
 *  In:      ctx: an existing context to copy (cannot be NULL)
 */
lw_secp256k1_API size_t lw_secp256k1_context_preallocated_clone_size(
    const lw_secp256k1_context* ctx
) lw_secp256k1_ARG_NONNULL(1) lw_secp256k1_WARN_UNUSED_RESULT;

/** Copy a secp256k1 context object into caller-provided memory.
 *
 *  The caller must provide a pointer to a rewritable contiguous block of memory
 *  of size at least lw_secp256k1_context_preallocated_size(flags) bytes, suitably
 *  aligned to hold an object of any type.
 *
 *  The block of memory is exclusively owned by the created context object during
 *  the lifetime of this context object, see the description of
 *  lw_secp256k1_context_preallocated_create for details.
 *
 *  Returns: a newly created context object.
 *  Args:    ctx:      an existing context to copy (cannot be NULL)
 *  In:      prealloc: a pointer to a rewritable contiguous block of memory of
 *                     size at least lw_secp256k1_context_preallocated_size(flags)
 *                     bytes, as detailed above (cannot be NULL)
 */
lw_secp256k1_API lw_secp256k1_context* lw_secp256k1_context_preallocated_clone(
    const lw_secp256k1_context* ctx,
    void* prealloc
) lw_secp256k1_ARG_NONNULL(1) lw_secp256k1_ARG_NONNULL(2) lw_secp256k1_WARN_UNUSED_RESULT;

/** Destroy a secp256k1 context object that has been created in
 *  caller-provided memory.
 *
 *  The context pointer may not be used afterwards.
 *
 *  The context to destroy must have been created using
 *  lw_secp256k1_context_preallocated_create or lw_secp256k1_context_preallocated_clone.
 *  If the context has instead been created using lw_secp256k1_context_create or
 *  lw_secp256k1_context_clone, the behaviour is undefined. In that case,
 *  lw_secp256k1_context_destroy must be used instead.
 *
 *  If required, it is the responsibility of the caller to deallocate the block
 *  of memory properly after this function returns, e.g., by calling free on the
 *  preallocated pointer given to lw_secp256k1_context_preallocated_create or
 *  lw_secp256k1_context_preallocated_clone.
 *
 *  Args:   ctx: an existing context to destroy, constructed using
 *               lw_secp256k1_context_preallocated_create or
 *               lw_secp256k1_context_preallocated_clone (cannot be NULL)
 */
lw_secp256k1_API void lw_secp256k1_context_preallocated_destroy(
    lw_secp256k1_context* ctx
);

#ifdef __cplusplus
}
#endif

#endif /* lw_secp256k1_PREALLOCATED_H */

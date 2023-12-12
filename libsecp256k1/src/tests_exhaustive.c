/***********************************************************************
 * Copyright (c) 2016 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#include <time.h>

#undef USE_ECMULT_STATIC_PRECOMPUTATION

#ifndef EXHAUSTIVE_TEST_ORDER
/* see group_impl.h for allowable values */
#define EXHAUSTIVE_TEST_ORDER 13
#define EXHAUSTIVE_TEST_LAMBDA 9   /* cube root of 1 mod 13 */
#endif

#include "include/secp256k1.h"
#include "group.h"
#include "secp256k1.c"
#include "testrand_impl.h"

#ifdef ENABLE_MODULE_RECOVERY
#include "src/modules/recovery/main_impl.h"
#include "include/secp256k1_recovery.h"
#endif

/** stolen from tests.c */
void ge_equals_ge(const lw_secp256k1_ge *a, const lw_secp256k1_ge *b) {
    CHECK(a->infinity == b->infinity);
    if (a->infinity) {
        return;
    }
    CHECK(lw_secp256k1_fe_equal_var(&a->x, &b->x));
    CHECK(lw_secp256k1_fe_equal_var(&a->y, &b->y));
}

void ge_equals_gej(const lw_secp256k1_ge *a, const lw_secp256k1_gej *b) {
    lw_secp256k1_fe z2s;
    lw_secp256k1_fe u1, u2, s1, s2;
    CHECK(a->infinity == b->infinity);
    if (a->infinity) {
        return;
    }
    /* Check a.x * b.z^2 == b.x && a.y * b.z^3 == b.y, to avoid inverses. */
    lw_secp256k1_fe_sqr(&z2s, &b->z);
    lw_secp256k1_fe_mul(&u1, &a->x, &z2s);
    u2 = b->x; lw_secp256k1_fe_normalize_weak(&u2);
    lw_secp256k1_fe_mul(&s1, &a->y, &z2s); lw_secp256k1_fe_mul(&s1, &s1, &b->z);
    s2 = b->y; lw_secp256k1_fe_normalize_weak(&s2);
    CHECK(lw_secp256k1_fe_equal_var(&u1, &u2));
    CHECK(lw_secp256k1_fe_equal_var(&s1, &s2));
}

void random_fe(lw_secp256k1_fe *x) {
    unsigned char bin[32];
    do {
        lw_secp256k1_rand256(bin);
        if (lw_secp256k1_fe_set_b32(x, bin)) {
            return;
        }
    } while(1);
}
/** END stolen from tests.c */

int lw_secp256k1_nonce_function_smallint(unsigned char *nonce32, const unsigned char *msg32,
                                      const unsigned char *key32, const unsigned char *algo16,
                                      void *data, unsigned int attempt) {
    lw_secp256k1_scalar s;
    int *idata = data;
    (void)msg32;
    (void)key32;
    (void)algo16;
    /* Some nonces cannot be used because they'd cause s and/or r to be zero.
     * The signing function has retry logic here that just re-calls the nonce
     * function with an increased `attempt`. So if attempt > 0 this means we
     * need to change the nonce to avoid an infinite loop. */
    if (attempt > 0) {
        *idata = (*idata + 1) % EXHAUSTIVE_TEST_ORDER;
    }
    lw_secp256k1_scalar_set_int(&s, *idata);
    lw_secp256k1_scalar_get_b32(nonce32, &s);
    return 1;
}

#ifdef USE_ENDOMORPHISM
void test_exhaustive_endomorphism(const lw_secp256k1_ge *group, int order) {
    int i;
    for (i = 0; i < order; i++) {
        lw_secp256k1_ge res;
        lw_secp256k1_ge_mul_lambda(&res, &group[i]);
        ge_equals_ge(&group[i * EXHAUSTIVE_TEST_LAMBDA % EXHAUSTIVE_TEST_ORDER], &res);
    }
}
#endif

void test_exhaustive_addition(const lw_secp256k1_ge *group, const lw_secp256k1_gej *groupj, int order) {
    int i, j;

    /* Sanity-check (and check infinity functions) */
    CHECK(lw_secp256k1_ge_is_infinity(&group[0]));
    CHECK(lw_secp256k1_gej_is_infinity(&groupj[0]));
    for (i = 1; i < order; i++) {
        CHECK(!lw_secp256k1_ge_is_infinity(&group[i]));
        CHECK(!lw_secp256k1_gej_is_infinity(&groupj[i]));
    }

    /* Check all addition formulae */
    for (j = 0; j < order; j++) {
        lw_secp256k1_fe fe_inv;
        lw_secp256k1_fe_inv(&fe_inv, &groupj[j].z);
        for (i = 0; i < order; i++) {
            lw_secp256k1_ge zless_gej;
            lw_secp256k1_gej tmp;
            /* add_var */
            lw_secp256k1_gej_add_var(&tmp, &groupj[i], &groupj[j], NULL);
            ge_equals_gej(&group[(i + j) % order], &tmp);
            /* add_ge */
            if (j > 0) {
                lw_secp256k1_gej_add_ge(&tmp, &groupj[i], &group[j]);
                ge_equals_gej(&group[(i + j) % order], &tmp);
            }
            /* add_ge_var */
            lw_secp256k1_gej_add_ge_var(&tmp, &groupj[i], &group[j], NULL);
            ge_equals_gej(&group[(i + j) % order], &tmp);
            /* add_zinv_var */
            zless_gej.infinity = groupj[j].infinity;
            zless_gej.x = groupj[j].x;
            zless_gej.y = groupj[j].y;
            lw_secp256k1_gej_add_zinv_var(&tmp, &groupj[i], &zless_gej, &fe_inv);
            ge_equals_gej(&group[(i + j) % order], &tmp);
        }
    }

    /* Check doubling */
    for (i = 0; i < order; i++) {
        lw_secp256k1_gej tmp;
        if (i > 0) {
            lw_secp256k1_gej_double_nonzero(&tmp, &groupj[i]);
            ge_equals_gej(&group[(2 * i) % order], &tmp);
        }
        lw_secp256k1_gej_double_var(&tmp, &groupj[i], NULL);
        ge_equals_gej(&group[(2 * i) % order], &tmp);
    }

    /* Check negation */
    for (i = 1; i < order; i++) {
        lw_secp256k1_ge tmp;
        lw_secp256k1_gej tmpj;
        lw_secp256k1_ge_neg(&tmp, &group[i]);
        ge_equals_ge(&group[order - i], &tmp);
        lw_secp256k1_gej_neg(&tmpj, &groupj[i]);
        ge_equals_gej(&group[order - i], &tmpj);
    }
}

void test_exhaustive_ecmult(const lw_secp256k1_context *ctx, const lw_secp256k1_ge *group, const lw_secp256k1_gej *groupj, int order) {
    int i, j, r_log;
    for (r_log = 1; r_log < order; r_log++) {
        for (j = 0; j < order; j++) {
            for (i = 0; i < order; i++) {
                lw_secp256k1_gej tmp;
                lw_secp256k1_scalar na, ng;
                lw_secp256k1_scalar_set_int(&na, i);
                lw_secp256k1_scalar_set_int(&ng, j);

                lw_secp256k1_ecmult(&ctx->ecmult_ctx, &tmp, &groupj[r_log], &na, &ng);
                ge_equals_gej(&group[(i * r_log + j) % order], &tmp);

                if (i > 0) {
                    lw_secp256k1_ecmult_const(&tmp, &group[i], &ng, 256);
                    ge_equals_gej(&group[(i * j) % order], &tmp);
                }
            }
        }
    }
}

typedef struct {
    lw_secp256k1_scalar sc[2];
    lw_secp256k1_ge pt[2];
} ecmult_multi_data;

static int ecmult_multi_callback(lw_secp256k1_scalar *sc, lw_secp256k1_ge *pt, size_t idx, void *cbdata) {
    ecmult_multi_data *data = (ecmult_multi_data*) cbdata;
    *sc = data->sc[idx];
    *pt = data->pt[idx];
    return 1;
}

void test_exhaustive_ecmult_multi(const lw_secp256k1_context *ctx, const lw_secp256k1_ge *group, int order) {
    int i, j, k, x, y;
    lw_secp256k1_scratch *scratch = lw_secp256k1_scratch_create(&ctx->error_callback, 4096);
    for (i = 0; i < order; i++) {
        for (j = 0; j < order; j++) {
            for (k = 0; k < order; k++) {
                for (x = 0; x < order; x++) {
                    for (y = 0; y < order; y++) {
                        lw_secp256k1_gej tmp;
                        lw_secp256k1_scalar g_sc;
                        ecmult_multi_data data;

                        lw_secp256k1_scalar_set_int(&data.sc[0], i);
                        lw_secp256k1_scalar_set_int(&data.sc[1], j);
                        lw_secp256k1_scalar_set_int(&g_sc, k);
                        data.pt[0] = group[x];
                        data.pt[1] = group[y];

                        lw_secp256k1_ecmult_multi_var(&ctx->error_callback, &ctx->ecmult_ctx, scratch, &tmp, &g_sc, ecmult_multi_callback, &data, 2);
                        ge_equals_gej(&group[(i * x + j * y + k) % order], &tmp);
                    }
                }
            }
        }
    }
    lw_secp256k1_scratch_destroy(&ctx->error_callback, scratch);
}

void r_from_k(lw_secp256k1_scalar *r, const lw_secp256k1_ge *group, int k) {
    lw_secp256k1_fe x;
    unsigned char x_bin[32];
    k %= EXHAUSTIVE_TEST_ORDER;
    x = group[k].x;
    lw_secp256k1_fe_normalize(&x);
    lw_secp256k1_fe_get_b32(x_bin, &x);
    lw_secp256k1_scalar_set_b32(r, x_bin, NULL);
}

void test_exhaustive_verify(const lw_secp256k1_context *ctx, const lw_secp256k1_ge *group, int order) {
    int s, r, msg, key;
    for (s = 1; s < order; s++) {
        for (r = 1; r < order; r++) {
            for (msg = 1; msg < order; msg++) {
                for (key = 1; key < order; key++) {
                    lw_secp256k1_ge nonconst_ge;
                    lw_secp256k1_ecdsa_signature sig;
                    lw_secp256k1_pubkey pk;
                    lw_secp256k1_scalar sk_s, msg_s, r_s, s_s;
                    lw_secp256k1_scalar s_times_k_s, msg_plus_r_times_sk_s;
                    int k, should_verify;
                    unsigned char msg32[32];

                    lw_secp256k1_scalar_set_int(&s_s, s);
                    lw_secp256k1_scalar_set_int(&r_s, r);
                    lw_secp256k1_scalar_set_int(&msg_s, msg);
                    lw_secp256k1_scalar_set_int(&sk_s, key);

                    /* Verify by hand */
                    /* Run through every k value that gives us this r and check that *one* works.
                     * Note there could be none, there could be multiple, ECDSA is weird. */
                    should_verify = 0;
                    for (k = 0; k < order; k++) {
                        lw_secp256k1_scalar check_x_s;
                        r_from_k(&check_x_s, group, k);
                        if (r_s == check_x_s) {
                            lw_secp256k1_scalar_set_int(&s_times_k_s, k);
                            lw_secp256k1_scalar_mul(&s_times_k_s, &s_times_k_s, &s_s);
                            lw_secp256k1_scalar_mul(&msg_plus_r_times_sk_s, &r_s, &sk_s);
                            lw_secp256k1_scalar_add(&msg_plus_r_times_sk_s, &msg_plus_r_times_sk_s, &msg_s);
                            should_verify |= lw_secp256k1_scalar_eq(&s_times_k_s, &msg_plus_r_times_sk_s);
                        }
                    }
                    /* nb we have a "high s" rule */
                    should_verify &= !lw_secp256k1_scalar_is_high(&s_s);

                    /* Verify by calling verify */
                    lw_secp256k1_ecdsa_signature_save(&sig, &r_s, &s_s);
                    memcpy(&nonconst_ge, &group[sk_s], sizeof(nonconst_ge));
                    lw_secp256k1_pubkey_save(&pk, &nonconst_ge);
                    lw_secp256k1_scalar_get_b32(msg32, &msg_s);
                    CHECK(should_verify ==
                          lw_secp256k1_ecdsa_verify(ctx, &sig, msg32, &pk));
                }
            }
        }
    }
}

void test_exhaustive_sign(const lw_secp256k1_context *ctx, const lw_secp256k1_ge *group, int order) {
    int i, j, k;

    /* Loop */
    for (i = 1; i < order; i++) {  /* message */
        for (j = 1; j < order; j++) {  /* key */
            for (k = 1; k < order; k++) {  /* nonce */
                const int starting_k = k;
                lw_secp256k1_ecdsa_signature sig;
                lw_secp256k1_scalar sk, msg, r, s, expected_r;
                unsigned char sk32[32], msg32[32];
                lw_secp256k1_scalar_set_int(&msg, i);
                lw_secp256k1_scalar_set_int(&sk, j);
                lw_secp256k1_scalar_get_b32(sk32, &sk);
                lw_secp256k1_scalar_get_b32(msg32, &msg);

                lw_secp256k1_ecdsa_sign(ctx, &sig, msg32, sk32, lw_secp256k1_nonce_function_smallint, &k);

                lw_secp256k1_ecdsa_signature_load(ctx, &r, &s, &sig);
                /* Note that we compute expected_r *after* signing -- this is important
                 * because our nonce-computing function function might change k during
                 * signing. */
                r_from_k(&expected_r, group, k);
                CHECK(r == expected_r);
                CHECK((k * s) % order == (i + r * j) % order ||
                      (k * (EXHAUSTIVE_TEST_ORDER - s)) % order == (i + r * j) % order);

                /* Overflow means we've tried every possible nonce */
                if (k < starting_k) {
                    break;
                }
            }
        }
    }

    /* We would like to verify zero-knowledge here by counting how often every
     * possible (s, r) tuple appears, but because the group order is larger
     * than the field order, when coercing the x-values to scalar values, some
     * appear more often than others, so we are actually not zero-knowledge.
     * (This effect also appears in the real code, but the difference is on the
     * order of 1/2^128th the field order, so the deviation is not useful to a
     * computationally bounded attacker.)
     */
}

#ifdef ENABLE_MODULE_RECOVERY
void test_exhaustive_recovery_sign(const lw_secp256k1_context *ctx, const lw_secp256k1_ge *group, int order) {
    int i, j, k;

    /* Loop */
    for (i = 1; i < order; i++) {  /* message */
        for (j = 1; j < order; j++) {  /* key */
            for (k = 1; k < order; k++) {  /* nonce */
                const int starting_k = k;
                lw_secp256k1_fe r_dot_y_normalized;
                lw_secp256k1_ecdsa_recoverable_signature rsig;
                lw_secp256k1_ecdsa_signature sig;
                lw_secp256k1_scalar sk, msg, r, s, expected_r;
                unsigned char sk32[32], msg32[32];
                int expected_recid;
                int recid;
                lw_secp256k1_scalar_set_int(&msg, i);
                lw_secp256k1_scalar_set_int(&sk, j);
                lw_secp256k1_scalar_get_b32(sk32, &sk);
                lw_secp256k1_scalar_get_b32(msg32, &msg);

                lw_secp256k1_ecdsa_sign_recoverable(ctx, &rsig, msg32, sk32, lw_secp256k1_nonce_function_smallint, &k);

                /* Check directly */
                lw_secp256k1_ecdsa_recoverable_signature_load(ctx, &r, &s, &recid, &rsig);
                r_from_k(&expected_r, group, k);
                CHECK(r == expected_r);
                CHECK((k * s) % order == (i + r * j) % order ||
                      (k * (EXHAUSTIVE_TEST_ORDER - s)) % order == (i + r * j) % order);
                /* In computing the recid, there is an overflow condition that is disabled in
                 * scalar_low_impl.h `lw_secp256k1_scalar_set_b32` because almost every r.y value
                 * will exceed the group order, and our signing code always holds out for r
                 * values that don't overflow, so with a proper overflow check the tests would
                 * loop indefinitely. */
                r_dot_y_normalized = group[k].y;
                lw_secp256k1_fe_normalize(&r_dot_y_normalized);
                /* Also the recovery id is flipped depending if we hit the low-s branch */
                if ((k * s) % order == (i + r * j) % order) {
                    expected_recid = lw_secp256k1_fe_is_odd(&r_dot_y_normalized) ? 1 : 0;
                } else {
                    expected_recid = lw_secp256k1_fe_is_odd(&r_dot_y_normalized) ? 0 : 1;
                }
                CHECK(recid == expected_recid);

                /* Convert to a standard sig then check */
                lw_secp256k1_ecdsa_recoverable_signature_convert(ctx, &sig, &rsig);
                lw_secp256k1_ecdsa_signature_load(ctx, &r, &s, &sig);
                /* Note that we compute expected_r *after* signing -- this is important
                 * because our nonce-computing function function might change k during
                 * signing. */
                r_from_k(&expected_r, group, k);
                CHECK(r == expected_r);
                CHECK((k * s) % order == (i + r * j) % order ||
                      (k * (EXHAUSTIVE_TEST_ORDER - s)) % order == (i + r * j) % order);

                /* Overflow means we've tried every possible nonce */
                if (k < starting_k) {
                    break;
                }
            }
        }
    }
}

void test_exhaustive_recovery_verify(const lw_secp256k1_context *ctx, const lw_secp256k1_ge *group, int order) {
    /* This is essentially a copy of test_exhaustive_verify, with recovery added */
    int s, r, msg, key;
    for (s = 1; s < order; s++) {
        for (r = 1; r < order; r++) {
            for (msg = 1; msg < order; msg++) {
                for (key = 1; key < order; key++) {
                    lw_secp256k1_ge nonconst_ge;
                    lw_secp256k1_ecdsa_recoverable_signature rsig;
                    lw_secp256k1_ecdsa_signature sig;
                    lw_secp256k1_pubkey pk;
                    lw_secp256k1_scalar sk_s, msg_s, r_s, s_s;
                    lw_secp256k1_scalar s_times_k_s, msg_plus_r_times_sk_s;
                    int recid = 0;
                    int k, should_verify;
                    unsigned char msg32[32];

                    lw_secp256k1_scalar_set_int(&s_s, s);
                    lw_secp256k1_scalar_set_int(&r_s, r);
                    lw_secp256k1_scalar_set_int(&msg_s, msg);
                    lw_secp256k1_scalar_set_int(&sk_s, key);
                    lw_secp256k1_scalar_get_b32(msg32, &msg_s);

                    /* Verify by hand */
                    /* Run through every k value that gives us this r and check that *one* works.
                     * Note there could be none, there could be multiple, ECDSA is weird. */
                    should_verify = 0;
                    for (k = 0; k < order; k++) {
                        lw_secp256k1_scalar check_x_s;
                        r_from_k(&check_x_s, group, k);
                        if (r_s == check_x_s) {
                            lw_secp256k1_scalar_set_int(&s_times_k_s, k);
                            lw_secp256k1_scalar_mul(&s_times_k_s, &s_times_k_s, &s_s);
                            lw_secp256k1_scalar_mul(&msg_plus_r_times_sk_s, &r_s, &sk_s);
                            lw_secp256k1_scalar_add(&msg_plus_r_times_sk_s, &msg_plus_r_times_sk_s, &msg_s);
                            should_verify |= lw_secp256k1_scalar_eq(&s_times_k_s, &msg_plus_r_times_sk_s);
                        }
                    }
                    /* nb we have a "high s" rule */
                    should_verify &= !lw_secp256k1_scalar_is_high(&s_s);

                    /* We would like to try recovering the pubkey and checking that it matches,
                     * but pubkey recovery is impossible in the exhaustive tests (the reason
                     * being that there are 12 nonzero r values, 12 nonzero points, and no
                     * overlap between the sets, so there are no valid signatures). */

                    /* Verify by converting to a standard signature and calling verify */
                    lw_secp256k1_ecdsa_recoverable_signature_save(&rsig, &r_s, &s_s, recid);
                    lw_secp256k1_ecdsa_recoverable_signature_convert(ctx, &sig, &rsig);
                    memcpy(&nonconst_ge, &group[sk_s], sizeof(nonconst_ge));
                    lw_secp256k1_pubkey_save(&pk, &nonconst_ge);
                    CHECK(should_verify ==
                          lw_secp256k1_ecdsa_verify(ctx, &sig, msg32, &pk));
                }
            }
        }
    }
}
#endif

int main(void) {
    int i;
    lw_secp256k1_gej groupj[EXHAUSTIVE_TEST_ORDER];
    lw_secp256k1_ge group[EXHAUSTIVE_TEST_ORDER];

    /* Build context */
    lw_secp256k1_context *ctx = lw_secp256k1_context_create(lw_secp256k1_CONTEXT_SIGN | lw_secp256k1_CONTEXT_VERIFY);

    /* TODO set z = 1, then do num_tests runs with random z values */

    /* Generate the entire group */
    lw_secp256k1_gej_set_infinity(&groupj[0]);
    lw_secp256k1_ge_set_gej(&group[0], &groupj[0]);
    for (i = 1; i < EXHAUSTIVE_TEST_ORDER; i++) {
        /* Set a different random z-value for each Jacobian point */
        lw_secp256k1_fe z;
        random_fe(&z);

        lw_secp256k1_gej_add_ge(&groupj[i], &groupj[i - 1], &lw_secp256k1_ge_const_g);
        lw_secp256k1_ge_set_gej(&group[i], &groupj[i]);
        lw_secp256k1_gej_rescale(&groupj[i], &z);

        /* Verify against ecmult_gen */
        {
            lw_secp256k1_scalar scalar_i;
            lw_secp256k1_gej generatedj;
            lw_secp256k1_ge generated;

            lw_secp256k1_scalar_set_int(&scalar_i, i);
            lw_secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &generatedj, &scalar_i);
            lw_secp256k1_ge_set_gej(&generated, &generatedj);

            CHECK(group[i].infinity == 0);
            CHECK(generated.infinity == 0);
            CHECK(lw_secp256k1_fe_equal_var(&generated.x, &group[i].x));
            CHECK(lw_secp256k1_fe_equal_var(&generated.y, &group[i].y));
        }
    }

    /* Run the tests */
#ifdef USE_ENDOMORPHISM
    test_exhaustive_endomorphism(group, EXHAUSTIVE_TEST_ORDER);
#endif
    test_exhaustive_addition(group, groupj, EXHAUSTIVE_TEST_ORDER);
    test_exhaustive_ecmult(ctx, group, groupj, EXHAUSTIVE_TEST_ORDER);
    test_exhaustive_ecmult_multi(ctx, group, EXHAUSTIVE_TEST_ORDER);
    test_exhaustive_sign(ctx, group, EXHAUSTIVE_TEST_ORDER);
    test_exhaustive_verify(ctx, group, EXHAUSTIVE_TEST_ORDER);

#ifdef ENABLE_MODULE_RECOVERY
    test_exhaustive_recovery_sign(ctx, group, EXHAUSTIVE_TEST_ORDER);
    test_exhaustive_recovery_verify(ctx, group, EXHAUSTIVE_TEST_ORDER);
#endif

    lw_secp256k1_context_destroy(ctx);
    return 0;
}


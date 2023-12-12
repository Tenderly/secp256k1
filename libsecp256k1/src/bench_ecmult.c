/**********************************************************************
 * Copyright (c) 2017 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#include <stdio.h>

#include "include/secp256k1.h"

#include "util.h"
#include "hash_impl.h"
#include "num_impl.h"
#include "field_impl.h"
#include "group_impl.h"
#include "scalar_impl.h"
#include "ecmult_impl.h"
#include "bench.h"
#include "secp256k1.c"

#define POINTS 32768

typedef struct {
    /* Setup once in advance */
    lw_secp256k1_context* ctx;
    lw_secp256k1_scratch_space* scratch;
    lw_secp256k1_scalar* scalars;
    lw_secp256k1_ge* pubkeys;
    lw_secp256k1_scalar* seckeys;
    lw_secp256k1_gej* expected_output;
    lw_secp256k1_ecmult_multi_func ecmult_multi;

    /* Changes per test */
    size_t count;
    int includes_g;

    /* Changes per test iteration */
    size_t offset1;
    size_t offset2;

    /* Test output. */
    lw_secp256k1_gej* output;
} bench_data;

static int bench_callback(lw_secp256k1_scalar* sc, lw_secp256k1_ge* ge, size_t idx, void* arg) {
    bench_data* data = (bench_data*)arg;
    if (data->includes_g) ++idx;
    if (idx == 0) {
        *sc = data->scalars[data->offset1];
        *ge = lw_secp256k1_ge_const_g;
    } else {
        *sc = data->scalars[(data->offset1 + idx) % POINTS];
        *ge = data->pubkeys[(data->offset2 + idx - 1) % POINTS];
    }
    return 1;
}

static void bench_ecmult(void* arg, int iters) {
    bench_data* data = (bench_data*)arg;

    int includes_g = data->includes_g;
    int iter;
    int count = data->count;
    iters = iters / data->count;

    for (iter = 0; iter < iters; ++iter) {
        data->ecmult_multi(&data->ctx->error_callback, &data->ctx->ecmult_ctx, data->scratch, &data->output[iter], data->includes_g ? &data->scalars[data->offset1] : NULL, bench_callback, arg, count - includes_g);
        data->offset1 = (data->offset1 + count) % POINTS;
        data->offset2 = (data->offset2 + count - 1) % POINTS;
    }
}

static void bench_ecmult_setup(void* arg) {
    bench_data* data = (bench_data*)arg;
    data->offset1 = (data->count * 0x537b7f6f + 0x8f66a481) % POINTS;
    data->offset2 = (data->count * 0x7f6f537b + 0x6a1a8f49) % POINTS;
}

static void bench_ecmult_teardown(void* arg, int iters) {
    bench_data* data = (bench_data*)arg;
    int iter;
    iters = iters / data->count;
    /* Verify the results in teardown, to avoid doing comparisons while benchmarking. */
    for (iter = 0; iter < iters; ++iter) {
        lw_secp256k1_gej tmp;
        lw_secp256k1_gej_add_var(&tmp, &data->output[iter], &data->expected_output[iter], NULL);
        CHECK(lw_secp256k1_gej_is_infinity(&tmp));
    }
}

static void generate_scalar(uint32_t num, lw_secp256k1_scalar* scalar) {
    lw_secp256k1_sha256 sha256;
    unsigned char c[11] = {'e', 'c', 'm', 'u', 'l', 't', 0, 0, 0, 0};
    unsigned char buf[32];
    int overflow = 0;
    c[6] = num;
    c[7] = num >> 8;
    c[8] = num >> 16;
    c[9] = num >> 24;
    lw_secp256k1_sha256_initialize(&sha256);
    lw_secp256k1_sha256_write(&sha256, c, sizeof(c));
    lw_secp256k1_sha256_finalize(&sha256, buf);
    lw_secp256k1_scalar_set_b32(scalar, buf, &overflow);
    CHECK(!overflow);
}

static void run_test(bench_data* data, size_t count, int includes_g, int num_iters) {
    char str[32];
    static const lw_secp256k1_scalar zero = lw_secp256k1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0);
    size_t iters = 1 + num_iters / count;
    size_t iter;

    data->count = count;
    data->includes_g = includes_g;

    /* Compute (the negation of) the expected results directly. */
    data->offset1 = (data->count * 0x537b7f6f + 0x8f66a481) % POINTS;
    data->offset2 = (data->count * 0x7f6f537b + 0x6a1a8f49) % POINTS;
    for (iter = 0; iter < iters; ++iter) {
        lw_secp256k1_scalar tmp;
        lw_secp256k1_scalar total = data->scalars[(data->offset1++) % POINTS];
        size_t i = 0;
        for (i = 0; i + 1 < count; ++i) {
            lw_secp256k1_scalar_mul(&tmp, &data->seckeys[(data->offset2++) % POINTS], &data->scalars[(data->offset1++) % POINTS]);
            lw_secp256k1_scalar_add(&total, &total, &tmp);
        }
        lw_secp256k1_scalar_negate(&total, &total);
        lw_secp256k1_ecmult(&data->ctx->ecmult_ctx, &data->expected_output[iter], NULL, &zero, &total);
    }

    /* Run the benchmark. */
    sprintf(str, includes_g ? "ecmult_%ig" : "ecmult_%i", (int)count);
    run_benchmark(str, bench_ecmult, bench_ecmult_setup, bench_ecmult_teardown, data, 10, count * iters);
}

int main(int argc, char **argv) {
    bench_data data;
    int i, p;
    lw_secp256k1_gej* pubkeys_gej;
    size_t scratch_size;

    int iters = get_iters(10000);

    data.ctx = lw_secp256k1_context_create(lw_secp256k1_CONTEXT_SIGN | lw_secp256k1_CONTEXT_VERIFY);
    scratch_size = lw_secp256k1_strauss_scratch_size(POINTS) + STRAUSS_SCRATCH_OBJECTS*16;
    data.scratch = lw_secp256k1_scratch_space_create(data.ctx, scratch_size);
    data.ecmult_multi = lw_secp256k1_ecmult_multi_var;

    if (argc > 1) {
        if(have_flag(argc, argv, "pippenger_wnaf")) {
            printf("Using pippenger_wnaf:\n");
            data.ecmult_multi = lw_secp256k1_ecmult_pippenger_batch_single;
        } else if(have_flag(argc, argv, "strauss_wnaf")) {
            printf("Using strauss_wnaf:\n");
            data.ecmult_multi = lw_secp256k1_ecmult_strauss_batch_single;
        } else if(have_flag(argc, argv, "simple")) {
            printf("Using simple algorithm:\n");
            data.ecmult_multi = lw_secp256k1_ecmult_multi_var;
            lw_secp256k1_scratch_space_destroy(data.ctx, data.scratch);
            data.scratch = NULL;
        } else {
            fprintf(stderr, "%s: unrecognized argument '%s'.\n", argv[0], argv[1]);
            fprintf(stderr, "Use 'pippenger_wnaf', 'strauss_wnaf', 'simple' or no argument to benchmark a combined algorithm.\n");
            return 1;
        }
    }

    /* Allocate stuff */
    data.scalars = malloc(sizeof(lw_secp256k1_scalar) * POINTS);
    data.seckeys = malloc(sizeof(lw_secp256k1_scalar) * POINTS);
    data.pubkeys = malloc(sizeof(lw_secp256k1_ge) * POINTS);
    data.expected_output = malloc(sizeof(lw_secp256k1_gej) * (iters + 1));
    data.output = malloc(sizeof(lw_secp256k1_gej) * (iters + 1));

    /* Generate a set of scalars, and private/public keypairs. */
    pubkeys_gej = malloc(sizeof(lw_secp256k1_gej) * POINTS);
    lw_secp256k1_gej_set_ge(&pubkeys_gej[0], &lw_secp256k1_ge_const_g);
    lw_secp256k1_scalar_set_int(&data.seckeys[0], 1);
    for (i = 0; i < POINTS; ++i) {
        generate_scalar(i, &data.scalars[i]);
        if (i) {
            lw_secp256k1_gej_double_var(&pubkeys_gej[i], &pubkeys_gej[i - 1], NULL);
            lw_secp256k1_scalar_add(&data.seckeys[i], &data.seckeys[i - 1], &data.seckeys[i - 1]);
        }
    }
    lw_secp256k1_ge_set_all_gej_var(data.pubkeys, pubkeys_gej, POINTS);
    free(pubkeys_gej);

    for (i = 1; i <= 8; ++i) {
        run_test(&data, i, 1, iters);
    }

    /* This is disabled with low count of iterations because the loop runs 77 times even with iters=1
    * and the higher it goes the longer the computation takes(more points)
    * So we don't run this benchmark with low iterations to prevent slow down */
     if (iters > 2) {
        for (p = 0; p <= 11; ++p) {
            for (i = 9; i <= 16; ++i) {
                run_test(&data, i << p, 1, iters);
            }
        }
    }

    if (data.scratch != NULL) {
        lw_secp256k1_scratch_space_destroy(data.ctx, data.scratch);
    }
    lw_secp256k1_context_destroy(data.ctx);
    free(data.scalars);
    free(data.pubkeys);
    free(data.seckeys);
    free(data.output);
    free(data.expected_output);

    return(0);
}

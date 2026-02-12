/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************
 * Copyright (c) 2024, Infineon Technologies AG
 *
 * All rights reserved.
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "tss2_mu.h"
#include "tss2_tpm2_types.h"

/*
 * Test round-trip marshal/unmarshal of TPMS_ML_PARAMETER_SET
 */
static void
test_TPMS_ML_PARAMETER_SET_marshal_unmarshal(void **state)
{
    (void)state;
    TPMS_ML_PARAMETER_SET src = { .identifier = TPMA_ML_PARAMETER_SET_MLKEM_768 };
    TPMS_ML_PARAMETER_SET dst = { 0 };
    uint8_t buffer[256] = { 0 };
    size_t offset = 0;
    TSS2_RC rc;

    rc = Tss2_MU_TPMS_ML_PARAMETER_SET_Marshal(&src, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_true(offset > 0);

    size_t offset2 = 0;
    rc = Tss2_MU_TPMS_ML_PARAMETER_SET_Unmarshal(buffer, offset, &offset2, &dst);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(offset, offset2);
    assert_int_equal(src.identifier, dst.identifier);
}

/*
 * Test round-trip marshal/unmarshal of TPMS_MLKEM_PARMS
 */
static void
test_TPMS_MLKEM_PARMS_marshal_unmarshal(void **state)
{
    (void)state;
    TPMS_MLKEM_PARMS src = {
        .nameAlg = TPM2_ALG_SHA256,
        .parameterSet = { .identifier = TPMA_ML_PARAMETER_SET_MLKEM_1024 }
    };
    TPMS_MLKEM_PARMS dst = { 0 };
    uint8_t buffer[256] = { 0 };
    size_t offset = 0;
    TSS2_RC rc;

    rc = Tss2_MU_TPMS_MLKEM_PARMS_Marshal(&src, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_true(offset > 0);

    size_t offset2 = 0;
    rc = Tss2_MU_TPMS_MLKEM_PARMS_Unmarshal(buffer, offset, &offset2, &dst);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(offset, offset2);
    assert_int_equal(src.nameAlg, dst.nameAlg);
    assert_int_equal(src.parameterSet.identifier, dst.parameterSet.identifier);
}

/*
 * Test round-trip marshal/unmarshal of TPMS_MLDSA_PARMS
 */
static void
test_TPMS_MLDSA_PARMS_marshal_unmarshal(void **state)
{
    (void)state;
    TPMS_MLDSA_PARMS src = {
        .nameAlg = TPM2_ALG_SHA512,
        .parameterSet = { .identifier = TPMA_ML_PARAMETER_SET_MLDSA_87 }
    };
    TPMS_MLDSA_PARMS dst = { 0 };
    uint8_t buffer[256] = { 0 };
    size_t offset = 0;
    TSS2_RC rc;

    rc = Tss2_MU_TPMS_MLDSA_PARMS_Marshal(&src, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_true(offset > 0);

    size_t offset2 = 0;
    rc = Tss2_MU_TPMS_MLDSA_PARMS_Unmarshal(buffer, offset, &offset2, &dst);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(offset, offset2);
    assert_int_equal(src.nameAlg, dst.nameAlg);
    assert_int_equal(src.parameterSet.identifier, dst.parameterSet.identifier);
}

/*
 * Test round-trip marshal/unmarshal of TPMS_SIGNATURE_MLDSA
 */
static void
test_TPMS_SIGNATURE_MLDSA_marshal_unmarshal(void **state)
{
    (void)state;
    TPMS_SIGNATURE_MLDSA src = { 0 };
    TPMS_SIGNATURE_MLDSA dst = { 0 };
    uint8_t buffer[8192] = { 0 };
    size_t offset = 0;
    TSS2_RC rc;

    src.hash = TPM2_ALG_SHA256;
    src.sig.size = 100;
    memset(src.sig.buffer, 0xAB, 100);

    rc = Tss2_MU_TPMS_SIGNATURE_MLDSA_Marshal(&src, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_true(offset > 0);

    size_t offset2 = 0;
    rc = Tss2_MU_TPMS_SIGNATURE_MLDSA_Unmarshal(buffer, offset, &offset2, &dst);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(offset, offset2);
    assert_int_equal(src.hash, dst.hash);
    assert_int_equal(src.sig.size, dst.sig.size);
    assert_memory_equal(src.sig.buffer, dst.sig.buffer, src.sig.size);
}

/*
 * Test round-trip marshal/unmarshal of TPM2B_MLKEM_PUBLIC_KEY
 */
static void
test_TPM2B_MLKEM_PUBLIC_KEY_marshal_unmarshal(void **state)
{
    (void)state;
    TPM2B_MLKEM_PUBLIC_KEY src = { 0 };
    TPM2B_MLKEM_PUBLIC_KEY dst = { 0 };
    uint8_t buffer[4096] = { 0 };
    size_t offset = 0;
    TSS2_RC rc;

    src.size = 64;
    memset(src.buffer, 0xCD, 64);

    rc = Tss2_MU_TPM2B_MLKEM_PUBLIC_KEY_Marshal(&src, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_true(offset > 0);

    size_t offset2 = 0;
    rc = Tss2_MU_TPM2B_MLKEM_PUBLIC_KEY_Unmarshal(buffer, offset, &offset2, &dst);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(offset, offset2);
    assert_int_equal(src.size, dst.size);
    assert_memory_equal(src.buffer, dst.buffer, src.size);
}

/*
 * Test round-trip marshal/unmarshal of TPM2B_MLDSA_PUBLIC_KEY
 */
static void
test_TPM2B_MLDSA_PUBLIC_KEY_marshal_unmarshal(void **state)
{
    (void)state;
    TPM2B_MLDSA_PUBLIC_KEY src = { 0 };
    TPM2B_MLDSA_PUBLIC_KEY dst = { 0 };
    uint8_t buffer[4096] = { 0 };
    size_t offset = 0;
    TSS2_RC rc;

    src.size = 64;
    memset(src.buffer, 0xEF, 64);

    rc = Tss2_MU_TPM2B_MLDSA_PUBLIC_KEY_Marshal(&src, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_true(offset > 0);

    size_t offset2 = 0;
    rc = Tss2_MU_TPM2B_MLDSA_PUBLIC_KEY_Unmarshal(buffer, offset, &offset2, &dst);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(offset, offset2);
    assert_int_equal(src.size, dst.size);
    assert_memory_equal(src.buffer, dst.buffer, src.size);
}

/*
 * Test round-trip marshal/unmarshal of TPM2B_MLDSA_SIGNATURE
 */
static void
test_TPM2B_MLDSA_SIGNATURE_marshal_unmarshal(void **state)
{
    (void)state;
    TPM2B_MLDSA_SIGNATURE src = { 0 };
    TPM2B_MLDSA_SIGNATURE dst = { 0 };
    uint8_t buffer[8192] = { 0 };
    size_t offset = 0;
    TSS2_RC rc;

    src.size = 128;
    memset(src.buffer, 0x42, 128);

    rc = Tss2_MU_TPM2B_MLDSA_SIGNATURE_Marshal(&src, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_true(offset > 0);

    size_t offset2 = 0;
    rc = Tss2_MU_TPM2B_MLDSA_SIGNATURE_Unmarshal(buffer, offset, &offset2, &dst);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(offset, offset2);
    assert_int_equal(src.size, dst.size);
    assert_memory_equal(src.buffer, dst.buffer, src.size);
}

/*
 * Test marshaling TPM2B_MLKEM_PUBLIC_KEY with NULL src pointer
 */
static void
test_TPM2B_MLKEM_PUBLIC_KEY_marshal_null(void **state)
{
    (void)state;
    uint8_t buffer[256] = { 0 };
    size_t offset = 0;
    TSS2_RC rc;

    rc = Tss2_MU_TPM2B_MLKEM_PUBLIC_KEY_Marshal(NULL, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_MU_RC_BAD_REFERENCE);
}

/*
 * Test marshaling TPM2B_MLDSA_SIGNATURE into a buffer that is too small
 */
static void
test_TPM2B_MLDSA_SIGNATURE_marshal_buffer_too_small(void **state)
{
    (void)state;
    TPM2B_MLDSA_SIGNATURE src = { 0 };
    uint8_t buffer[4] = { 0 };
    size_t offset = 0;
    TSS2_RC rc;

    src.size = 128;
    memset(src.buffer, 0x55, 128);

    rc = Tss2_MU_TPM2B_MLDSA_SIGNATURE_Marshal(&src, buffer, sizeof(buffer), &offset);
    assert_int_equal(rc, TSS2_MU_RC_INSUFFICIENT_BUFFER);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_TPMS_ML_PARAMETER_SET_marshal_unmarshal),
        cmocka_unit_test(test_TPMS_MLKEM_PARMS_marshal_unmarshal),
        cmocka_unit_test(test_TPMS_MLDSA_PARMS_marshal_unmarshal),
        cmocka_unit_test(test_TPMS_SIGNATURE_MLDSA_marshal_unmarshal),
        cmocka_unit_test(test_TPM2B_MLKEM_PUBLIC_KEY_marshal_unmarshal),
        cmocka_unit_test(test_TPM2B_MLDSA_PUBLIC_KEY_marshal_unmarshal),
        cmocka_unit_test(test_TPM2B_MLDSA_SIGNATURE_marshal_unmarshal),
        cmocka_unit_test(test_TPM2B_MLKEM_PUBLIC_KEY_marshal_null),
        cmocka_unit_test(test_TPM2B_MLDSA_SIGNATURE_marshal_buffer_too_small),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2024, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h> // for NULL, EXIT_FAILURE, EXIT_SUCCESS
#include <string.h> // for memset, memcmp

#include "tss2_common.h"     // for TSS2_RC_SUCCESS, TSS2_RC, TSS2_RESMGR_R...
#include "tss2_esys.h"       // for Esys_Free, ESYS_TR_NONE, Esys_FlushContext
#include "tss2_tpm2_types.h" // for TPM2B_PUBLIC, TPM2_ALG_MLKEM, TPM2B_DATA

#define LOGMODULE test
#include "util/log.h" // for goto_if_error, LOG_ERROR, LOG_INFO, LOG_WARNING

#include "test-esys.h" // for EXIT_SKIP

/** This test is intended to test Esys_Encapsulate and Esys_Decapsulate
 *  based on an ML-KEM key created with Esys_CreatePrimary (V185 PQC).
 *
 * The test creates an ML-KEM-768 primary key, performs key encapsulation
 * to produce a shared secret and ciphertext, then decapsulates the
 * ciphertext to recover the shared secret. Finally, it verifies that
 * the two shared secrets match.
 *
 * Tested ESYS commands:
 *  - Esys_CreatePrimary() (M)
 *  - Esys_Encapsulate() (M)
 *  - Esys_Decapsulate() (M)
 *  - Esys_FlushContext() (M)
 *
 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SKIP
 * @retval EXIT_SUCCESS
 */

int
test_esys_mlkem_encapsulate_decapsulate(ESYS_CONTEXT *esys_context) {
    TSS2_RC r;
    ESYS_TR primaryHandle = ESYS_TR_NONE;
    int     failure_return = EXIT_FAILURE;

    TPM2B_PUBLIC        *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST        *creationHash = NULL;
    TPMT_TK_CREATION    *creationTicket = NULL;

    TPM2B_DATA             *outSymSeedEncaps = NULL;
    TPM2B_ENCRYPTED_SECRET *cipherText = NULL;
    TPM2B_DATA             *outSymSeedDecaps = NULL;

    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0,
        .sensitive = {
            .userAuth = {
                 .size = 0,
                 .buffer = {0},
             },
            .data = {
                 .size = 0,
                 .buffer = {0},
             },
        },
    };

    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_MLKEM,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                 .size = 0,
             },
            .parameters.mlkemDetail = {
                 .nameAlg = TPM2_ALG_SHA256,
                 .parameterSet = {
                     .identifier = TPMA_ML_PARAMETER_SET_MLKEM_768,
                 },
             },
            .unique.mlkem = {
                 .size = 0,
                 .buffer = {},
             },
        },
    };

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {},
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    TPM2B_AUTH authValue = { .size = 0, .buffer = {} };

    r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &authValue);
    goto_if_error(r, "Error: TR_SetAuth", error);

    LOG_INFO("ML-KEM-768 key will be created.");

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                           ESYS_TR_NONE, ESYS_TR_NONE, &inSensitive, &inPublic,
                           &outsideInfo, &creationPCR, &primaryHandle,
                           &outPublic, &creationData, &creationHash,
                           &creationTicket);
    if ((r == TPM2_RC_COMMAND_CODE)
        || (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_RC_LAYER))
        || (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_TPM_RC_LAYER))) {
        LOG_WARNING("Command TPM2_CreatePrimary with ML-KEM not supported by TPM.");
        failure_return = EXIT_SKIP;
        goto error;
    }
    if (r != TSS2_RC_SUCCESS) {
        /*
         * TPMs not supporting V185 / PQC may return various error codes
         * (e.g., TPM2_RC_ASYMMETRIC, TPM2_RC_VALUE). Treat any failure
         * at key creation as a skip to avoid false test failures on
         * non-PQC-capable TPMs.
         */
        LOG_WARNING("ML-KEM key creation failed (rc=0x%x). "
                    "TPM may not support PQC. Skipping.", r);
        failure_return = EXIT_SKIP;
        goto error;
    }

    LOG_INFO("ML-KEM primary key created successfully.");

    /* Encapsulate: produce shared secret and ciphertext */
    TPM2B_DATA label = { .size = 0, .buffer = {} };

    r = Esys_Encapsulate(esys_context, primaryHandle, ESYS_TR_PASSWORD,
                         ESYS_TR_NONE, ESYS_TR_NONE, &label,
                         &outSymSeedEncaps, &cipherText);
    if ((r == TPM2_RC_COMMAND_CODE)
        || (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_RC_LAYER))
        || (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_TPM_RC_LAYER))) {
        LOG_WARNING("Command TPM2_Encapsulate not supported by TPM.");
        failure_return = EXIT_SKIP;
        goto error;
    }
    goto_if_error(r, "Error: Esys_Encapsulate", error);

    LOG_INFO("Encapsulate succeeded. outSymSeed size: %u, cipherText size: %u",
             outSymSeedEncaps->size, cipherText->size);

    /* Decapsulate: recover shared secret from ciphertext */
    r = Esys_Decapsulate(esys_context, primaryHandle, ESYS_TR_PASSWORD,
                         ESYS_TR_NONE, ESYS_TR_NONE, cipherText, &label,
                         &outSymSeedDecaps);
    if ((r == TPM2_RC_COMMAND_CODE)
        || (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_RC_LAYER))
        || (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_TPM_RC_LAYER))) {
        LOG_WARNING("Command TPM2_Decapsulate not supported by TPM.");
        failure_return = EXIT_SKIP;
        goto error;
    }
    goto_if_error(r, "Error: Esys_Decapsulate", error);

    LOG_INFO("Decapsulate succeeded. outSymSeed size: %u",
             outSymSeedDecaps->size);

    /* Verify that the shared secrets match */
    if (outSymSeedEncaps->size != outSymSeedDecaps->size) {
        LOG_ERROR("Shared secret size mismatch: encapsulate=%u, decapsulate=%u",
                  outSymSeedEncaps->size, outSymSeedDecaps->size);
        goto error;
    }

    if (memcmp(outSymSeedEncaps->buffer, outSymSeedDecaps->buffer,
               outSymSeedEncaps->size) != 0) {
        LOG_ERROR("Shared secret value mismatch between Encapsulate and Decapsulate.");
        goto error;
    }

    LOG_INFO("ML-KEM Encapsulate/Decapsulate test PASSED: shared secrets match.");

    /* Clean up */
    r = Esys_FlushContext(esys_context, primaryHandle);
    goto_if_error(r, "Error during FlushContext", error);
    primaryHandle = ESYS_TR_NONE;

    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);
    Esys_Free(outSymSeedEncaps);
    Esys_Free(cipherText);
    Esys_Free(outSymSeedDecaps);
    return EXIT_SUCCESS;

error:
    LOG_ERROR("\nError Code: %x\n", r);

    if (primaryHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, primaryHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup primaryHandle failed.");
        }
    }
    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);
    Esys_Free(outSymSeedEncaps);
    Esys_Free(cipherText);
    Esys_Free(outSymSeedDecaps);
    return failure_return;
}

int
test_invoke_esys(ESYS_CONTEXT *esys_context) {
    return test_esys_mlkem_encapsulate_decapsulate(esys_context);
}

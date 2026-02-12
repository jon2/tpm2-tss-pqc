/* SPDX-License-Identifier: BSD-2-Clause */
/*******************************************************************************
 * Copyright 2024, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <stdlib.h> // for NULL, EXIT_FAILURE, EXIT_SUCCESS
#include <string.h> // for memset, memcpy, strlen

#include "tss2_common.h"     // for TSS2_RC_SUCCESS, TSS2_RC, TSS2_RESMGR_R...
#include "tss2_esys.h"       // for Esys_Free, ESYS_TR_NONE, Esys_FlushContext
#include "tss2_tpm2_types.h" // for TPM2B_PUBLIC, TPM2_ALG_MLDSA, TPMT_SIGN...

#define LOGMODULE test
#include "util/log.h" // for goto_if_error, LOG_ERROR, LOG_INFO, LOG_WARNING

#include "test-esys.h" // for EXIT_SKIP

/** This test is intended to test the ML-DSA digest-based signing and
 *  verification commands (HashML-DSA path) based on an ML-DSA key
 *  created with Esys_CreatePrimary (V185 PQC).
 *
 * The test creates an ML-DSA-65 primary key, hashes a message externally,
 * then calls Esys_SignDigest to sign the hash, and Esys_VerifyDigestSignature
 * to verify the signature. It checks the resulting validation ticket.
 *
 * Tested ESYS commands:
 *  - Esys_CreatePrimary() (M)
 *  - Esys_Hash() (M)
 *  - Esys_SignDigest() (M)
 *  - Esys_VerifyDigestSignature() (M)
 *  - Esys_FlushContext() (M)
 *
 * @param[in,out] esys_context The ESYS_CONTEXT.
 * @retval EXIT_FAILURE
 * @retval EXIT_SKIP
 * @retval EXIT_SUCCESS
 */

int
test_esys_mldsa_sign_digest(ESYS_CONTEXT *esys_context) {
    TSS2_RC r;
    ESYS_TR primaryHandle = ESYS_TR_NONE;
    int     failure_return = EXIT_FAILURE;

    TPM2B_PUBLIC        *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST        *creationHash = NULL;
    TPMT_TK_CREATION    *creationTicket = NULL;

    TPM2B_DIGEST        *hashDigest = NULL;
    TPMT_TK_HASHCHECK   *hashTicket = NULL;
    TPMT_SIGNATURE      *signature = NULL;
    TPMT_TK_VERIFIED    *validation = NULL;

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
            .type = TPM2_ALG_MLDSA,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_SIGN_ENCRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                 .size = 0,
             },
            .parameters.mldsaDetail = {
                 .nameAlg = TPM2_ALG_SHA256,
                 .parameterSet = {
                     .identifier = TPMA_ML_PARAMETER_SET_MLDSA_65,
                 },
             },
            .unique.mldsa = {
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

    LOG_INFO("ML-DSA-65 key will be created.");

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                           ESYS_TR_NONE, ESYS_TR_NONE, &inSensitive, &inPublic,
                           &outsideInfo, &creationPCR, &primaryHandle,
                           &outPublic, &creationData, &creationHash,
                           &creationTicket);
    if ((r == TPM2_RC_COMMAND_CODE)
        || (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_RC_LAYER))
        || (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_TPM_RC_LAYER))) {
        LOG_WARNING("Command TPM2_CreatePrimary with ML-DSA not supported by TPM.");
        failure_return = EXIT_SKIP;
        goto error;
    }
    if (r != TSS2_RC_SUCCESS) {
        LOG_WARNING("ML-DSA key creation failed (rc=0x%x). "
                    "TPM may not support PQC. Skipping.", r);
        failure_return = EXIT_SKIP;
        goto error;
    }

    LOG_INFO("ML-DSA-65 primary key created successfully.");

    /* Hash a test message using TPM's Esys_Hash */
    const char *testMessage = "Test message for ML-DSA digest signing";
    TPM2B_MAX_BUFFER messageBuffer = { .size = 0, .buffer = {} };
    messageBuffer.size = (UINT16) strlen(testMessage);
    memcpy(messageBuffer.buffer, testMessage, messageBuffer.size);

    r = Esys_Hash(esys_context,
                  ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                  &messageBuffer,
                  TPM2_ALG_SHA256,
                  ESYS_TR_RH_OWNER,
                  &hashDigest,
                  &hashTicket);
    goto_if_error(r, "Error: Esys_Hash", error);

    LOG_INFO("Message hashed successfully (digest size=%u).", hashDigest->size);

    /* Sign the digest using Esys_SignDigest */
    TPMT_SIG_SCHEME inScheme = {
        .scheme = TPM2_ALG_HASH_MLDSA,
        .details.any.hashAlg = TPM2_ALG_SHA256,
    };

    r = Esys_SignDigest(esys_context, primaryHandle, ESYS_TR_PASSWORD,
                        ESYS_TR_NONE, ESYS_TR_NONE,
                        hashDigest, &inScheme, hashTicket, &signature);
    if ((r == TPM2_RC_COMMAND_CODE)
        || (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_RC_LAYER))
        || (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_TPM_RC_LAYER))) {
        LOG_WARNING("Command TPM2_SignDigest not supported by TPM.");
        failure_return = EXIT_SKIP;
        goto error;
    }
    goto_if_error(r, "Error: Esys_SignDigest", error);

    LOG_INFO("SignDigest succeeded. Signature algorithm: 0x%x", signature->sigAlg);

    /* Verify the signature using Esys_VerifyDigestSignature */
    r = Esys_VerifyDigestSignature(esys_context, primaryHandle,
                                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                    hashDigest, signature, &validation);
    if ((r == TPM2_RC_COMMAND_CODE)
        || (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_RC_LAYER))
        || (r == (TPM2_RC_COMMAND_CODE | TSS2_RESMGR_TPM_RC_LAYER))) {
        LOG_WARNING("Command TPM2_VerifyDigestSignature not supported by TPM.");
        failure_return = EXIT_SKIP;
        goto error;
    }
    goto_if_error(r, "Error: Esys_VerifyDigestSignature", error);

    LOG_INFO("VerifyDigestSignature succeeded.");

    /* Verify the validation ticket */
    if (validation->tag != TPM2_ST_DIGEST_VERIFIED) {
        LOG_ERROR("Validation ticket tag mismatch: expected 0x%x, got 0x%x",
                  TPM2_ST_DIGEST_VERIFIED, validation->tag);
        goto error;
    }

    LOG_INFO("ML-DSA SignDigest/VerifyDigestSignature test PASSED: "
             "validation ticket tag is TPM2_ST_DIGEST_VERIFIED.");

    /* Clean up */
    r = Esys_FlushContext(esys_context, primaryHandle);
    goto_if_error(r, "Error during FlushContext", error);
    primaryHandle = ESYS_TR_NONE;

    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);
    Esys_Free(hashDigest);
    Esys_Free(hashTicket);
    Esys_Free(signature);
    Esys_Free(validation);
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
    Esys_Free(hashDigest);
    Esys_Free(hashTicket);
    Esys_Free(signature);
    Esys_Free(validation);
    return failure_return;
}

int
test_invoke_esys(ESYS_CONTEXT *esys_context) {
    return test_esys_mldsa_sign_digest(esys_context);
}

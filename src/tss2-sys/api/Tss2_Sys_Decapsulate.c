/* SPDX-License-Identifier: BSD-2-Clause */
/***********************************************************************;
 * Copyright (c) 2015 - 2017, Intel Corporation
 * All rights reserved.
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include "sysapi_util.h"
#include "tss2_common.h"
#include "tss2_mu.h"
#include "tss2_sys.h"
#include "tss2_tpm2_types.h"

TSS2_RC
Tss2_Sys_Decapsulate_Prepare(TSS2_SYS_CONTEXT              *sysContext,
                             TPMI_DH_OBJECT                 keyHandle,
                             const TPM2B_ENCRYPTED_SECRET  *cipherText,
                             const TPM2B_DATA              *label) {
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC                rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(ctx, TPM2_CC_Decapsulate);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(keyHandle, ctx->cmdBuffer, ctx->maxCmdSize, &ctx->nextData);
    if (rval)
        return rval;

    if (!cipherText) {
        rval = Tss2_MU_UINT16_Marshal(0, ctx->cmdBuffer, ctx->maxCmdSize, &ctx->nextData);

    } else {

        rval = Tss2_MU_TPM2B_ENCRYPTED_SECRET_Marshal(cipherText, ctx->cmdBuffer, ctx->maxCmdSize,
                                                      &ctx->nextData);
    }

    if (rval)
        return rval;

    if (!label) {
        rval = Tss2_MU_UINT16_Marshal(0, ctx->cmdBuffer, ctx->maxCmdSize, &ctx->nextData);

    } else {

        rval = Tss2_MU_TPM2B_DATA_Marshal(label, ctx->cmdBuffer, ctx->maxCmdSize,
                                          &ctx->nextData);
    }

    if (rval)
        return rval;

    ctx->decryptAllowed = 1;
    ctx->encryptAllowed = 1;
    ctx->authAllowed = 1;

    return CommonPrepareEpilogue(ctx);
}

TSS2_RC
Tss2_Sys_Decapsulate_Complete(TSS2_SYS_CONTEXT *sysContext,
                              TPM2B_DATA       *outSymSeed) {
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC                rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonComplete(ctx);
    if (rval)
        return rval;

    return Tss2_MU_TPM2B_DATA_Unmarshal(ctx->cmdBuffer, ctx->maxCmdSize, &ctx->nextData,
                                        outSymSeed);
}

TSS2_RC
Tss2_Sys_Decapsulate(TSS2_SYS_CONTEXT             *sysContext,
                     TPMI_DH_OBJECT                keyHandle,
                     TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
                     TPM2B_ENCRYPTED_SECRET const *cipherText,
                     TPM2B_DATA const             *label,
                     TPM2B_DATA                   *outSymSeed,
                     TSS2L_SYS_AUTH_RESPONSE      *rspAuthsArray) {
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC                rval;

    rval = Tss2_Sys_Decapsulate_Prepare(sysContext, keyHandle, cipherText, label);
    if (rval)
        return rval;

    rval = CommonOneCall(ctx, cmdAuthsArray, rspAuthsArray);
    if (rval)
        return rval;

    return Tss2_Sys_Decapsulate_Complete(sysContext, outSymSeed);
}

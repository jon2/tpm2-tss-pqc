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
Tss2_Sys_VerifySequenceComplete_Prepare(TSS2_SYS_CONTEXT       *sysContext,
                                         TPMI_DH_OBJECT          sequenceHandle,
                                         const TPM2B_MAX_BUFFER *buffer) {
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC                rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(ctx, TPM2_CC_VerifySequenceComplete);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(sequenceHandle, ctx->cmdBuffer, ctx->maxCmdSize, &ctx->nextData);
    if (rval)
        return rval;

    if (!buffer) {
        ctx->decryptNull = 1;

        rval = Tss2_MU_UINT16_Marshal(0, ctx->cmdBuffer, ctx->maxCmdSize, &ctx->nextData);
    } else {

        rval = Tss2_MU_TPM2B_MAX_BUFFER_Marshal(buffer, ctx->cmdBuffer, ctx->maxCmdSize,
                                                 &ctx->nextData);
    }

    if (rval)
        return rval;

    ctx->decryptAllowed = 1;
    ctx->encryptAllowed = 0;
    ctx->authAllowed = 1;

    return CommonPrepareEpilogue(ctx);
}

TSS2_RC
Tss2_Sys_VerifySequenceComplete_Complete(TSS2_SYS_CONTEXT  *sysContext,
                                          TPMT_TK_VERIFIED  *validation) {
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC                rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonComplete(ctx);
    if (rval)
        return rval;

    return Tss2_MU_TPMT_TK_VERIFIED_Unmarshal(ctx->cmdBuffer, ctx->maxCmdSize, &ctx->nextData,
                                               validation);
}

TSS2_RC
Tss2_Sys_VerifySequenceComplete(TSS2_SYS_CONTEXT             *sysContext,
                                 TPMI_DH_OBJECT                sequenceHandle,
                                 TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
                                 TPM2B_MAX_BUFFER const       *buffer,
                                 TPMT_TK_VERIFIED             *validation,
                                 TSS2L_SYS_AUTH_RESPONSE      *rspAuthsArray) {
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC                rval;

    rval = Tss2_Sys_VerifySequenceComplete_Prepare(sysContext, sequenceHandle, buffer);
    if (rval)
        return rval;

    rval = CommonOneCall(ctx, cmdAuthsArray, rspAuthsArray);
    if (rval)
        return rval;

    return Tss2_Sys_VerifySequenceComplete_Complete(sysContext, validation);
}

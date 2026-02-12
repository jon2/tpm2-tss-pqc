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
Tss2_Sys_SignSequenceStart_Prepare(TSS2_SYS_CONTEXT       *sysContext,
                                   TPMI_DH_OBJECT          keyHandle,
                                   const TPMT_SIG_SCHEME  *inScheme,
                                   TPMI_DH_OBJECT          keyB) {
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC                rval;

    if (!ctx || !inScheme)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonPreparePrologue(ctx, TPM2_CC_SignSequenceStart);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(keyHandle, ctx->cmdBuffer, ctx->maxCmdSize, &ctx->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_TPMT_SIG_SCHEME_Marshal(inScheme, ctx->cmdBuffer, ctx->maxCmdSize,
                                            &ctx->nextData);
    if (rval)
        return rval;

    rval = Tss2_MU_UINT32_Marshal(keyB, ctx->cmdBuffer, ctx->maxCmdSize, &ctx->nextData);
    if (rval)
        return rval;

    ctx->decryptAllowed = 0;
    ctx->encryptAllowed = 0;
    ctx->authAllowed = 1;

    return CommonPrepareEpilogue(ctx);
}

TSS2_RC
Tss2_Sys_SignSequenceStart_Complete(TSS2_SYS_CONTEXT *sysContext,
                                    TPMI_DH_OBJECT   *sequenceHandle) {
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC                rval;

    if (!ctx)
        return TSS2_SYS_RC_BAD_REFERENCE;

    rval = CommonComplete(ctx);
    if (rval)
        return rval;

    return Tss2_MU_UINT32_Unmarshal(ctx->cmdBuffer, ctx->maxCmdSize, &ctx->nextData,
                                    sequenceHandle);
}

TSS2_RC
Tss2_Sys_SignSequenceStart(TSS2_SYS_CONTEXT             *sysContext,
                           TPMI_DH_OBJECT                keyHandle,
                           TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
                           TPMT_SIG_SCHEME const        *inScheme,
                           TPMI_DH_OBJECT                keyB,
                           TPMI_DH_OBJECT               *sequenceHandle,
                           TSS2L_SYS_AUTH_RESPONSE      *rspAuthsArray) {
    TSS2_SYS_CONTEXT_BLOB *ctx = syscontext_cast(sysContext);
    TSS2_RC                rval;

    rval = Tss2_Sys_SignSequenceStart_Prepare(sysContext, keyHandle, inScheme, keyB);
    if (rval)
        return rval;

    rval = CommonOneCall(ctx, cmdAuthsArray, rspAuthsArray);
    if (rval)
        return rval;

    return Tss2_Sys_SignSequenceStart_Complete(sysContext, sequenceHandle);
}

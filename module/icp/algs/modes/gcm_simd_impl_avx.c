/* SPDX-License-Identifier: CDDL-1.0 */
/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or https://opensource.org/licenses/CDDL-1.0.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2025 Attila Fülöp <attila@fueloep.org>
 */

#include <modes/modes.h>
#include <modes/gcm_simd_impl.h>

#if defined CAN_USE_GCM_SIMD_AVX_AESNI_X86

#include <sys/types.h>
#include <sys/simd.h>
#include <aes/aes_impl.h>
#include <modes/gcm_impl.h>
#include <modes/gcm_simd.h>
#include <modes/gcm_simd_impl_avx.h>

static boolean_t
gcm_avx_aesni_will_work(void)
{
	return (kfpu_allowed() &&
	    zfs_aes_available() && zfs_pclmulqdq_available());
}

gcm_impl_ops_t gcm_avx_aesni_impl = {
	.mul = NULL,
	.simd_impl = ZFS_GSO_AVX_AESNI_X64,
	.is_supported = gcm_avx_aesni_will_work,
	.is_fastest = B_FALSE,
	.name = "avx-aesni"
};

static void
gcm_avx_aesni_init_Htab(gcm_ctx_t *ctx)
{
	gcm_init_htab_avx(ctx->gcm_Htable, ctx->gcm_H);
}

static size_t
gcm_avx_aesni_encrypt(
    gcm_ctx_t *ctx, uint8_t *ct, const uint8_t *pt, uint64_t len)
{
	const uint32_t *key = ((aes_key_t *)ctx->gcm_keysched)->encr_ks.ks32;
	uint64_t *cb = ctx->gcm_cb;
	uint64_t *ghash = ctx->gcm_ghash;

	return (aesni_gcm_encrypt(pt, ct, len, key, cb, ghash));
}

static size_t
gcm_avx_aesni_decrypt(
    gcm_ctx_t *ctx, uint8_t *pt, const uint8_t *ct, uint64_t len)
{
	const uint32_t *key = ((aes_key_t *)ctx->gcm_keysched)->encr_ks.ks32;
	uint64_t *cb = ctx->gcm_cb;
	uint64_t *ghash = ctx->gcm_ghash;

	return (aesni_gcm_decrypt(ct, pt, len, key, cb, ghash));
}

static void
clear_fpu_regs_avx(void)
{
	__asm__ __volatile__("vzeroall");
	/* No input, no output, clobber intended. */
}

const gcm_simd_ops_t gcm_simd_ops_avx_aesni __attribute__((aligned(64))) = {
	.impl = ZFS_GSO_AVX_AESNI_X64,
	.name = "avx-aesni",
	.only_12bytes_iv = B_FALSE,
	.pre_inc_cntr = B_TRUE,
	.chunk_size = 32 * 1024 - 32 * 1024 % (GCM_BLOCK_LEN * 6),
	.enc_min_block_size = GCM_BLOCK_LEN * 6 * 3,
	.dec_min_block_size = GCM_BLOCK_LEN * 6,
	.Htab_size = GCM_BLOCK_LEN * 6 * 2,
	.init_Htab = gcm_avx_aesni_init_Htab,
	.init = NULL,
	.ghash = gcm_ghash_avx,
	.encrypt = gcm_avx_aesni_encrypt,
	.decrypt = gcm_avx_aesni_decrypt,
	.encrypt_final = NULL,
	.decrypt_final = NULL,
	.aes_encrypt_block = aes_encrypt_intel,
	.clear_fpu_regs = clear_fpu_regs_avx,
};


#endif /* #if defined CAN_USE_GCM_SIMD_AVX_AESNI_X86 */

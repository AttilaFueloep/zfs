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

/*
 * GCM SIMD function dispatcher.
 */

#ifndef	_GCM_SIMD_IMPL_H
#define	_GCM_SIMD_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/zfs_context.h>

#if defined(__x86_64__) && defined(HAVE_AVX) && defined(HAVE_AES) && \
	defined(HAVE_PCLMULQDQ)
#define	CAN_USE_GCM_SIMD_AVX_AESNI_X86
#if !defined(CAN_USE_GCM_SIMD)
#define	CAN_USE_GCM_SIMD
#endif
#endif

#define	GCM_BLOCK_LEN 16

struct gcm_ctx;

/* Prototypes for functions a SIMD implementation provides. */

/*
 * Seed the table of pre-computed and pre-shifted hash keys H, H^2, ....
 * Mandatory.
 */
typedef void (*gso_init_Htab_func_t)(struct gcm_ctx *ctx);

/*
 * Init the context.
 * Optional, NULL allowed.
 */
typedef void (*gso_init_func_t)(struct gcm_ctx *ctx, const uint8_t *iv,
    const uint8_t *aad, uint64_t iv_len, uint64_t aad_len);

/*
 * Update ghash with contents of in, in+len using Htab.
 * Mandatory.
 */
typedef void (*gso_ghash_func_t)(uint64_t ghash[2], const uint64_t *Htab,
    const uint8_t *in, size_t len);

/*
 * Encrypt plaintext pt and append to ciphertext ct, update ghash.
 * Return number of bytes encrypted.
 * Mandatory.
 */
typedef size_t (*gso_enc_func_t)(
    struct gcm_ctx *ctx, uint8_t *ct, const uint8_t *pt, uint64_t len);

/*
 * Decrypt ciphertext ct and append to plaintext pt, update ghash.
 * Return number of bytes decrypted.
 * Mandatory
 */
typedef size_t (*gso_dec_func_t)(
    struct gcm_ctx *ctx, uint8_t *pt, const uint8_t *ct, uint64_t len);

/*
 * Process pending plaintext data and finalize the authentication tag.
 * Optional, can be NULL.
 */
typedef void (*gso_enc_fin_func_t)(struct gcm_ctx *ctx);

/*
 * Process pending ciphertext data and verify the authentication tag.
 * Optional, can be NULL.
 */
typedef void (*gso_dec_fin_func_t)(struct gcm_ctx *ctx);

/*
 * AES encrpyt a single 16 byte block from pt to ct.
 * Mandatory.
 */
typedef void (*gso_enc_single_block_func_t)(
    const uint32_t keysched[], int rnds, const uint32_t pt[4], uint32_t ct[4]);

/*
 * Zero out all SIMD registers.
 * Mandatory
 */
typedef void (*gso_clear_fpu_regs_t)(void);

/*
 * SIMD implementation selector.
 * If you add to the enum please update gcm_simd_ops[] as well,
 */

typedef enum {
	ZFS_GSO_NOSIMD,
	ZFS_GSO_AVX_AESNI_X64,
	ZFS_GSO_SSE4_1_AESNI_X64,
	ZFS_GSO_MAX
	// XXXX ZFS_GSI_PAD = INT32_MAX
} gcm_simd_impl_t;

/*
 * The following defines an interface for AES-GCM SIMD.
 * It consists of functions the implementation must provide and flags which
 * describe supported properties.
 */
typedef const struct gcm_simd_ops {
	const gso_enc_func_t encrypt;
	const gso_dec_func_t decrypt;
	const gso_enc_fin_func_t encrypt_final;
	const gso_dec_fin_func_t decrypt_final;
	const gso_clear_fpu_regs_t clear_fpu_regs;
	const uint32_t chunk_size;
	const int enc_min_block_size;
	const int dec_min_block_size;
	const gcm_simd_impl_t impl;	// XXXX needed? Actuall pad right now
	const char *name;		/* 64 bytes up to here. */
	const gso_enc_single_block_func_t aes_encrypt_block;
	const gso_ghash_func_t ghash;
	const gso_init_Htab_func_t init_Htab;
	const size_t Htab_size;
	const gso_init_func_t init;
	const boolean_t only_12bytes_iv;
	const boolean_t pre_inc_cntr;
	const boolean_t fastest;
	const int32_t pad[3];	/* Pad to 128 bytes. */

} gcm_simd_ops_t;

extern const gcm_simd_ops_t *gcm_simd_ops[ZFS_GSO_MAX];
extern const char *gcm_simd_impl_to_string(gcm_simd_ops_t *ops);

#ifdef	__cplusplus
}
#endif

#endif	/* _GCM_SIMD_IMPL_H */

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

#ifdef CAN_USE_GCM_SIMD_AVX_AESNI_X86
#ifndef	_GCM_SIMD_IMPL_AVX_H
#define	_GCM_SIMD_IMPL_AVX_H

#include "modes/gcm_simd_impl.h"
#include <sys/asm_linkage.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern const gcm_simd_ops_t gcm_simd_ops_avx_aesni;
extern gcm_impl_ops_t gcm_avx_aesni_impl;

extern void ASMABI gcm_ghash_avx(uint64_t ghash[2], const uint64_t *Htable,
    const uint8_t *in, size_t len);
extern void ASMABI gcm_init_htab_avx(uint64_t *Htable, const uint64_t H[2]);
extern size_t ASMABI aesni_gcm_encrypt(const uint8_t *pt, uint8_t *ct,
    size_t len, const void *key, uint64_t *cb, uint64_t *ghash);
extern size_t ASMABI aesni_gcm_decrypt(const uint8_t *ct, uint8_t *pt,
    size_t len, const void *key, uint64_t *cb, uint64_t *ghash);
extern ASMABI void aes_encrypt_intel(const uint32_t rk[], int Nr,
    const uint32_t pt[4], uint32_t ct[4]);

#ifdef	__cplusplus
}
#endif

#endif	/* #ifndef _GCM_SIMD_IMPL_AVX_H */
#endif /* #ifdef CAN_USE_GCM_SIMD_AVX_AESNI_X86 */

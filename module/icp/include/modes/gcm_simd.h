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

#ifndef	_GCM_SIMD_H
#define	_GCM_SIMD_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <modes/modes.h>

extern int gcm_init_simd(gcm_ctx_t *ctx, const uint8_t *iv, size_t iv_len,
    const uint8_t *auth_data, size_t auth_data_len);

extern int gcm_mode_encrypt_contiguous_blocks_simd(
    gcm_ctx_t *ctx, char *data, size_t length, crypto_data_t *out);

extern int gcm_mode_decrypt_contiguous_blocks_simd(
    gcm_ctx_t *ctx, char *data, size_t length);

extern int gcm_encrypt_final_simd(gcm_ctx_t *ctx, crypto_data_t *out);
extern int gcm_decrypt_final_simd(gcm_ctx_t *ctx, crypto_data_t *out);

#ifdef	__cplusplus
}
#endif

#endif	/* _GCM_SIMD_H */

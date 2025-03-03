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

#include <modes/gcm_impl.h>
#include <modes/gcm_simd_impl.h>
#include <modes/gcm_simd_impl_avx.h>

/*
 * This is the entry point where you plug in new SIMD implementations.
 * TODO elaborate
 * 1. Add an entry to the gcm_simd_impl_t enum in gcm_simd_impl.h.
 * 2. Add gcm_impl_ops_t and gcm_simd_ops_t in new file.
 * 3. Add the newly defined gcm_impl_ops_t to gcm_all_impl[] in gcm.c.
 * 4. Add gcm_simd_ops_t below.
 * 5. Debug.
 * 6. You may want to change the initialization of the fastest implementation
 *    in gcm_impl_init() in gcm.c.
 */

gcm_simd_ops_t gcm_simd_ops_generic = {
	.impl = ZFS_GSO_NOSIMD,
	.name = "generic",
};

const gcm_simd_ops_t *gcm_simd_ops[ZFS_GSO_MAX] = {
	[ZFS_GSO_NOSIMD] = &gcm_simd_ops_generic,
#if defined(CAN_USE_GCM_SIMD_AVX_AESNI_X86)
	[ZFS_GSO_AVX_AESNI_X64] = &gcm_simd_ops_avx_aesni
#endif
};

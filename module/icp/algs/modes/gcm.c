// SPDX-License-Identifier: CDDL-1.0
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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include "sys/types.h"
#include <sys/zfs_context.h>
#include <sys/cmn_err.h>
#include <modes/modes.h>
#include <sys/crypto/common.h>
#include <sys/crypto/icp.h>
#include <sys/crypto/impl.h>
#include <sys/byteorder.h>
#include <modes/gcm_impl.h>
#ifdef CAN_USE_GCM_SIMD
#include <sys/simd.h>
#include <aes/aes_impl.h>
#include <modes/gcm_simd.h>
#include <modes/gcm_simd_impl.h>
#include <modes/gcm_simd_impl_avx.h>
#endif

#define	GHASH(c, d, t, o) \
	xor_block((uint8_t *)(d), (uint8_t *)(c)->gcm_ghash); \
	(o)->mul((uint64_t *)(void *)(c)->gcm_ghash, (c)->gcm_H, \
	(uint64_t *)(void *)(t));

/* Select GCM implementation */
#define	IMPL_FASTEST	(UINT32_MAX)
#define	IMPL_CYCLE	(UINT32_MAX-1)
#define	GCM_IMPL_READ(i) (*(volatile uint32_t *) &(i))

static uint32_t icp_gcm_impl = IMPL_FASTEST;
static uint32_t user_sel_impl = IMPL_FASTEST;

/* GCM implementation that contains the fastest methods */
static gcm_impl_ops_t gcm_fastest_impl = {
	.name = "fastest"
};

/* All compiled in implementations */
static const gcm_impl_ops_t *gcm_all_impl[] = {
	&gcm_generic_impl,
#if defined(__x86_64) && defined(HAVE_PCLMULQDQ)
	&gcm_pclmulqdq_impl,
#endif
#if defined CAN_USE_GCM_SIMD_AVX_AESNI_X86
	&gcm_avx_aesni_impl,
#endif
};

/* Hold all supported implementations */
static uint32_t gcm_supp_impl_cnt = 0;
static gcm_impl_ops_t *gcm_supp_impl[ARRAY_SIZE(gcm_all_impl)];


#ifdef CAN_USE_GCM_SIMD
/* Monotonic increasing counter used for the cycle implementation. */
static uint32_t gcm_impl_cycle_cnt = 0;

/* Does the architecture we run on support the MOVBE instruction? */
boolean_t gcm_avx_can_use_movbe = B_FALSE;

extern boolean_t ASMABI atomic_toggle_boolean_nv(volatile boolean_t *);

#endif /* ifdef CAN_USE_GCM_SIMD */

/*
 * Encrypt multiple blocks of data in GCM mode.  Decrypt for GCM mode
 * is done in another function.
 */
int
gcm_mode_encrypt_contiguous_blocks(gcm_ctx_t *ctx, char *data, size_t length,
    crypto_data_t *out, size_t block_size,
    int (*encrypt_block)(const void *, const uint8_t *, uint8_t *),
    void (*copy_block)(uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	const gcm_impl_ops_t *gops;
	size_t remainder = length;
	size_t need = 0;
	uint8_t *datap = (uint8_t *)data;
	uint8_t *blockp;
	uint8_t *lastp;
	void *iov_or_mp;
	offset_t offset;
	uint8_t *out_data_1;
	uint8_t *out_data_2;
	size_t out_data_1_len;
	uint64_t counter;
	uint64_t counter_mask = ntohll(0x00000000ffffffffULL);

	if (length + ctx->gcm_remainder_len < block_size) {
		/* accumulate bytes here and return */
		memcpy((uint8_t *)ctx->gcm_remainder + ctx->gcm_remainder_len,
		    datap,
		    length);
		ctx->gcm_remainder_len += length;
		if (ctx->gcm_copy_to == NULL) {
			ctx->gcm_copy_to = datap;
		}
		return (CRYPTO_SUCCESS);
	}

	crypto_init_ptrs(out, &iov_or_mp, &offset);

	gops = gcm_impl_get_ops();
	do {
		/* Unprocessed data from last call. */
		if (ctx->gcm_remainder_len > 0) {
			need = block_size - ctx->gcm_remainder_len;

			if (need > remainder)
				return (CRYPTO_DATA_LEN_RANGE);

			memcpy(&((uint8_t *)ctx->gcm_remainder)
			    [ctx->gcm_remainder_len], datap, need);

			blockp = (uint8_t *)ctx->gcm_remainder;
		} else {
			blockp = datap;
		}

		/*
		 * Increment counter. Counter bits are confined
		 * to the bottom 32 bits of the counter block.
		 */
		counter = ntohll(ctx->gcm_cb[1] & counter_mask);
		counter = htonll(counter + 1);
		counter &= counter_mask;
		ctx->gcm_cb[1] = (ctx->gcm_cb[1] & ~counter_mask) | counter;

		encrypt_block(ctx->gcm_keysched, (uint8_t *)ctx->gcm_cb,
		    (uint8_t *)ctx->gcm_tmp);
		xor_block(blockp, (uint8_t *)ctx->gcm_tmp);

		lastp = (uint8_t *)ctx->gcm_tmp;

		ctx->gcm_processed_data_len += block_size;

		crypto_get_ptrs(out, &iov_or_mp, &offset, &out_data_1,
		    &out_data_1_len, &out_data_2, block_size);

		/* copy block to where it belongs */
		if (out_data_1_len == block_size) {
			copy_block(lastp, out_data_1);
		} else {
			memcpy(out_data_1, lastp, out_data_1_len);
			if (out_data_2 != NULL) {
				memcpy(out_data_2,
				    lastp + out_data_1_len,
				    block_size - out_data_1_len);
			}
		}
		/* update offset */
		out->cd_offset += block_size;

		/* add ciphertext to the hash */
		GHASH(ctx, ctx->gcm_tmp, ctx->gcm_ghash, gops);

		/* Update pointer to next block of data to be processed. */
		if (ctx->gcm_remainder_len != 0) {
			datap += need;
			ctx->gcm_remainder_len = 0;
		} else {
			datap += block_size;
		}

		remainder = (size_t)&data[length] - (size_t)datap;

		/* Incomplete last block. */
		if (remainder > 0 && remainder < block_size) {
			memcpy(ctx->gcm_remainder, datap, remainder);
			ctx->gcm_remainder_len = remainder;
			ctx->gcm_copy_to = datap;
			goto out;
		}
		ctx->gcm_copy_to = NULL;

	} while (remainder > 0);
out:
	return (CRYPTO_SUCCESS);
}

int
gcm_encrypt_final(gcm_ctx_t *ctx, crypto_data_t *out, size_t block_size,
    int (*encrypt_block)(const void *, const uint8_t *, uint8_t *),
    void (*copy_block)(uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	(void) copy_block;
	const gcm_impl_ops_t *gops;
	uint64_t counter_mask = ntohll(0x00000000ffffffffULL);
	uint8_t *ghash, *macp = NULL;
	int i, rv;

	if (out->cd_length <
	    (ctx->gcm_remainder_len + ctx->gcm_tag_len)) {
		return (CRYPTO_DATA_LEN_RANGE);
	}

	gops = gcm_impl_get_ops();
	ghash = (uint8_t *)ctx->gcm_ghash;

	if (ctx->gcm_remainder_len > 0) {
		uint64_t counter;
		uint8_t *tmpp = (uint8_t *)ctx->gcm_tmp;

		/*
		 * Here is where we deal with data that is not a
		 * multiple of the block size.
		 */

		/*
		 * Increment counter.
		 */
		counter = ntohll(ctx->gcm_cb[1] & counter_mask);
		counter = htonll(counter + 1);
		counter &= counter_mask;
		ctx->gcm_cb[1] = (ctx->gcm_cb[1] & ~counter_mask) | counter;

		encrypt_block(ctx->gcm_keysched, (uint8_t *)ctx->gcm_cb,
		    (uint8_t *)ctx->gcm_tmp);

		macp = (uint8_t *)ctx->gcm_remainder;
		memset(macp + ctx->gcm_remainder_len, 0,
		    block_size - ctx->gcm_remainder_len);

		/* XOR with counter block */
		for (i = 0; i < ctx->gcm_remainder_len; i++) {
			macp[i] ^= tmpp[i];
		}

		/* add ciphertext to the hash */
		GHASH(ctx, macp, ghash, gops);

		ctx->gcm_processed_data_len += ctx->gcm_remainder_len;
	}

	ctx->gcm_len_a_len_c[1] =
	    htonll(CRYPTO_BYTES2BITS(ctx->gcm_processed_data_len));
	GHASH(ctx, ctx->gcm_len_a_len_c, ghash, gops);
	encrypt_block(ctx->gcm_keysched, (uint8_t *)ctx->gcm_J0,
	    (uint8_t *)ctx->gcm_J0);
	xor_block((uint8_t *)ctx->gcm_J0, ghash);

	if (ctx->gcm_remainder_len > 0) {
		rv = crypto_put_output_data(macp, out, ctx->gcm_remainder_len);
		if (rv != CRYPTO_SUCCESS)
			return (rv);
	}
	out->cd_offset += ctx->gcm_remainder_len;
	ctx->gcm_remainder_len = 0;
	rv = crypto_put_output_data(ghash, out, ctx->gcm_tag_len);
	if (rv != CRYPTO_SUCCESS)
		return (rv);
	out->cd_offset += ctx->gcm_tag_len;

	return (CRYPTO_SUCCESS);
}

/*
 * This will only deal with decrypting the last block of the input that
 * might not be a multiple of block length.
 */
static void
gcm_decrypt_incomplete_block(gcm_ctx_t *ctx, size_t block_size, size_t index,
    int (*encrypt_block)(const void *, const uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	uint8_t *datap, *outp, *counterp;
	uint64_t counter;
	uint64_t counter_mask = ntohll(0x00000000ffffffffULL);
	int i;

	/*
	 * Increment counter.
	 * Counter bits are confined to the bottom 32 bits
	 */
	counter = ntohll(ctx->gcm_cb[1] & counter_mask);
	counter = htonll(counter + 1);
	counter &= counter_mask;
	ctx->gcm_cb[1] = (ctx->gcm_cb[1] & ~counter_mask) | counter;

	datap = (uint8_t *)ctx->gcm_remainder;
	outp = &((ctx->gcm_pt_buf)[index]);
	counterp = (uint8_t *)ctx->gcm_tmp;

	/* authentication tag */
	memset((uint8_t *)ctx->gcm_tmp, 0, block_size);
	memcpy((uint8_t *)ctx->gcm_tmp, datap, ctx->gcm_remainder_len);

	/* add ciphertext to the hash */
	GHASH(ctx, ctx->gcm_tmp, ctx->gcm_ghash, gcm_impl_get_ops());

	/* decrypt remaining ciphertext */
	encrypt_block(ctx->gcm_keysched, (uint8_t *)ctx->gcm_cb, counterp);

	/* XOR with counter block */
	for (i = 0; i < ctx->gcm_remainder_len; i++) {
		outp[i] = datap[i] ^ counterp[i];
	}
}

int
gcm_mode_decrypt_contiguous_blocks(gcm_ctx_t *ctx, char *data, size_t length,
    crypto_data_t *out, size_t block_size,
    int (*encrypt_block)(const void *, const uint8_t *, uint8_t *),
    void (*copy_block)(uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	(void) out, (void) block_size, (void) encrypt_block, (void) copy_block,
	    (void) xor_block;
	size_t new_len;
	uint8_t *new;

	/*
	 * Copy contiguous ciphertext input blocks to plaintext buffer.
	 * Ciphertext will be decrypted in the final.
	 */
	if (length > 0) {
		new_len = ctx->gcm_pt_buf_len + length;
		new = vmem_alloc(new_len, KM_SLEEP);
		if (new == NULL) {
			vmem_free(ctx->gcm_pt_buf, ctx->gcm_pt_buf_len);
			ctx->gcm_pt_buf = NULL;
			return (CRYPTO_HOST_MEMORY);
		}

		if (ctx->gcm_pt_buf != NULL) {
			memcpy(new, ctx->gcm_pt_buf, ctx->gcm_pt_buf_len);
			vmem_free(ctx->gcm_pt_buf, ctx->gcm_pt_buf_len);
		} else {
			ASSERT0(ctx->gcm_pt_buf_len);
		}

		ctx->gcm_pt_buf = new;
		ctx->gcm_pt_buf_len = new_len;
		memcpy(&ctx->gcm_pt_buf[ctx->gcm_processed_data_len], data,
		    length);
		ctx->gcm_processed_data_len += length;
	}

	ctx->gcm_remainder_len = 0;
	return (CRYPTO_SUCCESS);
}

int
gcm_decrypt_final(gcm_ctx_t *ctx, crypto_data_t *out, size_t block_size,
    int (*encrypt_block)(const void *, const uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	const gcm_impl_ops_t *gops;
	size_t pt_len;
	size_t remainder;
	uint8_t *ghash;
	uint8_t *blockp;
	uint8_t *cbp;
	uint64_t counter;
	uint64_t counter_mask = ntohll(0x00000000ffffffffULL);
	int processed = 0, rv;

	ASSERT(ctx->gcm_processed_data_len == ctx->gcm_pt_buf_len);

	gops = gcm_impl_get_ops();
	pt_len = ctx->gcm_processed_data_len - ctx->gcm_tag_len;
	ghash = (uint8_t *)ctx->gcm_ghash;
	blockp = ctx->gcm_pt_buf;
	remainder = pt_len;
	while (remainder > 0) {
		/* Incomplete last block */
		if (remainder < block_size) {
			memcpy(ctx->gcm_remainder, blockp, remainder);
			ctx->gcm_remainder_len = remainder;
			/*
			 * not expecting anymore ciphertext, just
			 * compute plaintext for the remaining input
			 */
			gcm_decrypt_incomplete_block(ctx, block_size,
			    processed, encrypt_block, xor_block);
			ctx->gcm_remainder_len = 0;
			goto out;
		}
		/* add ciphertext to the hash */
		GHASH(ctx, blockp, ghash, gops);

		/*
		 * Increment counter.
		 * Counter bits are confined to the bottom 32 bits
		 */
		counter = ntohll(ctx->gcm_cb[1] & counter_mask);
		counter = htonll(counter + 1);
		counter &= counter_mask;
		ctx->gcm_cb[1] = (ctx->gcm_cb[1] & ~counter_mask) | counter;

		cbp = (uint8_t *)ctx->gcm_tmp;
		encrypt_block(ctx->gcm_keysched, (uint8_t *)ctx->gcm_cb, cbp);

		/* XOR with ciphertext */
		xor_block(cbp, blockp);

		processed += block_size;
		blockp += block_size;
		remainder -= block_size;
	}
out:
	ctx->gcm_len_a_len_c[1] = htonll(CRYPTO_BYTES2BITS(pt_len));
	GHASH(ctx, ctx->gcm_len_a_len_c, ghash, gops);
	encrypt_block(ctx->gcm_keysched, (uint8_t *)ctx->gcm_J0,
	    (uint8_t *)ctx->gcm_J0);
	xor_block((uint8_t *)ctx->gcm_J0, ghash);

	/* compare the input authentication tag with what we calculated */
	if (memcmp(&ctx->gcm_pt_buf[pt_len], ghash, ctx->gcm_tag_len)) {
		/* They don't match */
		return (CRYPTO_INVALID_MAC);
	} else {
		rv = crypto_put_output_data(ctx->gcm_pt_buf, out, pt_len);
		if (rv != CRYPTO_SUCCESS)
			return (rv);
		out->cd_offset += pt_len;
	}
	return (CRYPTO_SUCCESS);
}

static int
gcm_validate_args(CK_AES_GCM_PARAMS *gcm_param)
{
	size_t tag_len;

	/*
	 * Check the length of the authentication tag (in bits).
	 */
	tag_len = gcm_param->ulTagBits;
	switch (tag_len) {
	case 32:
	case 64:
	case 96:
	case 104:
	case 112:
	case 120:
	case 128:
		break;
	default:
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

	if (gcm_param->ulIvLen == 0)
		return (CRYPTO_MECHANISM_PARAM_INVALID);

	return (CRYPTO_SUCCESS);
}

extern void
gcm_format_initial_blocks(const uint8_t *iv, ulong_t iv_len,
    gcm_ctx_t *ctx, size_t block_size,
    void (*copy_block)(uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	const gcm_impl_ops_t *gops;
	uint8_t *cb;
	ulong_t remainder = iv_len;
	ulong_t processed = 0;
	uint8_t *datap, *ghash;
	uint64_t len_a_len_c[2];

	gops = gcm_impl_get_ops();
	ghash = (uint8_t *)ctx->gcm_ghash;
	cb = (uint8_t *)ctx->gcm_cb;
	if (iv_len == 12) {
		memcpy(cb, iv, 12);
		cb[12] = 0;
		cb[13] = 0;
		cb[14] = 0;
		cb[15] = 1;
		/* J0 will be used again in the final */
		copy_block(cb, (uint8_t *)ctx->gcm_J0);
	} else {
		/* GHASH the IV */
		do {
			if (remainder < block_size) {
				memset(cb, 0, block_size);
				memcpy(cb, &(iv[processed]), remainder);
				datap = (uint8_t *)cb;
				remainder = 0;
			} else {
				datap = (uint8_t *)(&(iv[processed]));
				processed += block_size;
				remainder -= block_size;
			}
			GHASH(ctx, datap, ghash, gops);
		} while (remainder > 0);

		len_a_len_c[0] = 0;
		len_a_len_c[1] = htonll(CRYPTO_BYTES2BITS(iv_len));
		GHASH(ctx, len_a_len_c, ctx->gcm_J0, gops);

		/* J0 will be used again in the final */
		copy_block((uint8_t *)ctx->gcm_J0, (uint8_t *)cb);
	}
}

static int
gcm_init(gcm_ctx_t *ctx, const uint8_t *iv, size_t iv_len,
    const uint8_t *auth_data, size_t auth_data_len, size_t block_size,
    int (*encrypt_block)(const void *, const uint8_t *, uint8_t *),
    void (*copy_block)(uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	const gcm_impl_ops_t *gops;
	uint8_t *ghash, *datap, *authp;
	size_t remainder, processed;

	/* encrypt zero block to get subkey H */
	memset(ctx->gcm_H, 0, sizeof (ctx->gcm_H));
	encrypt_block(ctx->gcm_keysched, (uint8_t *)ctx->gcm_H,
	    (uint8_t *)ctx->gcm_H);

	gcm_format_initial_blocks(iv, iv_len, ctx, block_size,
	    copy_block, xor_block);

	gops = gcm_impl_get_ops();
	authp = (uint8_t *)ctx->gcm_tmp;
	ghash = (uint8_t *)ctx->gcm_ghash;
	memset(authp, 0, block_size);
	memset(ghash, 0, block_size);

	processed = 0;
	remainder = auth_data_len;
	do {
		if (remainder < block_size) {
			/*
			 * There's not a block full of data, pad rest of
			 * buffer with zero
			 */

			if (auth_data != NULL) {
				memset(authp, 0, block_size);
				memcpy(authp, &(auth_data[processed]),
				    remainder);
			} else {
				ASSERT0(remainder);
			}

			datap = (uint8_t *)authp;
			remainder = 0;
		} else {
			datap = (uint8_t *)(&(auth_data[processed]));
			processed += block_size;
			remainder -= block_size;
		}

		/* add auth data to the hash */
		GHASH(ctx, datap, ghash, gops);

	} while (remainder > 0);

	return (CRYPTO_SUCCESS);
}

/*
 * Init the GCM context struct. Handle the cycle and avx implementations here.
 */
int
gcm_init_ctx(gcm_ctx_t *gcm_ctx, char *param,
    size_t block_size, int (*encrypt_block)(const void *, const uint8_t *,
    uint8_t *), void (*copy_block)(uint8_t *, uint8_t *),
    void (*xor_block)(uint8_t *, uint8_t *))
{
	CK_AES_GCM_PARAMS *gcm_param;
	int rv = CRYPTO_SUCCESS;
	size_t tag_len, iv_len;

	if (param != NULL) {
		gcm_param = (CK_AES_GCM_PARAMS *)(void *)param;

		/* GCM mode. */
		if ((rv = gcm_validate_args(gcm_param)) != 0) {
			return (rv);
		}
		gcm_ctx->gcm_flags |= GCM_MODE;

		size_t tbits = gcm_param->ulTagBits;
		tag_len = CRYPTO_BITS2BYTES(tbits);
		iv_len = gcm_param->ulIvLen;

		gcm_ctx->gcm_tag_len = tag_len;
		gcm_ctx->gcm_processed_data_len = 0;

		/* these values are in bits */
		gcm_ctx->gcm_len_a_len_c[0]
		    = htonll(CRYPTO_BYTES2BITS(gcm_param->ulAADLen));
	} else {
		return (CRYPTO_MECHANISM_PARAM_INVALID);
	}

	const uint8_t *iv = (const uint8_t *)gcm_param->pIv;
	const uint8_t *aad = (const uint8_t *)gcm_param->pAAD;
	size_t aad_len = gcm_param->ulAADLen;

#ifdef CAN_USE_GCM_SIMD
	/*
	 * Figure out which implementation to use.
	 */
	uint32_t impl = GCM_IMPL_READ(icp_gcm_impl);
	boolean_t needs_bswap =
	    ((aes_key_t *)gcm_ctx->gcm_keysched)->ops->needs_byteswap;

	ASSERT3U(gcm_supp_impl_cnt, >, 0);

	if (impl == IMPL_FASTEST) {
		gcm_ctx->gcm_simd_impl = gcm_fastest_impl.simd_impl;
	} else if (impl == IMPL_CYCLE) {
		/*
		 * Handle the "cycle" implementation by using each
		 * available implementation in a round robin fashion.
		 */
		uint32_t cc = atomic_add_32_nv(
		    (volatile uint32_t *)&gcm_impl_cycle_cnt, 1);

		impl = cc % gcm_supp_impl_cnt;

		ASSERT3U(impl, <, gcm_supp_impl_cnt);
		ASSERT3U(impl, <, ARRAY_SIZE(gcm_all_impl));

		gcm_ctx->gcm_simd_impl = gcm_supp_impl[impl]->simd_impl;

		/* The avx impl. doesn't handle byte swapped key schedules. */
		if (gcm_ctx->gcm_simd_impl != ZFS_GSO_NOSIMD &&
		    needs_bswap == B_TRUE) {
			gcm_ctx->gcm_simd_impl = ZFS_GSO_NOSIMD;
		}
		/*
		 * If this is a GCM context, use the MOVBE and the BSWAP
		 * variants alternately.
		 */
		if (gcm_ctx->gcm_simd_impl == ZFS_GSO_AVX_AESNI_X64 &&
		    zfs_movbe_available() == B_TRUE) {
			(void) atomic_toggle_boolean_nv(
			    (volatile boolean_t *)&gcm_avx_can_use_movbe);
		}
	} else {
		ASSERT3U(impl, <, gcm_supp_impl_cnt);
		ASSERT3U(impl, <, ARRAY_SIZE(gcm_all_impl));

		gcm_ctx->gcm_simd_impl = gcm_supp_impl[impl]->simd_impl;
	}

	/*
	 * We don't handle byte swapped key schedules in the avx code path,
	 * still they could be created by the aes generic implementation.
	 * Make sure not to use them since we'll corrupt data if we do.
	 */
	if (gcm_ctx->gcm_simd_impl != ZFS_GSO_NOSIMD && needs_bswap == B_TRUE) {
		gcm_ctx->gcm_simd_impl = ZFS_GSO_NOSIMD;

		cmn_err_once(CE_WARN,
		    "ICP: Can't use the aes generic or cycle implementations "
		    "in combination with the gcm avx implementation!");
		cmn_err_once(CE_WARN,
		    "ICP: Falling back to a compatible implementation, "
		    "aes-gcm performance will likely be degraded.");
		cmn_err_once(CE_WARN,
		    "ICP: Choose at least the x86_64 aes implementation to "
		    "restore performance.");
	}
#endif /* ifdef CAN_USE_GCM_SIMD */

#if !defined(CAN_USE_GCM_SIMD)
	if (gcm_init(gcm_ctx, iv, iv_len, aad, aad_len, block_size,
	    encrypt_block, copy_block, xor_block) != CRYPTO_SUCCESS) {
		rv = CRYPTO_MECHANISM_PARAM_INVALID;
	}
#else
	if (gcm_ctx->gcm_simd_impl == ZFS_GSO_NOSIMD) {
		if (gcm_init(gcm_ctx, iv, iv_len, aad, aad_len, block_size,
		    encrypt_block, copy_block, xor_block) != CRYPTO_SUCCESS) {
			rv = CRYPTO_MECHANISM_PARAM_INVALID;
		}
	} else {
		if (gcm_init_simd(gcm_ctx, iv, iv_len, aad, aad_len) !=
		    CRYPTO_SUCCESS) {
			rv = CRYPTO_MECHANISM_PARAM_INVALID;
		}
	}
#endif /* if !defined(CAN_USE_GCM_SIMD) */

	return (rv);
}

void *
gcm_alloc_ctx(int kmflag)
{
	gcm_ctx_t *gcm_ctx;

	if ((gcm_ctx = kmem_zalloc(sizeof (gcm_ctx_t), kmflag)) == NULL)
		return (NULL);

	gcm_ctx->gcm_flags = GCM_MODE;
	return (gcm_ctx);
}


/* Indicate that benchmark has been completed */
static boolean_t gcm_impl_initialized = B_FALSE;

/*
 * Returns the GCM operations for encrypt/decrypt/key setup.  When a
 * SIMD implementation is not allowed in the current context, then
 * fallback to the fastest generic implementation.
 */
const gcm_impl_ops_t *
gcm_impl_get_ops(void)
{
	if (!kfpu_allowed())
		return (&gcm_generic_impl);

	const gcm_impl_ops_t *ops = NULL;
	const uint32_t impl = GCM_IMPL_READ(icp_gcm_impl);

	switch (impl) {
	case IMPL_FASTEST:
		ASSERT(gcm_impl_initialized);
		ops = &gcm_fastest_impl;
		break;
	case IMPL_CYCLE:
		/* Cycle through supported implementations */
		ASSERT(gcm_impl_initialized);
		ASSERT3U(gcm_supp_impl_cnt, >, 0);
		static size_t cycle_impl_idx = 0;
		size_t idx = (++cycle_impl_idx) % 2; /* XXXX  */
		ops = gcm_supp_impl[idx];
		break;
	default:
		ASSERT3U(impl, <, gcm_supp_impl_cnt);
		ASSERT3U(gcm_supp_impl_cnt, >, 0);
		if (impl < ARRAY_SIZE(gcm_all_impl))
			ops = gcm_supp_impl[impl];

#ifdef CAN_USE_GCM_SIMD
		/*
		 * Make sure that we return a valid implementation while
		 * switching to the avx implementation since there still
		 * may be unfinished non-avx contexts around.
		 */
		ASSERT3P(ops, !=, NULL);
		if (ops->simd_impl != ZFS_GSO_NOSIMD)
			ops = &gcm_generic_impl;
#endif
		break;
	}

	ASSERT3P(ops, !=, NULL);

	return (ops);
}

/*
 * Initialize all supported implementations.
 */
void
gcm_impl_init(void)
{
	gcm_impl_ops_t *curr_impl;
	int i, c;

	/* Move supported implementations into gcm_supp_impls. */
	for (i = 0, c = 0; i < ARRAY_SIZE(gcm_all_impl); i++) {
		curr_impl = (gcm_impl_ops_t *)gcm_all_impl[i];

		if (curr_impl->is_supported()) {
			gcm_supp_impl[c++] = (gcm_impl_ops_t *)curr_impl;
		}
	}
	gcm_supp_impl_cnt = c;

	/*
	 * Right now the fastest implementation is hard coded.
	 * TODO: Benchmark impls; adjust chunk_size to 5us - 10us
	 */
#ifdef CAN_USE_GCM_SIMD_AVX_AESNI_X86
	if (gcm_avx_aesni_impl.is_supported() == B_TRUE) {
		gcm_avx_aesni_impl.is_fastest = B_TRUE;
		memcpy(&gcm_fastest_impl, &gcm_avx_aesni_impl,
		    sizeof (gcm_fastest_impl));

		goto found;
	}
#endif
#if defined(__x86_64) && defined(HAVE_PCLMULQDQ)
	if (gcm_pclmulqdq_impl.is_supported() == B_TRUE) {
		gcm_pclmulqdq_impl.is_fastest = B_TRUE;
		memcpy(&gcm_fastest_impl, &gcm_pclmulqdq_impl,
		    sizeof (gcm_fastest_impl));

		goto found;
	}
#endif
	memcpy(&gcm_fastest_impl, &gcm_generic_impl, sizeof (gcm_fastest_impl));

found:
	strlcpy(gcm_fastest_impl.name, "fastest", GCM_IMPL_NAME_MAX);

#if defined(CAN_USE_GCM_SIMD_AVX_AESNI_X86) && defined(HAVE_MOVBE)
	if (zfs_movbe_available() == B_TRUE) {
		(void) atomic_swap_32(&gcm_avx_can_use_movbe, B_TRUE);
	}
#endif
	/* Finish initialization */
	(void) atomic_swap_32(&icp_gcm_impl, user_sel_impl);
	gcm_impl_initialized = B_TRUE;
}

static const struct {
	const char *name;
	uint32_t sel;
} gcm_impl_opts[] = {
		{ "cycle",	IMPL_CYCLE },
		{ "fastest",	IMPL_FASTEST },
};

/*
 * Function sets desired gcm implementation.
 *
 * If we are called before init(), user preference will be saved in
 * user_sel_impl, and applied in later init() call. This occurs when module
 * parameter is specified on module load. Otherwise, directly update
 * icp_gcm_impl.
 *
 * @val		Name of gcm implementation to use
 * @param	Unused.
 */
int
gcm_impl_set(const char *val)
{
	int err = -EINVAL;
	char req_name[GCM_IMPL_NAME_MAX];
	uint32_t impl = GCM_IMPL_READ(user_sel_impl);
	size_t i;

	/* sanitize input */
	i = strnlen(val, GCM_IMPL_NAME_MAX);
	if (i == 0 || i >= GCM_IMPL_NAME_MAX)
		return (err);

	strlcpy(req_name, val, GCM_IMPL_NAME_MAX);
	while (i > 0 && isspace(req_name[i-1]))
		i--;
	req_name[i] = '\0';

	/* Check mandatory options */
	for (i = 0; i < ARRAY_SIZE(gcm_impl_opts); i++) {
		if (strcmp(req_name, gcm_impl_opts[i].name) == 0) {
			impl = gcm_impl_opts[i].sel;
			err = 0;
			break;
		}
	}

	/* check all supported impl if init() was already called */
	if (err != 0 && gcm_impl_initialized) {
		/* check all supported implementations */
		for (i = 0; i < gcm_supp_impl_cnt; i++) {
			if (strcmp(req_name, gcm_supp_impl[i]->name) == 0) {
				impl = i;
				err = 0;
				break;
			}
		}
	}
	if (err == 0) {
		if (gcm_impl_initialized)
			atomic_swap_32(&icp_gcm_impl, impl);
		else
			atomic_swap_32(&user_sel_impl, impl);
	}

	return (err);
}

#if defined(_KERNEL) && defined(__linux__)

static int
icp_gcm_impl_set(const char *val, zfs_kernel_param_t *kp)
{
	return (gcm_impl_set(val));
}

static int
icp_gcm_impl_get(char *buffer, zfs_kernel_param_t *kp)
{
	int i, cnt = 0;
	char *fmt;
	const uint32_t impl = GCM_IMPL_READ(icp_gcm_impl);

	ASSERT(gcm_impl_initialized);

	/* List mandatory options. */
	for (i = 0; i < ARRAY_SIZE(gcm_impl_opts); i++) {
		fmt = (impl == gcm_impl_opts[i].sel) ? "[%s] " : "%s ";
		cnt += kmem_scnprintf(buffer + cnt, PAGE_SIZE - cnt, fmt,
		    gcm_impl_opts[i].name);
	}

	/*
	 * List all supported implementations. The selected implementation is
	 * enclosed in square brackets, and the fastest implementation gets an
	 * asterisk appended.
	 */
	for (i = 0; i < gcm_supp_impl_cnt; i++) {
		if (i == impl && gcm_supp_impl[i]->is_fastest)
			fmt = "[%s*] ";
		else if (i == impl && !gcm_supp_impl[i]->is_fastest)
			fmt = "[%s] ";
		else if (gcm_supp_impl[i]->is_fastest)
			fmt = "%s* ";
		else
			fmt = "%s ";

		cnt += kmem_scnprintf(buffer + cnt, PAGE_SIZE - cnt, fmt,
		    gcm_supp_impl[i]->name);
	}

	return (cnt);
}

module_param_call(icp_gcm_impl, icp_gcm_impl_set, icp_gcm_impl_get,
    NULL, 0644);
MODULE_PARM_DESC(icp_gcm_impl, "Select gcm implementation.");
#endif /* defined(__KERNEL) */

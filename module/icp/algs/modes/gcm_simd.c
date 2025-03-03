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
 * Copyright (c) 2025 Attila Fülöp <attila@fueloep.net>
 */

#include <modes/gcm_impl.h>
#if defined(CAN_USE_GCM_SIMD)

#include <sys/zfs_context.h>
#include <sys/crypto/impl.h>
#include <aes/aes_impl.h>
#include <modes/modes.h>
#include <sys/simd.h>
#include <modes/gcm_simd.h>
#include <modes/gcm_simd_impl.h>
#include <sys/cmn_err.h>



static inline void gcm_incr_counter_block_by(gcm_ctx_t *ctx, int n);
#define	gcm_incr_counter_block(ctx) gcm_incr_counter_block_by(ctx, 1)

/*
 * Encrypt multiple blocks of data in GCM mode using a SIMD implementation.
 * This is done in gcm_simd_chunk_size chunks to reduce the kfpu_{begin,end}()
 * overhead. While processing a chunk the FPU is "locked".
 */
int
gcm_mode_encrypt_contiguous_blocks_simd(gcm_ctx_t *ctx, char *data,
    size_t length, crypto_data_t *out)
{
	const gcm_simd_ops_t *ops = gcm_simd_ops[ctx->gcm_simd_impl];
	ASSERT3P(ops, !=, NULL);
	const size_t chunk_size = ops->chunk_size;
	const aes_key_t *key = ((aes_key_t *)ctx->gcm_keysched);

	size_t bleft = length;
	size_t need = 0;
	size_t done = 0;
	uint8_t *datap = (uint8_t *)data;
	uint8_t *ct_buf = NULL;
	int rv = CRYPTO_SUCCESS;

	ASSERT3B(key->ops->needs_byteswap, ==, B_FALSE);

	/*
	 * If the last call left an incomplete block, try to fill
	 * it first.
	 */
	if (ctx->gcm_remainder_len > 0) {
		uint8_t *remainder = (uint8_t*)ctx->gcm_remainder;
		need = GCM_BLOCK_LEN - ctx->gcm_remainder_len;

		if (length < need) {
			/* Accumulate bytes here and return. */
			memcpy(remainder + ctx->gcm_remainder_len,
			    datap, length);
			ctx->gcm_remainder_len += length;
			if (ctx->gcm_copy_to == NULL) {
				ctx->gcm_copy_to = datap;
			}
			return (CRYPTO_SUCCESS);
		} else {
			/* Complete incomplete block. */
			memcpy(remainder + ctx->gcm_remainder_len, datap, need);
			ctx->gcm_copy_to = NULL;
		}
		/* We completed an incomplete block, encrypt and write it out.
		 * Use the SIMD implementation if it can encrypt a single block.
		 * Otherwise we have to roll our own.
		 */
		uint8_t *tmp = (uint8_t *) ctx->gcm_tmp;

		kfpu_begin();
		if (ops->enc_min_block_size <= GCM_BLOCK_LEN) {
			done = (*ops->encrypt)(
			    ctx, tmp, remainder, GCM_BLOCK_LEN);

			if (done != GCM_BLOCK_LEN) {
				rv = CRYPTO_FAILED;
				goto out;
			}
		} else {
			const uint32_t *ks32 = key->encr_ks.ks32;
			const int nr = key->nr;
			const uint32_t *cb = (uint32_t *)ctx->gcm_cb;
			const uint64_t *Htab = ctx->gcm_Htable;
			uint64_t *ghash = ctx->gcm_ghash;

			(*ops->aes_encrypt_block)(ks32, nr, cb,
			    (uint32_t *)tmp);
			aes_xor_block(remainder, tmp);
			(*ops->ghash)(ghash, Htab, tmp, GCM_BLOCK_LEN);
			gcm_incr_counter_block(ctx);
		}
		(ops->clear_fpu_regs)();
		kfpu_end();

		/* Output ciphertext and update state. */
		rv = crypto_put_output_data(tmp, out, GCM_BLOCK_LEN);
		out->cd_offset += GCM_BLOCK_LEN;
		ctx->gcm_processed_data_len += GCM_BLOCK_LEN;
		bleft -= need;
		datap += need;
		ctx->gcm_remainder_len = 0;
	}

	/* Allocate a buffer to encrypt to if there is enough input. */
	if (bleft >= GCM_BLOCK_LEN) {
		ct_buf = vmem_alloc(chunk_size, KM_SLEEP);
	}
	/* Do the bulk encryption in chunk_size blocks. */
	ASSERT0(chunk_size % ops->dec_min_block_size);
	for (; bleft >= chunk_size; bleft -= chunk_size) {
		kfpu_begin();
		done = (*ops->encrypt)(ctx, ct_buf, datap, chunk_size);
		(*ops->clear_fpu_regs)();
		kfpu_end();
		if (done != chunk_size) {
			rv = CRYPTO_FAILED;
			goto out_nofpu;
		}
		rv = crypto_put_output_data(ct_buf, out, chunk_size);
		if (rv != CRYPTO_SUCCESS) {
			goto out_nofpu;
		}
		out->cd_offset += chunk_size;
		datap += chunk_size;
		ctx->gcm_processed_data_len += chunk_size;
	}
	/* Check if we are already done. */
	if (bleft == 0) {
		goto out_nofpu;
	}
	/* Stash away an incomplete block. */
	if (bleft < GCM_BLOCK_LEN) {
		memcpy(ctx->gcm_remainder, datap, bleft);
		ctx->gcm_remainder_len = bleft;
		ctx->gcm_copy_to = datap;
		goto out_nofpu;
	}

	/* Bulk encrypt the remaining data, use SIMD if possible. */
	ASSERT3P(ct_buf, !=, NULL);
	kfpu_begin();

	if (ops->enc_min_block_size <= bleft) {
		done = (*ops->encrypt)(ctx, ct_buf, datap, bleft);
		rv = crypto_put_output_data(ct_buf, out, done);
		if (rv != CRYPTO_SUCCESS) {
			goto out;
		}
		out->cd_offset += done;
		datap += done;
		ctx->gcm_processed_data_len += done;
		bleft -= done;
	}
	/*
	 * What's left is to small to be encrypted by the SIMD routines,
	 * Roll our own and stash away a potential incomplete block.
	 */
	const uint32_t *ks32 = key->encr_ks.ks32;
	const int nr = key->nr;
	const uint32_t *cb = (uint32_t *)ctx->gcm_cb;
	const uint64_t *Htab = ctx->gcm_Htable;
	uint64_t *ghash = ctx->gcm_ghash;
	uint8_t *tmp = (uint8_t *)ctx->gcm_tmp;

	while (bleft > 0) {
		if (bleft < GCM_BLOCK_LEN) {
			memcpy(ctx->gcm_remainder, datap, bleft);
			ctx->gcm_remainder_len = bleft;
			ctx->gcm_copy_to = datap;
			goto out;
		}
		/* Encrypt, hash and write out. */
		(*ops->aes_encrypt_block)(ks32, nr, cb, (uint32_t*)tmp);
		aes_xor_block(datap, tmp);
		(*ops->ghash)(ghash, Htab, tmp, GCM_BLOCK_LEN);

		rv = crypto_put_output_data(tmp, out, GCM_BLOCK_LEN);
		if (rv != CRYPTO_SUCCESS) {
			goto out;
		}
		out->cd_offset += GCM_BLOCK_LEN;
		gcm_incr_counter_block(ctx);
		ctx->gcm_processed_data_len += GCM_BLOCK_LEN;
		datap += GCM_BLOCK_LEN;
		bleft -= GCM_BLOCK_LEN;
	}
out:
	(*ops->clear_fpu_regs)();
	kfpu_end();
out_nofpu:
	if (ct_buf != NULL) {
		vmem_free(ct_buf, chunk_size);
	}
	return (rv);
}

/*
 * Decrypt multiple blocks of data in GCM mode.  Note that we are not decrypting
 * at all but just collecting ciphertext in a buffer.
 *
 * XXXX We could use gcm_mode_decrypt_contiguous_blocks_simd() directly but it
 * seems cleaner XXXXXX to have a copy here.
 */
int
gcm_mode_decrypt_contiguous_blocks_simd(
    gcm_ctx_t *ctx, char *data, size_t length)
{
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

/*
 * Finalize the encryption: Zero fill, encrypt, hash and write out an eventual
 * incomplete last block. Encrypt the ICB. Calculate the tag and write it out.
 */
int
gcm_encrypt_final_simd(gcm_ctx_t *ctx, crypto_data_t *out)
{
	const gcm_simd_ops_t *ops = gcm_simd_ops[ctx->gcm_simd_impl];
	const aes_key_t *key = ctx->gcm_keysched;
	const uint32_t *ks32 = key->encr_ks.ks32;
	const int nr = key->nr;
	const uint64_t *Htab = ctx->gcm_Htable;
	uint64_t *ghash = ctx->gcm_ghash;
	uint32_t *J0 = (uint32_t *)ctx->gcm_J0;
	uint8_t *remainder = (uint8_t *)ctx->gcm_remainder;
	size_t rem_len = ctx->gcm_remainder_len;
	size_t done;
	int rv;

	ASSERT3B(key->ops->needs_byteswap, ==, B_FALSE);

	if (out->cd_length < (rem_len + ctx->gcm_tag_len)) {
		return (CRYPTO_DATA_LEN_RANGE);
	}

	kfpu_begin();
	/* Pad last incomplete block with zeros, encrypt and hash. */
	if (rem_len > 0) {
		uint8_t *tmp = (uint8_t *)ctx->gcm_tmp;
		const uint32_t *cb = (uint32_t *)ctx->gcm_cb;

		memset(remainder + rem_len, 0, GCM_BLOCK_LEN - rem_len);

		/*
		 * Encrypt and hash in one go if we can, roll our own otherwise.
		 */
		if (ops->enc_min_block_size <= rem_len) {
			done = (*ops->encrypt)(
			    ctx, remainder, remainder, rem_len);

			ASSERT3U(done, ==, rem_len);
		} else {
			(*ops->aes_encrypt_block)(ks32, nr, cb,
			    (uint32_t *)tmp);

			for (int i = 0; i < rem_len; i++) {
				remainder[i] ^= tmp[i];
			}
			(*ops->ghash)(
			    ghash, Htab, remainder, GCM_BLOCK_LEN);
			/*
			 * No need to increment counter_block,
			 * this is the last block.
			 */
		}
		ctx->gcm_processed_data_len += rem_len;
	}
	/* Finish tag. */
	if (*ops->encrypt_final != NULL) {
		(*ops->encrypt_final)(ctx);
	} else {
		ctx->gcm_len_a_len_c[1] =
		    htonll(CRYPTO_BYTES2BITS(ctx->gcm_processed_data_len));

		(*ops->ghash)(ghash, Htab,
		    (const uint8_t *)ctx->gcm_len_a_len_c, GCM_BLOCK_LEN);

		(*ops->aes_encrypt_block)(key->encr_ks.ks32, key->nr,
		    J0, J0);

		aes_xor_block((uint8_t *)J0, (uint8_t *)ghash);
	}
	(*ops->clear_fpu_regs)();
	kfpu_end();

	/* Output remainder and authentication tag. */
	if (rem_len > 0) {
		rv = crypto_put_output_data(remainder, out, rem_len);
		if (rv != CRYPTO_SUCCESS) {
			return (rv);
		}
		out->cd_offset += rem_len;
		ctx->gcm_remainder_len = 0;
	}
	rv = crypto_put_output_data((uint8_t *)ghash, out, ctx->gcm_tag_len);
	if (rv != CRYPTO_SUCCESS) {
		return (rv);
	}
	out->cd_offset += ctx->gcm_tag_len;
	return (CRYPTO_SUCCESS);
}

/*
 * Finalize decryption: We just have accumulated crypto text, so now we
 * decrypt it here in-place.
 */
int
gcm_decrypt_final_simd(gcm_ctx_t *ctx, crypto_data_t *out)
{
	const gcm_simd_ops_t *ops = gcm_simd_ops[ctx->gcm_simd_impl];
	ASSERT3P(ops, !=, NULL);
	const size_t chunk_size = ops->chunk_size;
	const aes_key_t *key = ((aes_key_t *)ctx->gcm_keysched);

	size_t pt_len = ctx->gcm_processed_data_len - ctx->gcm_tag_len;
	uint8_t *datap = ctx->gcm_pt_buf;
	size_t bleft, done;

	ASSERT3U(ctx->gcm_processed_data_len, ==, ctx->gcm_pt_buf_len);
	ASSERT3B(key->ops->needs_byteswap, ==, B_FALSE);
	ASSERT3S(ops->impl, !=, ZFS_GSO_NOSIMD);

	/* Do the bulk decryption in chunk_size blocks. */
	ASSERT0(chunk_size % ops->dec_min_block_size);
	for (bleft = pt_len; bleft >= chunk_size; bleft -= chunk_size) {
		kfpu_begin();
		done = (*ops->decrypt)(ctx, datap, datap, chunk_size);
		(*ops->clear_fpu_regs)();
		kfpu_end();
		if (done != chunk_size) {
			return (CRYPTO_FAILED);
		}
		datap += done;
	}

	/* Encrypt the remaining data, use SIMD if possible. */
	kfpu_begin();
	if (bleft >= ops->dec_min_block_size) {
		done = (*ops->decrypt)(ctx, datap, datap, bleft);
		datap += done;
		bleft -= done;
	}
	ASSERT3U(bleft, <, ops->dec_min_block_size);

	/* Process any blocks left by rolling our own. */
	const uint32_t *ks32 = key->encr_ks.ks32;
	const int nr = key->nr;
	const uint64_t * Htab = ctx->gcm_Htable;
	uint64_t *ghash = ctx->gcm_ghash;
	uint32_t *cb = (uint32_t *)ctx->gcm_cb;
	uint32_t *tmp = (uint32_t *)ctx->gcm_tmp;

	while (bleft > 0) {
		/*
		 * If we have an incomplete last block, zero pad it
		 * to GCM_BLOCK_LEN, process the block and end the loop.
		 */
		if (bleft < GCM_BLOCK_LEN) {
			uint8_t *lastb = (uint8_t *)ctx->gcm_remainder;

			memset(lastb, 0, GCM_BLOCK_LEN);
			memcpy(lastb, datap, bleft);
			/* The GCM processing. */
			(*ops->ghash)(ghash, Htab, lastb, GCM_BLOCK_LEN);
			(*ops->aes_encrypt_block)(ks32, nr, cb, tmp);

			for (size_t i = 0; i < bleft; i++) { // XXXX bleft ?
				datap[i] = lastb[i] ^ ((uint8_t *)tmp)[i];
			}
			bleft = 0;
			break;
		}
		(*ops->ghash)(ghash, Htab, datap, GCM_BLOCK_LEN);
		(*ops->aes_encrypt_block)(ks32, nr, cb, tmp);

		aes_xor_block((uint8_t *)tmp, datap);
		gcm_incr_counter_block(ctx);
		datap += GCM_BLOCK_LEN;
		bleft -= GCM_BLOCK_LEN;
	}
	ASSERT3U(bleft, ==, 0);

	/* Decryption done, finish the tag. */
	uint32_t *J0 = (uint32_t *)ctx->gcm_J0;

	if (ops->decrypt_final != NULL) {
		(*ops->decrypt_final)(ctx);
	} else {
		ctx->gcm_len_a_len_c[1] = htonll(CRYPTO_BYTES2BITS(pt_len));
		(*ops->ghash)(ghash, Htab,
		    (uint8_t *)ctx->gcm_len_a_len_c, GCM_BLOCK_LEN);

		(*ops->aes_encrypt_block)(ks32, nr, J0, J0);
		aes_xor_block((uint8_t*)J0, (uint8_t *)ghash);
	}
	/* We are done with the FPU, restore its state. */
	(*ops->clear_fpu_regs)();
	kfpu_end();

	int rv2 = CRYPTO_SUCCESS;

	/* Compare the input authentication tag with what we calculated. */
	if (memcmp(&ctx->gcm_pt_buf[pt_len], ghash, ctx->gcm_tag_len)) {
		/* They don't match. */
		rv2 = CRYPTO_INVALID_MAC;
#if !defined(DEBUG_ICP_GCM) || defined(_KERNEL)
		/*
		 * Output plain text which failed tag validation only if
		 * we are in debug mode and in user space.
		 */
		return (rv2);
#endif
	}
	int rv = crypto_put_output_data(ctx->gcm_pt_buf, out, pt_len);
	if (rv != CRYPTO_SUCCESS) {
		return (rv);
	}
	out->cd_offset += pt_len;
	return (rv2);
}

/*
 * Initialize the GCM params H, Htabtle and the counter block. Save the
 * initial counter block.
 */
int
gcm_init_simd(gcm_ctx_t *ctx, const uint8_t *iv, size_t iv_len,
    const uint8_t *auth_data, size_t auth_data_len)
{
	const gcm_simd_ops_t *ops = gcm_simd_ops[ctx->gcm_simd_impl];
	const size_t chunk_size = ops->chunk_size;
	const aes_key_t *key = ((aes_key_t *)ctx->gcm_keysched);

	ASSERT3B(key->ops->needs_byteswap, ==, B_FALSE);

	/* Some asm impl. only support 12 byte IVs */
	if (iv_len != 12 && ops->only_12bytes_iv == B_TRUE) {
		cmn_err_once(CE_WARN,
		    "ICP: The %s gcm SIMD implementation handles "
		    "12 byte initialization vectors only.", ops->name);
		cmn_err_once(CE_WARN, "ICP: You requested %zu bytes.", iv_len);

		return (CRYPTO_NOT_SUPPORTED);
	}

	/* Allocate table of pre-computed hashes of H */
	ctx->gcm_Htable = kmem_alloc(ops->Htab_size, KM_SLEEP);

	/* Use the assembly init routine if there is one. */
	if (ops->init != NULL) {
		kfpu_begin();
		(*ops->init)(ctx, iv, auth_data, iv_len, auth_data_len);
		(*ops->clear_fpu_regs)();
		kfpu_end();
		/*
		 * Some implementations post increment the counter,
		 * adjust for that.
		 */
		if (ops->pre_inc_cntr == B_TRUE) {
			gcm_incr_counter_block(ctx);
		}
		return (CRYPTO_SUCCESS);
	}

	/* We have to init the context on our own */
	const void *ks32 = key->encr_ks.ks32;
	const int nr = key->nr;
	const uint8_t *datap = auth_data;
	uint8_t *cb = (uint8_t *)ctx->gcm_cb;
	uint64_t *H = ctx->gcm_H;
	size_t bleft;

	/* Init H (encrypt zero block) and create the initial counter block. */
	/* memset(H, 0, sizeof (ctx->gcm_H)); XXX we zalloc the ctx */
	kfpu_begin();
	(*ops->aes_encrypt_block)(ks32, nr, (const uint32_t *)H, (uint32_t *)H);
	(*ops->init_Htab)(ctx);

	if (iv_len == 12) {
		memcpy(cb, iv, 12);
		cb[12] = 0;
		cb[13] = 0;
		cb[14] = 0;
		cb[15] = 1;
		/* We need the ICB later. */
		memcpy(ctx->gcm_J0, cb, sizeof (ctx->gcm_J0));
	} else {
		/*
		 * Most consumers use 12 byte IVs, so it's OK to use the
		 * original routines for other IV sizes, just avoid nesting
		 * kfpu_begin calls.
		 */
		(*ops->clear_fpu_regs)();
		kfpu_end();
		gcm_format_initial_blocks(iv, iv_len, ctx, GCM_BLOCK_LEN,
		    aes_copy_block, aes_xor_block);
		memset(ctx->gcm_ghash, 0, sizeof (ctx->gcm_ghash));
		kfpu_begin();
	}

	/* Ghash AAD in chunk_size blocks. */
	ASSERT0(chunk_size % ops->dec_min_block_size);
	for (bleft = auth_data_len; bleft >= chunk_size; bleft -= chunk_size) {
		(*ops->ghash)(
		    ctx->gcm_ghash, ctx->gcm_Htable, datap, chunk_size);

		datap += chunk_size;
		(*ops->clear_fpu_regs)();
		kfpu_end();
		kfpu_begin();
	}
	/* Ghash the remainder and handle possible incomplete GCM block. */
	if (bleft > 0) {
		size_t incomp = bleft % GCM_BLOCK_LEN;

		bleft -= incomp;
		if (bleft > 0) {
			(*ops->ghash)(
			    ctx->gcm_ghash, ctx->gcm_Htable, datap, bleft);

			datap += bleft;
		}
		if (incomp > 0) {
			/* Zero pad and hash incomplete last block. */
			uint8_t *authp = (uint8_t *)ctx->gcm_tmp;

			memset(authp, 0, GCM_BLOCK_LEN);
			memcpy(authp, datap, incomp);
			(*ops->ghash)(ctx->gcm_ghash, ctx->gcm_Htable,
			    authp, GCM_BLOCK_LEN);
		}
	}
	(*ops->clear_fpu_regs)();
	kfpu_end();
	if (ops->pre_inc_cntr == B_TRUE) {
		gcm_incr_counter_block(ctx);
	}
	return (CRYPTO_SUCCESS);
}


/* Increment the GCM counter block by n. */
static inline void
gcm_incr_counter_block_by(gcm_ctx_t *ctx, int n)
{
	uint64_t counter_mask = ntohll(0x00000000ffffffffULL);
	uint64_t counter = ntohll(ctx->gcm_cb[1] & counter_mask);

	counter = htonll(counter + n);
	counter &= counter_mask;
	ctx->gcm_cb[1] = (ctx->gcm_cb[1] & ~counter_mask) | counter;
}

#endif /* if defined(CAN_USE_GCM_SIMD) */

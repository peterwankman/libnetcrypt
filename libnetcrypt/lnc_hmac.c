/* 
 * libnetcrypt -- Encrypted communication with DH and AES
 * 
 * Copyright (C) 2013-2014  Martin Wolters
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to 
 * the Free Software Foundation, Inc.
 * 51 Franklin Street, Fifth Floor
 * Boston, MA  02110-1301, USA
 * 
 */

#include "../shared/mem.h"
#include "lnc.h"

uint8_t *lnc_hmac(const lnc_hashdef_t hdef, const uint8_t *key, const size_t klen, const uint8_t *msg, const size_t mlen, int *status) {
	uint8_t *ipad, *opad, *intkey, *buf;
	size_t hlen = hdef.blocksize;
	lnc_hash_t h;
	uint8_t *out = NULL;

	*status = LNC_ERR_MALLOC;

	if((ipad = malloc(hlen)) == NULL)
		return NULL;

	if((opad = malloc(hlen)) == NULL)
		goto freeipad; /* YAY! */

	if((intkey = malloc(hlen)) == NULL)
		goto freeopad;

	if((buf = malloc(hlen + mlen)) == NULL)
		goto freekey;

	if(klen > hlen) {
		h = hdef.hashfunc(key, klen, status);
		if(*status != LNC_OK)
			goto freebuf;
		memset(intkey, 0, hlen);
		memcpy(intkey, h.string, hdef.outsize);
		hdef.freefunc(&h);
	} else {
		memset(intkey, 0, hlen);
		memcpy(intkey, key, klen);
	}

	memset(ipad, 0x36, hlen);
	lnc_xor_block(ipad, intkey, hlen);
	
	memset(opad, 0x5c, hlen);
	lnc_xor_block(opad, intkey, hlen);

	memcpy(buf, ipad, hlen);
	memcpy(buf + hlen, msg, mlen);
	h = hdef.hashfunc(buf, hlen + mlen, status);
	free(buf);
	if(*status != LNC_OK)
		goto freekey;

	if((buf = malloc(hlen + hdef.outsize)) == NULL) {
		*status = LNC_ERR_MALLOC;
		goto freekey;
	}

	memcpy(buf, opad, hlen);
	memcpy(buf + hlen, h.string, hdef.outsize);

	hdef.freefunc(&h);

	h = hdef.hashfunc(buf, hlen + hdef.outsize, status);
	if(*status != LNC_OK) 
		goto freekey;

	if(out = malloc(hdef.outsize)) {
		memcpy(out, h.string, hdef.outsize);
	} else {
		out = NULL;
		*status = LNC_ERR_MALLOC;
	}

	hdef.freefunc(&h);

freebuf:
	free(buf);
freekey:
	free(intkey);
freeopad:
	free(opad);
freeipad:
	free(ipad);

	return out;
}

lnc_hmac_ctx_t *lnc_hmac_init(const lnc_hashdef_t hdef, const uint8_t *key, const size_t keylen, int *status) {
	lnc_hmac_ctx_t *out = malloc(sizeof(lnc_hmac_ctx_t));

	if(out == NULL) {
		*status = LNC_ERR_MALLOC;
		return NULL;
	}

	out->data = NULL;
	out->datalen = 0;

	if((out->key = malloc(keylen)) == NULL) {
		free(out);
		*status = LNC_ERR_MALLOC;
		return NULL;
	}

	memcpy(out->key, key, keylen);
	out->keylen = keylen;

	out->hashdef = hdef;

	*status = LNC_OK;

	return out;
}

void lnc_hmac_free(lnc_hmac_ctx_t *ctx) {
	if(ctx->data)
		free(ctx->data);
	if(ctx->key)
		free(ctx->key);
	free(ctx);
}

void lnc_hmac_update(lnc_hmac_ctx_t *ctx, const uint8_t *data, const size_t datalen, int *status) {
	size_t newlen = ctx->datalen + datalen;
	uint8_t *newdata;

	if((newdata = malloc(newlen)) == NULL) {
		*status = LNC_ERR_MALLOC;
		return;
	}

	if(ctx->datalen) {
		memcpy(newdata, ctx->data, ctx->datalen);
		free(ctx->data);
	}

	ctx->data = newdata;
	memcpy(ctx->data + ctx->datalen, data, datalen);
	ctx->datalen = newlen;

	*status = LNC_OK;
}

uint8_t *lnc_hmac_finalize(lnc_hmac_ctx_t *ctx, int *status) {
	uint8_t *ret = lnc_hmac(ctx->hashdef, ctx->key, ctx->keylen, ctx->data, ctx->datalen, status);

	if(*status == LNC_OK)
		lnc_hmac_free(ctx);
	return ret;
}

uint8_t *lnc_hkdf_extract(const lnc_hashdef_t hdef, const uint8_t *salt, const size_t saltlen, const uint8_t *ikm, const size_t ikmlen, int *status) {
	lnc_hmac_ctx_t *ctx;

	ctx = lnc_hmac_init(hdef, salt, saltlen, status);
	if(*status != LNC_OK)
		return NULL;
	lnc_hmac_update(ctx, ikm, ikmlen, status);
	if(*status != LNC_OK) {
		lnc_hmac_free(ctx);
		return NULL;
	}
	return lnc_hmac_finalize(ctx, status);
}

uint8_t *lnc_hkdf_expand(const lnc_hashdef_t hdef, const uint8_t *prk, const size_t prklen, const uint8_t *info, const size_t infolen, const size_t L, int *status) {
	size_t hashlen = hdef.outsize;
	size_t nblocks;
	size_t inputlen, outputlen, msglen, bytesleft = L;

	uint8_t currblock, N;
	uint8_t *T = NULL, *msg, *out;

	lnc_hmac_ctx_t *ctx;

	nblocks = L / hashlen + ((L % hashlen) ? 1 : 0);

	N = nblocks & 255;
	if(N > 255) {
		*status = LNC_ERR_OVER;
		return NULL;
	}

	if((out = malloc(L)) == NULL) {
		*status = LNC_ERR_MALLOC;
		return NULL;
	}

	if((msg = malloc(hashlen + infolen + 1)) == NULL) {
		free(out);
		*status = LNC_ERR_MALLOC;
		return NULL;
	}

	for(currblock = 1; currblock < N + 1; currblock++) {
		if(currblock == 1) {
			inputlen = 0;
		} else {
			inputlen = hashlen;
		}

		msglen = inputlen + infolen + 1;

		memcpy(msg, T, inputlen);
		memcpy(msg + inputlen, info, infolen);
		memcpy(msg + inputlen + infolen, &currblock, 1);
		free(T);

		ctx = lnc_hmac_init(hdef, prk, prklen, status);
		if(*status != LNC_OK) {
			free(out);
			free(msg);
			return NULL;
		}

		lnc_hmac_update(ctx, msg, msglen, status);

		if(*status != LNC_OK) {
			free(out);
			free(msg);
			return NULL;
		}

		T = lnc_hmac_finalize(ctx, status);
		if(*status != LNC_OK) {
			free(out);
			free(msg);
			return NULL;
		}

		outputlen = bytesleft >= hashlen ? hashlen : bytesleft;
		bytesleft -= outputlen;
		memcpy(out + hashlen * (currblock - 1), T, outputlen);
	}

	free(msg);
	free(T);

	return out;
}

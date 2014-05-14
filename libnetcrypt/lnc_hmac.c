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

typedef struct hkdftest {
	uint8_t ikm[1024];
	size_t ikmlen;

	uint8_t salt[1024];
	size_t saltlen;

	uint8_t info[1024];
	size_t infolen;

	size_t L;
} hkdftest_t;

void hkdftest(void) {
	size_t ntest, i;
	int status;

	hkdftest_t test[] = 
	{
		{ /* TEST 1 */
			{ /* IKM */
				0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,	0x0b, 0x0b,
				0x0b, 0x0b, 0x0b, 0x0b,	0x0b, 0x0b, 0x0b, 0x0b,
				0x0b, 0x0b,	0x0b, 0x0b, 0x0b, 0x0b
			}, 22,
			{ /* SALT */
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0a, 0x0b, 0x0c
			}, 13,
			{ /* INFO */
				0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
				0xf8, 0xf9
			}, 10,
			42 /* L */
		},
		{ /* TEST 1 */
			{ /* IKM */
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
				0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
				0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
				0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
				0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
				0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
			}, 80,
			{ /* SALT */
				0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
				0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
				0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
				0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
				0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
				0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
				0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
				0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
				0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
				0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf
			}, 80,
			{ /* INFO */
				0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 
				0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
				0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
				0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
				0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
				0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
				0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
				0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
				0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
				0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
			}, 80,
			82 /* L */
		},
		{ /* TEST 1 */
			{ /* IKM */
				0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
				0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
				0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
			}, 22,
			{ 0 }, 0, /* SALT */
			{ 0 }, 0, /* INFO */
			42 /* L */
		}
	};

	uint8_t *prk, *okm;

	for(ntest = 0; ntest < sizeof(test) / sizeof(hkdftest_t); ntest++) {
		prk = lnc_hkdf_extract(lnc_hash_sha256,
			test[ntest].salt, test[ntest].saltlen,
			test[ntest].ikm, test[ntest].ikmlen,
			&status);

		printf("test%d:\n prk =", ntest);
		for(i = 0; i < lnc_hash_sha256.outsize; i++) {
			if(!(i % 16))
				printf("\n  ");
			printf("%02x", prk[i]);
		}
		printf("\n");

		okm = lnc_hkdf_expand(lnc_hash_sha256, 
			prk, lnc_hash_sha256.outsize,
			test[ntest].info, test[ntest].infolen, test[ntest].L,
			&status);

		printf(" okm =");
		for(i = 0; i < test[ntest].L; i++) {
			if(!(i % 16))
				printf("\n  ");
			printf("%02x", okm[i]);
		}
		printf("\n");

		free(prk);
		free(okm);
	}

}
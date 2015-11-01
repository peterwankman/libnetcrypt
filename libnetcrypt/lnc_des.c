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

#include "lnc.h"
#include "lnc_des_tables.h"
#include "../shared/mem.h"

#define rot28(i, n) ((((i) << (n)) | ((i) >> (28 - (n)))) & 0xfffffff0)

static uint32_t *permute(const uint32_t *in, const uint32_t *table, const size_t tsize, const uint32_t splitpos, int *status) {
	uint32_t *out, tentry, select;
	size_t idx = 0;
	size_t outsize = (tsize > 32)?2:1;

	if((out = malloc(outsize * sizeof(uint32_t))) == NULL) {
		*status = LNC_ERR_MALLOC;
		return NULL;
	}

	memset(out, 0, outsize * sizeof(uint32_t));

	for(idx = 0; idx < tsize; idx++) {
		tentry = table[idx];
		if(tentry > 32) {
			select = (in[1] >> (64 - tentry)) & 1;
		} else {
			select = (in[0] >> (32 - tentry)) & 1;
		}
		
		if(idx > splitpos - 1) {
			out[1] <<= 1;
			out[1] |= select;
		} else {
			out[0] <<= 1;
			out[0] |= select;
		}
	}

	out[0] <<= 32 - splitpos;

	if(outsize == 2)
		out[1] <<= splitpos - (tsize % 32);

	*status = LNC_OK;
	return out;
}

static uint32_t *expand_key(const uint32_t *key, int *status) {
	uint32_t *choice1, *choice2;
	uint32_t *out;
	uint32_t shifted[2];
	uint32_t round;

	out = malloc(16 * 2 * sizeof(uint32_t));
	if(out == NULL) {
		*status = LNC_ERR_MALLOC;
		return NULL;
	}

	choice1 = permute(key, PC1, 56, 28, status);
	if(*status != LNC_OK) {
		free(out);
		return NULL;
	}

	for(round = 0; round < 16; round++) {
		choice1[0] = rot28(choice1[0], kshift[round]);
		choice1[1] = rot28(choice1[1], kshift[round]);

		shifted[0] = choice1[0];
		shifted[0] |= choice1[1] >> 28;
		shifted[1]= choice1[1] << 4;

		choice2 = permute(shifted, PC2, 48, 24, status);
		if(*status != LNC_OK) {
			free(choice1);
			free(out);
			*status = LNC_ERR_MALLOC;
			return NULL;
		}
		out[round * 2] = choice2[0];
		out[round * 2 + 1] = choice2[1];

		free(choice2);
	}
	free(choice1);

	return out;
}

static uint32_t substitute(const uint32_t *in) {
	int i, part;
	uint32_t out = 0;

	for(i = 0;i < 8; i++) {
		if(i < 4)
			part = (in[0] >> (26 - i * 6)) & 0x3f;
		else
			part = (in[1] >> (50 - i * 6)) & 0x3f;

		out <<= 4;
		out |= S[i][part];
	}

	return out;
}

static uint32_t *encrypt(const uint32_t *pt, const uint32_t *expkey, int *status) {
	uint32_t *block = permute(pt, IP, 64, 32, status);
	uint32_t *expblock, subblock, *permblock, temp;
	int round;

	if(*status != LNC_OK)
		return NULL;

	for(round = 0; round < 16; round++) {
		expblock = permute(&block[1], E, 48, 24, status);
		if(*status != LNC_OK) {
			free(block);
			return NULL;
		}

		expblock[0] ^= expkey[2 * round];
		expblock[1] ^= expkey[2 * round + 1];

		subblock = substitute(expblock);
		free(expblock);

		permblock = permute(&subblock, P, 32, 32, status);
		if(*status != LNC_OK) {
			free(block);
			return NULL;
		}
		temp = block[0] ^ permblock[0];
		free(permblock);
		block[0] = block[1];
		block[1] = temp;

	}

	temp = block[0];
	block[0] = block[1];
	block[1] = temp;

	permblock = permute(block, IP1, 64, 32, status);
	free(block);

	return permblock;
}

lnc_des_ctx_t *lnc_des_init(const uint8_t *msg, const uint8_t *key, int *status) {
	lnc_des_ctx_t *out = malloc(sizeof(lnc_des_ctx_t));
	uint32_t intkey[2];
	uint8_t tobyte[8];

	if(out == NULL) {
		*status = LNC_ERR_MALLOC;
		return NULL;
	}

	tobyte[0] = (key[0] & 0xfe);
	tobyte[1] = (key[0] & 0x01) << 7 | (key[1] & 0xfc) >> 1;
	tobyte[2] = (key[1] & 0x03) << 6 | (key[2] & 0xf8) >> 2;
	tobyte[3] = (key[2] & 0x07) << 5 | (key[3] & 0xf0) >> 3;
	tobyte[4] = (key[3] & 0x0f) << 4 | (key[4] & 0xe0) >> 4;
	tobyte[5] = (key[4] & 0x1f) << 3 | (key[5] & 0xc0) >> 5;
	tobyte[6] = (key[5] & 0x3f) << 2 | (key[5] & 0x80) >> 6;
	tobyte[7] = (key[6] & 0x7f) << 1;

	intkey[0] = (tobyte[0] << 24) | (tobyte[1] << 16) | (tobyte[2] << 8) | tobyte[3];
	intkey[1] = (tobyte[4] << 24) | (tobyte[5] << 16) | (tobyte[6] << 8) | tobyte[7];

	out->expkey = expand_key(intkey, status);
	if(*status != LNC_OK) {
		free(out);
		return NULL;
	}

	out->state[0] = (msg[0] << 24) | (msg[1] << 16) | (msg[2] << 8) | msg[3];
	out->state[1] = (msg[4] << 24) | (msg[5] << 16) | (msg[6] << 8) | msg[7];

	*status = LNC_OK;
	return out;
}

void lnc_des_free(void *context) {
	lnc_des_ctx_t *ctx = context;

	free(ctx->expkey);
	free(ctx);
}

uint8_t *lnc_des_tochar(void *context, int *status) {
	lnc_des_ctx_t *ctx = context;
	uint8_t *out = malloc(8);
	int i, j;

	if(out == NULL) {
		*status = LNC_ERR_MALLOC;
		return NULL;
	}

	for(i = 0; i < 2; i++)
		for(j = 0; j < 4; j++)
			out[i * 4 + j] = (ctx->state[i] >> (24 - 8 * j)) & 255;
	
	*status = LNC_OK;
	return out;
}

void lnc_des_enc(void *context) {
	lnc_des_ctx_t *ctx = context;
	uint32_t *block;
	uint32_t *expblock, subblock, *permblock, temp;
	int round, status;

	block = permute(ctx->state, IP, 64, 32, &status);
	if(status != LNC_OK)
		return;

	for(round = 0; round < 16; round++) {
		expblock = permute(&block[1], E, 48, 24, &status);
		if(status != LNC_OK) {
			free(block);
			return;
		}

		expblock[0] ^= ctx->expkey[2 * round];
		expblock[1] ^= ctx->expkey[2 * round + 1];

		subblock = substitute(expblock);
		free(expblock);

		permblock = permute(&subblock, P, 32, 32, &status);
		if(status != LNC_OK) {
			free(block);
			return;
		}
		temp = block[0] ^ permblock[0];
		free(permblock);
		block[0] = block[1];
		block[1] = temp;

	}

	temp = block[0];
	block[0] = block[1];
	block[1] = temp;

	permblock = permute(block, IP1, 64, 32, &status);
	free(block);

	memcpy(ctx->state, permblock, 2 * sizeof(uint32_t));
	free(permblock);
}

void lnc_des_dec(void *context) {
	lnc_des_ctx_t *ctx = context;
	int i;
	uint32_t *expkey = malloc(16 * 2 * sizeof(uint32_t));
	if(expkey == NULL)
		return;

	memcpy(expkey, ctx->expkey, 16 * 2 * sizeof(uint32_t));
	for(i = 0; i < 16; i++) {
		ctx->expkey[2 * i] = expkey[2 * (15 - i)];
		ctx->expkey[2 * i + 1] = expkey[2 * (15 - i) + 1];
	}

	lnc_des_enc(ctx);
	memcpy(ctx->expkey, expkey, 16 * 2 * sizeof(uint32_t));
	free(expkey);
}

uint8_t *lnc_des_enc_block(uint8_t *msg, uint8_t *key, int *status) {
	lnc_des_ctx_t *ctx = lnc_des_init(msg, key, status);
	uint8_t *buf;

	if(*status != LNC_OK)
		return NULL;

	lnc_des_enc(ctx);
	buf = lnc_des_tochar(ctx, status);
	lnc_des_free(ctx);

	return buf;
}

uint8_t *lnc_des_dec_block(uint8_t *msg, uint8_t *key, int *status) {
	lnc_des_ctx_t *ctx = lnc_des_init(msg, key, status);
	uint8_t *buf;

	if(*status != LNC_OK)
		return NULL;

	lnc_des_dec(ctx);
	buf = lnc_des_tochar(ctx, status);
	lnc_des_free(ctx);

	return buf;
}

/*
void destest(void) {
	uint32_t key[] = {0x1bac8107,0x6a39042d}; //{ 0x13345779, 0x9bbcdff1 }; // { 0x12486248, 0x62486248 };
	uint32_t pt[] = {0x812801da,0xcbe98103}; //{ 0x01234567, 0x89abcdef }; // { 0xf0e1d2c3, 0xb4a59687 };
	uint32_t *ct;

	uint8_t key2[7] = { 0x1b, 0x5a, 0x00, 0x36, 0xa7, 0x01, 0x16 };
	uint8_t pt2[8] =  { 0x81, 0x28, 0x01, 0xda, 0xcb, 0xe9, 0x81, 0x03 };
	uint8_t *ct2, *pt3;

	int status, i;
	uint32_t *expkey;
	
	expkey = expand_key(key, &status);
	ct = encrypt(pt, expkey, &status);
	printf("%08x %08x\n\n", ct[0], ct[1]);

	free(expkey);
	free(ct);

	ct2 = lnc_des_enc_block(pt2, key2, &status);

	for(i = 0; i < 8; i++)
		printf("%02x", ct2[i]);
	printf("\n\n");

	pt3 = lnc_des_dec_block(ct2, key2, &status);
	for(i = 0; i < 8; i++)
		printf("%02x", pt3[i]);
	printf("\n\n");
	
	free(ct2);
	free(pt3);
}
*/
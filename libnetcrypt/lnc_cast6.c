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
#include "lnc_macros.h"
#include "lnc_cast6.h"
#include "lnc_cast6_tables.h"

#define byte(i, n) ((uint8_t)((i) >> ((3 - (n)) * 8)))

static uint32_t f1(const uint32_t D, const uint8_t Kr, const uint32_t Km) {
	uint32_t I = rotl((Km + D), Kr);
	return ((S1[byte(I, 0)] ^ S2[byte(I, 1)]) - S3[byte(I, 2)]) + S4[byte(I, 3)];
}

static uint32_t f2(const uint32_t D, const uint8_t Kr, const uint32_t Km) {
	uint32_t I = rotl((Km ^ D), Kr);
	return ((S1[byte(I, 0)] - S2[byte(I, 1)]) + S3[byte(I, 2)]) ^ S4[byte(I, 3)];	
}

static uint32_t f3(const uint32_t D, const uint8_t Kr, const uint32_t Km) {	
	uint32_t I = rotl((Km - D), Kr);
	return ((S1[byte(I, 0)] + S2[byte(I, 1)]) ^ S3[byte(I, 2)]) - S4[byte(I, 3)];	
}

static void W(uint32_t *in, int i) {
	int j = (i & 3) << 3;
	
	i <<= 3;
	in[6] ^= f1(in[7], Tr[j + 0], Tm[i + 0]);
	in[5] ^= f2(in[6], Tr[j + 1], Tm[i + 1]);
	in[4] ^= f3(in[5], Tr[j + 2], Tm[i + 2]);
	in[3] ^= f1(in[4], Tr[j + 3], Tm[i + 3]);
	in[2] ^= f2(in[3], Tr[j + 4], Tm[i + 4]);
	in[1] ^= f3(in[2], Tr[j + 5], Tm[i + 5]);
	in[0] ^= f1(in[1], Tr[j + 6], Tm[i + 6]);
	in[7] ^= f2(in[0], Tr[j + 7], Tm[i + 7]);
}

static void Q(lnc_cast6_ctx_t *ctx, int i) {
	uint32_t *s = ctx->state;

	i <<= 2;
	s[2] ^= f1(s[3], ctx->Kr[i + 0], ctx->Km[i + 0]);
	s[1] ^= f2(s[2], ctx->Kr[i + 1], ctx->Km[i + 1]);
	s[0] ^= f3(s[1], ctx->Kr[i + 2], ctx->Km[i + 2]);
	s[3] ^= f1(s[0], ctx->Kr[i + 3], ctx->Km[i + 3]);
}

static void QBAR(lnc_cast6_ctx_t *ctx, int i) {
	uint32_t *s = ctx->state;

	i <<= 2;
	s[3] ^= f1(s[0], ctx->Kr[i + 3], ctx->Km[i + 3]);
	s[0] ^= f3(s[1], ctx->Kr[i + 2], ctx->Km[i + 2]);
	s[1] ^= f2(s[2], ctx->Kr[i + 1], ctx->Km[i + 1]);
	s[2] ^= f1(s[3], ctx->Kr[i + 0], ctx->Km[i + 0]);
}

static void expand_key(lnc_cast6_ctx_t *context, uint32_t *key, int *status) {
	int i, j;

	if((context->Km = malloc(48 * sizeof(uint32_t))) == NULL) {
		*status = LNC_ERR_MALLOC;
		return;
	}

	if((context->Kr = malloc(48 * sizeof(int))) == NULL) {
		free(context->Km);
		*status = LNC_ERR_MALLOC;
		return;
	}

	for(i = 0; i < 12; i++) {
		W(key, 2 * i);
		W(key, 2 * i + 1);

		j = i << 2;

		context->Kr[j + 0] = key[0] & 31;
		context->Kr[j + 1] = key[2] & 31;
		context->Kr[j + 2] = key[4] & 31;
		context->Kr[j + 3] = key[6] & 31;

		context->Km[j + 0] = key[7];
		context->Km[j + 1] = key[5];
		context->Km[j + 2] = key[3];
		context->Km[j + 3] = key[1];
	}

	*status = LNC_OK;
}

void lnc_cast6_enc(lnc_cast6_ctx_t *context) {
	int i;

	for(i = 0; i < 6; i++)
		Q(context, i);
	for(i = 6; i < 12; i++)
		QBAR(context, i);
}

void lnc_cast6_dec(lnc_cast6_ctx_t *context) {
	int i;

	for(i = 11; i > 5; i--)
		Q(context, i);
	for(i = 5; i >= 0; i--)
		QBAR(context, i);
}

void lnc_cast6_update(lnc_cast6_ctx_t *context, uint8_t *msg, uint8_t *key, int *status) {
	uint32_t int_key[8];
	if(key) {
		free(context->Km);
		free(context->Kr);

		int_key[0] = key[ 0] << 24 | key[ 1] << 16 | key[ 2] << 8 | key[ 3];
		int_key[1] = key[ 4] << 24 | key[ 5] << 16 | key[ 6] << 8 | key[ 7];
		int_key[2] = key[ 8] << 24 | key[ 9] << 16 | key[10] << 8 | key[11];
		int_key[3] = key[12] << 24 | key[13] << 16 | key[14] << 8 | key[15];
		int_key[4] = key[16] << 24 | key[17] << 16 | key[18] << 8 | key[19];
		int_key[5] = key[20] << 24 | key[21] << 16 | key[22] << 8 | key[23];
		int_key[6] = key[24] << 24 | key[25] << 16 | key[26] << 8 | key[27];
		int_key[7] = key[28] << 24 | key[29] << 16 | key[30] << 8 | key[31];

		expand_key(context, int_key, status);
	}

	if(msg) {
		context->state[0] = msg[ 0] << 24 | msg[ 1] << 16 | msg[ 2] << 8 | msg[ 3];
		context->state[1] = msg[ 4] << 24 | msg[ 5] << 16 | msg[ 6] << 8 | msg[ 7];
		context->state[2] = msg[ 8] << 24 | msg[ 9] << 16 | msg[10] << 8 | msg[11];
		context->state[3] = msg[12] << 24 | msg[13] << 16 | msg[14] << 8 | msg[15];
	}
}

void lnc_cast6_init(lnc_cast6_ctx_t *context, uint8_t *msg, uint8_t *key, int *status) {
	uint32_t int_key[8];

	int_key[0] = key[ 0] << 24 | key[ 1] << 16 | key[ 2] << 8 | key[ 3];
	int_key[1] = key[ 4] << 24 | key[ 5] << 16 | key[ 6] << 8 | key[ 7];
	int_key[2] = key[ 8] << 24 | key[ 9] << 16 | key[10] << 8 | key[11];
	int_key[3] = key[12] << 24 | key[13] << 16 | key[14] << 8 | key[15];
	int_key[4] = key[16] << 24 | key[17] << 16 | key[18] << 8 | key[19];
	int_key[5] = key[20] << 24 | key[21] << 16 | key[22] << 8 | key[23];
	int_key[6] = key[24] << 24 | key[25] << 16 | key[26] << 8 | key[27];
	int_key[7] = key[28] << 24 | key[29] << 16 | key[30] << 8 | key[31];

	expand_key(context, int_key, status);

	if(*status != LNC_OK)
		return;

	if((context->state = malloc(4 * sizeof(uint32_t))) == NULL) {
		free(context->Km);
		free(context->Kr);
		*status = LNC_ERR_MALLOC;
		return;
	}

	context->state[0] = msg[ 0] << 24 | msg[ 1] << 16 | msg[ 2] << 8 | msg[ 3];
	context->state[1] = msg[ 4] << 24 | msg[ 5] << 16 | msg[ 6] << 8 | msg[ 7];
	context->state[2] = msg[ 8] << 24 | msg[ 9] << 16 | msg[10] << 8 | msg[11];
	context->state[3] = msg[12] << 24 | msg[13] << 16 | msg[14] << 8 | msg[15];
}

void lnc_cast6_free(lnc_cast6_ctx_t *context) {
	free(context->Km);
	free(context->Kr);
	free(context->state);
}

uint8_t *lnc_cast6_tochar(lnc_cast6_ctx_t ctx, int *status) {
	uint8_t *out = malloc(16);
	if(out == NULL) {
		*status = LNC_ERR_MALLOC;
		return NULL;
	}

	out[ 0] = byte(ctx.state[0], 0);
	out[ 1] = byte(ctx.state[0], 1);
	out[ 2] = byte(ctx.state[0], 2);
	out[ 3] = byte(ctx.state[0], 3);

	out[ 4] = byte(ctx.state[1], 0);
	out[ 5] = byte(ctx.state[1], 1);
	out[ 6] = byte(ctx.state[1], 2);
	out[ 7] = byte(ctx.state[1], 3);

	out[ 8] = byte(ctx.state[2], 0);
	out[ 9] = byte(ctx.state[2], 1);
	out[10] = byte(ctx.state[2], 2);
	out[11] = byte(ctx.state[2], 3);

	out[12] = byte(ctx.state[3], 0);
	out[13] = byte(ctx.state[3], 1);
	out[14] = byte(ctx.state[3], 2);
	out[15] = byte(ctx.state[3], 3);

	*status = LNC_OK;
	return out;
}

uint8_t *lnc_cast6_enc_block(uint8_t *msg, uint8_t *key, int *status) {
	lnc_cast6_ctx_t ctx;
	uint8_t *buf;

	lnc_cast6_init(&ctx, msg, key, status);
	if(*status != LNC_OK)
		return NULL;

	lnc_cast6_enc(&ctx);
	buf = lnc_cast6_tochar(ctx, status);
	lnc_cast6_free(&ctx);

	return buf;
}

uint8_t *lnc_cast6_dec_block(uint8_t *msg, uint8_t *key, int *status) {
	lnc_cast6_ctx_t ctx;
	uint8_t *buf;

	lnc_cast6_init(&ctx, msg, key, status);
	if(*status != LNC_OK)
		return NULL;

	lnc_cast6_dec(&ctx);
	buf = lnc_cast6_tochar(ctx, status);
	lnc_cast6_free(&ctx);

	return buf;
}

lnc_symdef_t lnc_sym_cast6 = { "cast6", 16, 32, lnc_cast6_enc_block, lnc_cast6_dec_block };
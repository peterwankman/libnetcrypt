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

#include <stdio.h>
#include <stdlib.h>

#include "../shared/mem.h"
#include "lnc_aes.h"
#include "lnc_aes_tables.h"

static void sub_bytes(uint8_t *state) {
	int i;
	for(i = 0; i < LNC_AES_BSIZE; i++)
		state[i] = S[state[i]];
}

static void inv_sub_bytes(uint8_t *state) {
	int i;
	for(i = 0; i < LNC_AES_BSIZE; i++)
		state[i] = inv_S[state[i]];
}

static void shift_rows(uint8_t *state) {
	uint8_t temp;

	temp = state[Nb];
	state[Nb] = state[Nb + 1];
	state[Nb + 1] = state[Nb + 2];
	state[Nb + 2] = state[Nb + 3];
	state[Nb + 3] = temp;

	temp = state[2 * Nb];
	state[2 * Nb] = state[2 * Nb + 2];
	state[2 * Nb + 2] = temp;
	temp = state[2 * Nb + 1];
	state[2 * Nb + 1] = state[2 * Nb + 3];
	state[2 * Nb + 3] = temp;

	temp = state[3 * Nb + 3];
	state[3 * Nb + 3] = state[3 * Nb + 2];
	state[3 * Nb + 2] = state[3 * Nb + 1];
	state[3 * Nb + 1] = state[3 * Nb];
	state[3 * Nb] = temp;
}

static void inv_shift_rows(uint8_t *state) {
	uint8_t temp;

	temp = state[Nb + 3];
	state[Nb + 3] = state[Nb + 2];
	state[Nb + 2] = state[Nb + 1];
	state[Nb + 1] = state[Nb];
	state[Nb] = temp;

	temp = state[2 * Nb];
	state[2 * Nb] = state[2 * Nb + 2];
	state[2 * Nb + 2] = temp;
	temp = state[2 * Nb + 1];
	state[2 * Nb + 1] = state[2 * Nb + 3];
	state[2 * Nb + 3] = temp;

	temp = state[3 * Nb];
	state[3 * Nb] = state[3 * Nb + 1];
	state[3 * Nb + 1] = state[3 * Nb + 2];
	state[3 * Nb + 2] = state[3 * Nb + 3];
	state[3 * Nb + 3] = temp;
}

/* 
 * The following functions are taken from 
 * http://www.codeplanet.eu/tutorials/cpp/51-advanced-encryption-standard.html
 */

static uint8_t mult_GF(uint8_t a, uint8_t b) {
	uint8_t out = 0, hi, i;

	for(i = 0; i < 8; i++) {
		if(b & 1)
			out ^= a;
		hi = a & 0x80;
		a <<= 1;
		if(hi)
			a ^= 0x1b;
		b >>= 1;
	}

	return out;
}

static void mix_column(uint8_t *Column) {
	int i;
	uint8_t cpy[4];

	for(i = 0; i < 4; i ++)
		cpy[i] = Column[i];

	Column[0] = mult_GF(cpy[0], 2) ^
				mult_GF(cpy[1], 3) ^
				mult_GF(cpy[2], 1) ^
				mult_GF(cpy[3], 1);

	Column[1] = mult_GF(cpy[0], 1) ^
				mult_GF(cpy[1], 2) ^
				mult_GF(cpy[2], 3) ^
				mult_GF(cpy[3], 1);

	Column[2] = mult_GF(cpy[0], 1) ^
				mult_GF(cpy[1], 1) ^
				mult_GF(cpy[2], 2) ^
				mult_GF(cpy[3], 3);

	Column[3] = mult_GF(cpy[0], 3) ^
				mult_GF(cpy[1], 1) ^
				mult_GF(cpy[2], 1) ^
				mult_GF(cpy[3], 2);
}

static void inv_mix_column(uint8_t *Column) {
	int i;
	uint8_t cpy[4];

	for(i = 0; i < 4; i ++)
		cpy[i] = Column[i];

	Column[0] = mult_GF(cpy[0], 0xe) ^
				mult_GF(cpy[1], 0xb) ^
				mult_GF(cpy[2], 0xd) ^
				mult_GF(cpy[3], 0x9);

	Column[1] = mult_GF(cpy[0], 0x9) ^
				mult_GF(cpy[1], 0xe) ^
				mult_GF(cpy[2], 0xb) ^
				mult_GF(cpy[3], 0xd);

	Column[2] = mult_GF(cpy[0], 0xd) ^
				mult_GF(cpy[1], 0x9) ^
				mult_GF(cpy[2], 0xe) ^
				mult_GF(cpy[3], 0xb);

	Column[3] = mult_GF(cpy[0], 0xb) ^
				mult_GF(cpy[1], 0xd) ^
				mult_GF(cpy[2], 0x9) ^
				mult_GF(cpy[3], 0xe);
}

static void mix_columns(uint8_t *state, int mode) {
	int i, j;
	uint8_t column[4];

	for(i = 0; i < Nb; i++) {
		for(j = 0; j < 4; j++)
			column[j] = state[4 * j + i];

		if(mode == FOR_MIX)
			mix_column(column);
		else
			inv_mix_column(column);

		for(j = 0; j < 4; j++)
			state[4 * j + i] = column[j];
	}
}

static void add_roundkey(uint8_t *state, uint32_t *expkey, int round) {
	int i;
	for(i = 0; i < Nb; i++) {
		state[i] ^= expkey[round * Nb + i] >> 24;
		state[Nb + i] ^= ((expkey[round * Nb + i] >> 16) & 255);
		state[2 * Nb + i] ^= ((expkey[round * Nb + i] >> 8) & 255);
		state[3 * Nb + i] ^= (expkey[round * Nb + i] & 255);
	}
}

static uint32_t *expand_key(uint32_t *key, int *status) {
	int i;
	uint32_t temp, *W;

	if((W = malloc(Nb * (Nr + 1) * sizeof(uint32_t))) == NULL) {
		*status = LNC_ERR_MALLOC;
		return NULL;
	}

	for(i = 0; i < Nk; i++)
		W[i] = key[i];

	for(i = Nk; i < Nb * (Nr + 1); i++) {
		temp = W[i - 1];
		if(i % Nk == 0) {
			temp = sub_byte(rot_byte(temp)) ^ (rcon[i / Nk] << 24);
		}
#if Nk > 6
		else if(i % Nk == 4)
			temp = sub_byte(temp);
#endif
		W[i] = W[i - Nk] ^ temp;
	}
	
	*status = LNC_OK;
	return W;
}

static uint8_t *mkstate(uint8_t *msg, int *status) {
    uint8_t *state;
    int i;

    if((state = malloc(LNC_AES_BSIZE)) == NULL) {
		*status = LNC_ERR_MALLOC;
        return NULL;
	}

    for(i = 0; i < Nb; i++) {
        state[i] = msg[i * Nb];
        state[Nb + i] = msg[i * Nb + 1];
        state[2 * Nb + i] = msg[i * Nb + 2];
        state[3 * Nb + i] = msg[i * Nb + 3];
    }

	*status = LNC_OK;
    return state;
}

void lnc_aes_enc(lnc_aes_ctx_t context) {
	int i;
	uint32_t *expkey = context.expkey;
	uint8_t *state = context.state;

	add_roundkey(state, expkey, 0);

	for(i = 1; i < Nr; i++) {
		sub_bytes(state);
		shift_rows(state);
		mix_columns(state, FOR_MIX);
		add_roundkey(state, expkey, i);
	}
	sub_bytes(state);
	shift_rows(state);
	add_roundkey(state, expkey, Nr);
}

void lnc_aes_dec(lnc_aes_ctx_t context) {
	int i;
	uint32_t *expkey = context.expkey;
	uint8_t *state = context.state;

	add_roundkey(state, expkey, Nr);
	inv_shift_rows(state);
	inv_sub_bytes(state);
	for(i = Nr - 1; i > 0; i--) {
		add_roundkey(state, expkey, i);
		mix_columns(state, INV_MIX);
		inv_shift_rows(state);
		inv_sub_bytes(state);
	}
	add_roundkey(state, expkey, 0);
}

void lnc_aes_update(lnc_aes_ctx_t *context, uint8_t *msg, uint8_t *key, int *status) {
	uint32_t int_key[Nk];
	int i;

	*status = LNC_OK;

	if(key) {
		free(context->expkey);
		for(i = 0; i < Nk; i++)
			int_key[i] = key[i * 4] << 24 |
						key[i * 4 + 1] << 16 |
						key[i * 4 + 2] << 8 |
						key[i * 4 + 3];
		context->expkey = expand_key(int_key, status);
		if(status != LNC_OK)
			return;
	}	
	
	if(msg) {
		free(context->state);
		context->state = mkstate(msg, status);
	}
}

void lnc_aes_init(lnc_aes_ctx_t *context, uint8_t *msg, uint8_t *key, int *status) {
	uint32_t int_key[Nk];
	int i;
	
	for(i = 0; i < Nk; i++)
		int_key[i] = key[i * 4] << 24 |
					key[i * 4 + 1] << 16 |
					key[i * 4 + 2] << 8 |
					key[i * 4 + 3];

	context->expkey = expand_key(int_key, status);
	if(*status != LNC_OK)
		return;

	context->state = mkstate(msg, status);
}

void lnc_aes_free(lnc_aes_ctx_t context) {
	free(context.expkey);
	free(context.state);
}

uint8_t *lnc_aes_tochar(lnc_aes_ctx_t context, int *status) {
	uint8_t *out = malloc(LNC_AES_BSIZE);
	int i, j;

	if(out == NULL) {
		*status = LNC_ERR_MALLOC;
		return NULL;
	}

	for(i = 0; i < 4; i++) {
		for(j = 0; j < Nb; j++) {
			out[i * Nb + j] = context.state[j * Nb + i];
		}
	}

	*status = LNC_OK;
	return out;
}

uint8_t *lnc_aes_enc_block(uint8_t *msg, uint8_t *key, int *status) {
	lnc_aes_ctx_t context;

	lnc_aes_init(&context, msg, key, status);
	if(*status != LNC_OK)
		return NULL;

	lnc_aes_enc(context);
	return lnc_aes_tochar(context, status);
}

uint8_t *lnc_aes_dec_block(uint8_t *msg, uint8_t *key, int *status) {
	lnc_aes_ctx_t context;

	lnc_aes_init(&context, msg, key, status);
	if(*status != LNC_OK)
		return NULL;

	lnc_aes_dec(context);
	return lnc_aes_tochar(context, status);
}
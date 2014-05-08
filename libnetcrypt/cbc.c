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

#include <stdlib.h>

#include "lnc.h"

#define MODE_ENC		1
#define MODE_DEC		2
#define LNC_MORE		1
#define LNC_DONE		2

typedef struct lnc_moo_ctx {
	lnc_symdef_t cipher;
	uint8_t *intext, *outtext, *key, *data;
	uint32_t fill;
	int mode;
} lnc_moo_ctx_t;

lnc_moo_ctx_t *lnc_cbc_init_ctx(lnc_symdef_t cipher, uint8_t *IV, uint8_t *key, int mode, int *status) {
	lnc_moo_ctx_t *out = malloc(sizeof(lnc_moo_ctx_t));

	if((mode != MODE_ENC) && (mode != MODE_DEC)) {
		*status = LNC_ERR_VAL;
		return NULL;
	}

	if(!out) {
		*status = LNC_ERR_MALLOC;
		return NULL;
	}

	if((out->data = malloc(cipher.bsize)) == NULL) {
		free(out);
		*status = LNC_ERR_MALLOC;
		return NULL;
	}

	if((out->intext = malloc(cipher.bsize)) == NULL) {
		free(out->data);
		free(out);
		*status = LNC_ERR_MALLOC;
		return NULL;
	}

	if((out->outtext = malloc(cipher.bsize)) == NULL) {
		free(out->intext);
		free(out->data);
		free(out);
		*status = LNC_ERR_MALLOC;
		return NULL;
	}

	if((out->key = malloc(cipher.ksize)) == NULL) {
		free(out->outtext);
		free(out->intext);
		free(out->data);
		free(out);
		*status = LNC_ERR_MALLOC;
		return NULL;
	}

	memcpy(out->key, key, cipher.ksize);
	memcpy(out->data, IV, cipher.bsize);
	out->cipher = cipher;
	out->fill = 0;
}

int lnc_cbc_update_ctx(lnc_moo_ctx_t *context, uint8_t *intext, uint32_t len, int *status) {
	uint32_t offs = 0, tocopy;
	uint8_t *buf;

	if(len) {
		tocopy = context->cipher.bsize - context->fill;
		tocopy = tocopy < len ? tocopy : len;
		memcpy(context->intext, intext, tocopy);
		len -= tocopy;
		context->fill += tocopy;
	}

	if(context->fill == context->cipher.bsize) {
		if(context->mode == MODE_ENC) {
			lnc_xor_block(context->intext, context->data, context->cipher.bsize);
			buf = context->cipher.encfunc(context->intext, context->key, status);
			memcpy(context->outtext, buf, context->cipher.bsize);
			memcpy(context->data, buf, context->cipher.bsize);
		} else if(context->mode == MODE_DEC) {
			buf = context->cipher.decfunc(context->intext, context->key, status);
			lnc_xor_block(buf, context->data, context->cipher.bsize);
			memcpy(context->outtext, buf, context->cipher.bsize);
			memcpy(context->data, context->intext, context->cipher.bsize);
		}
		len -= context->cipher.bsize;
		context->fill -= context->cipher.bsize;
	}

	return len;
}
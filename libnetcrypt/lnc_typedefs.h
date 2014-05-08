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

#include <stdint.h>
#include "../libtommath/tommath.h"

#include "lnc.h"

#ifndef LNC_TYPEDEFS_H_
#define LNC_TYPEDEFS_H_

typedef struct lnc_conn {
	SOCKET s;
	uint8_t *sym_key, *cookie;
	uint32_t sym_key_size, cookie_size;
} lnc_sock_t;

typedef struct hash {
	uint32_t size;
	uint32_t h0, h1, h2, h3, h4, h5, h6, h7;
	unsigned char *string;
} lnc_hash_t;

typedef struct dh_key {
	mp_int generator;
	mp_int modulus;
	mp_int secret_key;
	mp_int public_key;
} lnc_key_t;

typedef struct lnc_aes_ctx {
	uint32_t *expkey;
	uint8_t *state;
} lnc_aes_ctx_t;

typedef struct lnc_cast6_ctx {
	uint32_t *Km;
	int *Kr;
	uint32_t *state;
} lnc_cast6_ctx_t;

typedef lnc_hash_t (*lnc_hashfunc_t)(const uint8_t*, const size_t);
typedef uint8_t* (*lnc_symfunc_t)(uint8_t*, uint8_t*, int*);

typedef struct hashdef {
	char *name;
	size_t outsize;
	lnc_hashfunc_t func;
} lnc_hashdef_t;

typedef struct symdef {
	char *name;
	size_t bsize, ksize;
	lnc_symfunc_t encfunc;
	lnc_symfunc_t decfunc;	
} lnc_symdef_t;

#define LNC_FEATURE_ENCRYPT		0x00000001
#define LNC_FEATURE_SIGN		0x00000002
#define LNC_FEATURE_EXCHANGE	0x00000004

typedef struct asymdef {
	char *name;
	uint32_t features;

} lnc_asymdef_t;

#endif

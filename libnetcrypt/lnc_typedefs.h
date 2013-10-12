/* 
 * libnetcrypt -- Encrypted communication with DH and AES
 * 
 * Copyright (C) 2013  Martin Wolters
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

#include <WinSock2.h>
#include <stdint.h>
#include "../libtommath/tommath.h"

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

typedef struct {
	uint32_t *expkey;
	uint8_t *state;
} lnc_aes_ctx_t;

#endif
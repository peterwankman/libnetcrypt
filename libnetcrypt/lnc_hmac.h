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

#include "lnc_typedefs.h"

#ifndef LNC_HMAC_H_
#define LNC_HMAC_H_

uint8_t *lnc_hmac(const lnc_hashdef_t hdef, const uint8_t *key, const size_t klen, const uint8_t *msg, const size_t mlen, int *status);

lnc_hmac_ctx_t *lnc_hmac_init(const lnc_hashdef_t hdef, const uint8_t *key, const size_t keylen, int *status);
void lnc_hmac_free(lnc_hmac_ctx_t *ctx);
void lnc_hmac_update(lnc_hmac_ctx_t *ctx, const uint8_t *data, const size_t datalen, int *status);
uint8_t *lnc_hmac_finalize(lnc_hmac_ctx_t *ctx, int *status);

uint8_t *lnc_hkdf_extract(const lnc_hashdef_t hdef, const uint8_t *salt, const size_t saltlen, const uint8_t *ikm, const size_t ikmlen, int *status);
uint8_t *lnc_hkdf_expand(const lnc_hashdef_t hdef, const uint8_t *prk, const size_t prklen, const uint8_t *info, const size_t infolen, const size_t L, int *status);

#endif
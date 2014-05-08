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

#ifndef CAST6_H_
#define CAST6_H_

void lnc_cast6_enc(lnc_cast6_ctx_t *context);
void lnc_cast6_dec(lnc_cast6_ctx_t *context);
void lnc_cast6_update(lnc_cast6_ctx_t *context, uint8_t *msg, uint8_t *key, int *status);
void lnc_cast6_init(lnc_cast6_ctx_t *context, uint8_t *msg, uint8_t *key, int *status);
void lnc_cast6_free(lnc_cast6_ctx_t context);
uint8_t *lnc_cast6_tochar(lnc_cast6_ctx_t context, int *status);

uint8_t *lnc_cast6_enc_block(uint8_t *msg, uint8_t *key, int *status);
uint8_t *lnc_cast6_dec_block(uint8_t *msg, uint8_t *key, int *status);

void initconst(void);

#endif
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
#include "lnc_macros.h"

#ifndef LNC_AES_H
#define LNC_AES_H

#define FOR_MIX 1
#define INV_MIX 2

#define rot_byte(i) rotl(i, 8)
#define sub_byte(i) ((S[i >> 24] << 24) |\
                    (S[(i >> 16) & 255] << 16) |\
                    (S[(i >> 8) & 255] << 8) |\
                    (S[i & 255] & 255))

#define Nb	4
#define Nk	8
#define Nr	(Nk + 6)

#define LNC_AES_BSIZE (Nb * 4)
#define LNC_AES_KSIZE (Nk * 4)

void lnc_aes_enc(void *context);
void lnc_aes_dec(void *context);
void lnc_aes_update(void *context, uint8_t *msg, uint8_t *key, int *status);
void lnc_aes_init(void *context, uint8_t *msg, uint8_t *key, int *status);
void lnc_aes_free(void *context);
uint8_t *lnc_aes_tochar(void *context, int *status);

uint8_t *lnc_aes_enc_block(uint8_t *msg, uint8_t *key, int *status);
uint8_t *lnc_aes_dec_block(uint8_t *msg, uint8_t *key, int *status);

LNC_DEFINE_SYM(lnc_sym_aes, "AES", 0x383a1d45, 16, 32, lnc_aes_enc_block, lnc_aes_dec_block, lnc_aes_enc, lnc_aes_dec, lnc_aes_update, lnc_aes_init, lnc_aes_free, lnc_aes_tochar);

#endif

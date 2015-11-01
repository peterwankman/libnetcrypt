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

#ifdef WITH_DES
#ifndef LNC_DES_H_
#define LNC_DES_H_

uint8_t *lnc_des_enc_block(uint8_t *msg, uint8_t *key, int *status);
// void destest(void);

LNC_DEFINE_SYM(lnc_sym_des, "DES", 0x90d6d677, 8, 7, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

#endif
#endif
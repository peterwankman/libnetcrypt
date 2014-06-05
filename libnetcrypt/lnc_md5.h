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


#ifdef WITH_MD5
#ifndef LNC_MD5_H_
#define LNC_MD5_H_

#include "lnc.h"
#include "lnc_macros.h"

void lnc_md5_free(void *in);
lnc_hash_t lnc_md5(const uint8_t *in, const size_t insize, int *status);

void md5test(void);

LNC_DEFINE_HASH(lnc_hash_md5, "md5", 0x229ca98b, 16, 64, lnc_md5, lnc_md5_free);

#endif
#endif
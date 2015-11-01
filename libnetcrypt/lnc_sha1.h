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

#ifdef WITH_SHA1
#ifndef LNC_SHA1_H_
#define LNC_SHA1_H_

#include "lnc.h"
#include "lnc_macros.h"

void lnc_sha1_free(void *in);
lnc_hash_t lnc_sha1(const uint8_t *in, const size_t insize, int *status);

LNC_DEFINE_HASH( lnc_hash_sha1, "SHA1", 0xd4e90fd2, 20, 64, lnc_sha1, lnc_sha1_free);

#endif 
#endif

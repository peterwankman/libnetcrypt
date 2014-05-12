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

#ifndef LNC_UTIL_H_
#define LNC_UTIL_H_

#ifdef _MSC_VER
#define snprintf sprintf_s
#ifdef _WIN64
#define strlen(n) ((int)strlen(n))
#endif
#endif

#define MAXBUF 512
#define SALTLEN 256

typedef enum { type_boolean, type_integer, type_text } value_type_t;

uint32_t lnc_conv_endian(uint32_t n);
size_t lnc_mksalt(char **saltout, size_t *slen);
uint8_t *lnc_hex2char(const char *in, size_t len);
int lnc_salt_hash(const char *in, const size_t len, const uint8_t *salthex, char **hashout, int *status);
int lnc_fill_random(unsigned char *dst, int len, void *dat);
void lnc_key_to_file(lnc_key_t *key, char *filename, int *status);
lnc_key_t *lnc_key_from_file(char *filename, int *status);
void lnc_xor_block(uint8_t *b1, const uint8_t *b2, const uint32_t len);
uint8_t *lnc_pad(const uint8_t *data, const uint32_t bsize, const uint32_t inlen, uint32_t *newlen);
char *get_line(FILE *fp);
void lnc_key_to_file_new(lnc_key_t *key, char *filename, int *status);

#endif

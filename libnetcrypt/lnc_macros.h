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

#ifndef LNC_MISC_H_
#define LNC_MISC_H_

#define rotl(i, n) (((i) << (n)) | ((i) >> (32 - (n))))
#define rotr(i, n) (((i) >> (n)) | ((i) << (32 - (n))))

#define LNC_DEFINE_HASH(identifier, name, ID, outsize, blocksize, hashfunc, freefunc) \
	static lnc_hashdef_t identifier = { name, ID, outsize, blocksize, hashfunc, freefunc };

/*
typedef struct symdef {
	char *name;
	uint32_t ID;
	size_t bsize, ksize;
	lnc_sym_blockfunc_t encblock;
	lnc_sym_blockfunc_t decblock;

	lnc_sym_func_t enc;
	lnc_sym_func_t dec;
	lnc_sym_updatefunc_t update;
	lnc_sym_initfunc_t init;
	lnc_sym_freefunc_t clear;
	lnc_sym_charfunc_t tochar;

	lnc_freefunc_t freefunc;
} lnc_symdef_t;
*/

#define LNC_DEFINE_SYM(identifier, name, ID, bsize, ksize, encblock, decblock, enc, dec, update, init, clear, tochar) \
	static lnc_symdef_t identifier = { \
		name, ID, \
		bsize, ksize, \
		encblock, decblock, \
		enc, dec, \
		update, init, clear, tochar \
	};

#endif
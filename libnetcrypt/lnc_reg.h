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

#ifndef LNC_REG_H_
#define LNC_REG_H_

#include "lnc.h"

int lnc_reg_sym_alg(char *name, size_t bsize, size_t ksize,
	lnc_symfunc_t enc, lnc_symfunc_t dec);
int lnc_reg_hash_alg(char *name, size_t outsize, lnc_hashfunc_t func);
void lnc_free_algs(void);
void lnc_reg_builtin(void);
void lnc_list_algs(void);

#endif
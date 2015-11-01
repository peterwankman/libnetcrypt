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

#include <stdlib.h>

#include "../shared/mem.h"
#include "lnc.h"
#include "lnc_reg.h"

#ifdef WITH_SHA256
#include "lnc_sha1.h"
#endif
#ifdef WITH_SHA256
#include "lnc_sha256.h"
#endif

#define PREALLOC_BLOCK	3

lnc_hashdef_t *lnc_hash_algs = NULL;
size_t lnc_num_hash_algs = 0;
size_t lnc_alloc_hash_algs = 0;

lnc_symdef_t *lnc_sym_algs = NULL;
size_t lnc_num_sym_algs = 0;
size_t lnc_alloc_sym_algs = 0;

lnc_symdef_t *lnc_asym_algs = NULL;
size_t lnc_num_asym_algs = 0;
size_t lnc_alloc_asym_algs = 0;

int lnc_reg_sym_alg(const lnc_symdef_t def) {
	lnc_symdef_t *newblock;
	size_t i;

	for(i = 0; i < lnc_num_sym_algs; i++)
		if(def.ID == lnc_sym_algs[i].ID)
			return LNC_ERR_VAL;

	if(lnc_num_sym_algs % PREALLOC_BLOCK == 0) {
		newblock = malloc((lnc_alloc_sym_algs + PREALLOC_BLOCK) * sizeof(lnc_symdef_t));
		if(!newblock)
			return LNC_ERR_MALLOC;

		memcpy(newblock, lnc_sym_algs, lnc_num_sym_algs * sizeof(lnc_symdef_t));
		free(lnc_sym_algs);
		lnc_sym_algs = newblock;
		lnc_alloc_sym_algs += PREALLOC_BLOCK;
	}

	lnc_sym_algs[lnc_num_sym_algs] = def;
	lnc_num_sym_algs++;

	return LNC_OK;
}

int lnc_reg_hash_alg(const lnc_hashdef_t def) {
	lnc_hashdef_t *newblock;
	size_t i;

	for(i = 0; i < lnc_num_hash_algs; i++)
		if(def.ID == lnc_hash_algs[i].ID)
			return LNC_ERR_VAL;

	if(lnc_alloc_hash_algs % PREALLOC_BLOCK == 0) {
		newblock = malloc((lnc_alloc_hash_algs + PREALLOC_BLOCK) * sizeof(lnc_hashdef_t));
		if(!newblock)
			return LNC_ERR_MALLOC;

		memcpy(newblock, lnc_hash_algs, lnc_num_hash_algs * sizeof(lnc_hashdef_t));
		free(lnc_hash_algs);
		lnc_hash_algs = newblock;
	}

	lnc_hash_algs[lnc_num_hash_algs] = def;
	lnc_num_hash_algs++;

	return LNC_OK;
}

void lnc_free_algs(void) {
	lnc_num_sym_algs = 0;
	free(lnc_sym_algs);

	lnc_num_hash_algs = 0;
	free(lnc_hash_algs);
}

int lnc_reg_builtin(void) {
	int status;
#ifdef WITH_AES
	if((status = lnc_reg_sym_alg(lnc_sym_aes)) != LNC_OK) return status;
#endif
#ifdef WITH_CAST6
	if((status = lnc_reg_sym_alg(lnc_sym_cast6)) != LNC_OK) return status;
#endif
#ifdef WITH_DES
	if((status = lnc_reg_sym_alg(lnc_sym_des)) != LNC_OK) return status;
#endif
#ifdef WITH_MD5
	if((status = lnc_reg_hash_alg(lnc_hash_md5)) != LNC_OK) return status;
#endif
#ifdef WITH_SHA1
	if((status = lnc_reg_hash_alg(lnc_hash_sha1)) != LNC_OK) return status;
#endif
#ifdef WITH_SHA256
	if((status = lnc_reg_hash_alg(lnc_hash_sha256)) != LNC_OK) return status;
#endif

	return status;
}

lnc_hashdef_t *lnc_get_hash(const uint32_t ID, int *status) {
	size_t i;

	*status = LNC_OK;
	for(i = 0; i < lnc_num_hash_algs; i++)
		if(lnc_hash_algs[i].ID == ID)
			return lnc_hash_algs + i;

	*status = LNC_ERR_UNK;
	return NULL;
}

lnc_symdef_t *lnc_get_sym(const uint32_t ID, int *status) {
	size_t i;

	*status = LNC_OK;
	for(i = 0; i < lnc_num_sym_algs; i++)
		if(lnc_sym_algs[i].ID == ID)
			return lnc_sym_algs + i;

	*status = LNC_ERR_UNK;
	return NULL;
}

void lnc_list_algs(void) {
	size_t i;
	printf("Hash algorithms:\n");
	for(i = 0; i < lnc_num_hash_algs; i++) {
		printf(" %s (%d bits)\n", lnc_hash_algs[i].name, lnc_hash_algs[i].outsize * 8);
	}
	if(!lnc_num_hash_algs)
		printf(" None.\n");

	printf("Symmetric algorithms:\n");
	for(i = 0; i < lnc_num_sym_algs; i++) {
		printf(" %s (Block size: %d bits; Key size: %d bits)\n", lnc_sym_algs[i].name,
			lnc_sym_algs[i].bsize * 8, lnc_sym_algs[i].ksize * 8);
	}
	if(!lnc_num_sym_algs)
		printf(" None.\n");

	printf("Asymmetric algorithms:\n");
	for(i = 0; i < lnc_num_asym_algs; i++) {
		printf(" %s\n", lnc_asym_algs[i].name);
	}
	if(!lnc_num_asym_algs)
		printf(" None.\n");
}
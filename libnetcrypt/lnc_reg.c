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

int lnc_reg_sym_alg(char *name, size_t bsize, size_t ksize,
	lnc_symfunc_t enc, lnc_symfunc_t dec) {

	lnc_symdef_t *newblock;

	if(lnc_num_sym_algs % PREALLOC_BLOCK == 0) {
		newblock = malloc((lnc_alloc_sym_algs + PREALLOC_BLOCK) * sizeof(lnc_symdef_t));
		if(!newblock)
			return LNC_ERR_MALLOC;
		memcpy(newblock, lnc_sym_algs, lnc_num_sym_algs * sizeof(lnc_symdef_t));
		free(lnc_sym_algs);
		lnc_sym_algs = newblock;
		lnc_alloc_sym_algs += PREALLOC_BLOCK;
	}

	if((lnc_sym_algs[lnc_num_sym_algs].name = malloc(strlen(name) + 1)) == NULL)
		return LNC_ERR_MALLOC;

	strncpy(lnc_sym_algs[lnc_num_sym_algs].name, name, strlen(name) + 1);
	lnc_sym_algs[lnc_num_sym_algs].bsize = bsize;
	lnc_sym_algs[lnc_num_sym_algs].ksize = ksize;
	lnc_sym_algs[lnc_num_sym_algs].encfunc = enc;
	lnc_sym_algs[lnc_num_sym_algs].decfunc = dec;
	
	lnc_num_sym_algs++;

	return LNC_OK;
}

int lnc_reg_hash_alg(char *name, size_t outsize, size_t blocksize, lnc_hashfunc_t hashfunc, lnc_freefunc_t freefunc) {
	lnc_hashdef_t *newblock;

	if(lnc_alloc_hash_algs % PREALLOC_BLOCK == 0) {
		newblock = malloc((lnc_alloc_hash_algs + PREALLOC_BLOCK) * sizeof(lnc_hashdef_t));
		if(!newblock)
			return LNC_ERR_MALLOC;
		memcpy(newblock, lnc_hash_algs, lnc_num_hash_algs * sizeof(lnc_hashdef_t));
		free(lnc_hash_algs);
		lnc_hash_algs = newblock;
	}

	if((lnc_hash_algs[lnc_num_hash_algs].name = malloc(strlen(name) + 1)) == NULL)
		return LNC_ERR_MALLOC;

	strncpy(lnc_hash_algs[lnc_num_hash_algs].name, name, strlen(name) + 1);
	lnc_hash_algs[lnc_num_hash_algs].outsize = outsize;
	lnc_hash_algs[lnc_num_hash_algs].blocksize = blocksize;
	lnc_hash_algs[lnc_num_hash_algs].hashfunc = hashfunc;
	lnc_hash_algs[lnc_num_hash_algs].freefunc = freefunc;
	lnc_num_hash_algs++;

	return LNC_OK;
}

void lnc_free_algs(void) {
	while(lnc_num_sym_algs)
		free(lnc_sym_algs[--lnc_num_sym_algs].name);
	free(lnc_sym_algs);

	while(lnc_num_hash_algs)
		free(lnc_hash_algs[--lnc_num_hash_algs].name);
	free(lnc_hash_algs);
}

void lnc_reg_builtin(void) {
	int status;

#ifdef WITH_AES
	lnc_reg_sym_alg("aes128", LNC_AES_BSIZE, LNC_AES_KSIZE, lnc_aes_enc_block, lnc_aes_dec_block);
#endif
#ifdef WITH_CAST6
	lnc_reg_sym_alg("cast6", 16, 32, lnc_cast6_enc_block, lnc_cast6_dec_block);
#endif
#ifdef WITH_SHA256
	lnc_reg_hash_alg("sha256", 32, 64, lnc_sha256, lnc_sha256_free);
#endif

	lnc_hmac(lnc_hash_algs[0], "key", 3, "The quick brown fox jumps over the lazy dog", 43, &status);
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
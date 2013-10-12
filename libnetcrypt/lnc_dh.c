/* 
 * libnetcrypt -- Encrypted communication with DH and AES
 * 
 * Copyright (C) 2013  Martin Wolters
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

#include "../libtommath/tommath.h"

#include "../shared/mem.h"
#include "lnc.h"

static int mp_add1(mp_int *a, mp_int *b) {
    mp_int one;
    int ret = MP_OKAY;

    if((ret = mp_init(&one)) != MP_OKAY) return ret;

    mp_set(&one, 1);
    ret = mp_add(a, &one, b);

    mp_clear(&one);
    return ret;
}

static int mp_random(mp_int *mpi, size_t size) {
	uint8_t *buf;
	size /= 8;

	if(size > UINT_MAX)
		return LNC_ERR_OVER;

	if((buf = malloc(size)) == NULL)
		return LNC_ERR_MALLOC;
	lnc_fill_random(buf, (int)size, NULL);
		
	mp_read_unsigned_bin(mpi, buf, (int)size);
	free(buf);

	return LNC_OK;
}

/* FROM NIST RECOMMENDATIONS */
uint32_t lnc_suggest_subgroup(uint32_t modsize) {
	if(modsize <= 160)
		return 0;
	if(modsize <= 1024)
		return 160;
	else if(modsize <= 2048)
		return 224;
	else if(modsize <= 3072)
		return 256;
	else if(modsize <= 7680)
		return 384;
	else
		return 511;
}

lnc_key_t *lnc_gen_key(const uint32_t size, int *status) {
	mp_int small_prime, random, mul, s, tmp;
	mp_int modulus, root, public_key, secret_key;
	int test_small, test_full;
	uint32_t smallsize = lnc_suggest_subgroup(size);
	int ret;
	
	lnc_key_t *out;

	if(size > UINT_MAX) {
		*status = LNC_ERR_OVER;
		return NULL;
	}

	
	test_small = mp_prime_rabin_miller_trials((int)smallsize);
	test_full = mp_prime_rabin_miller_trials((int)size);

	if((ret = mp_init_multi(&small_prime, &random, &mul, &s, &tmp, &modulus, &root, &secret_key, &public_key, NULL)) != MP_OKAY) {
		*status = LNC_ERR_LTM;
		return NULL;
	}

	/*
	 * The modulus is created in the form p = q * r + 1. This aids
	 * in finding g and guarantees a large prime factor (q) in the
	 * order of the group. I the order of the group contains only
	 * small prime factors, the key can be attacked easily.
	 */
	printf("libnetcrypt: Generating small prime (%d bits)...\n", smallsize);
	mp_prime_random_ex(&small_prime, test_small, smallsize, 0, lnc_fill_random, NULL);

	printf("libnetcrypt: Generating modulus... (%d bits)\n", size);
	do {
		do {
			mp_random(&random, size - smallsize);
		} while(mp_cmp_d(&random, 0) == MP_EQ);
		mp_mul(&small_prime, &random, &mul);
		mp_add1(&mul, &modulus);
		mp_prime_is_prime(&modulus, test_full, &ret);		
	} while(!ret);	

	/* Specified in FIPS 186-4 A.2.1 */
	printf("libnetcrypt: Generating generator...\n");
	do {
		mp_random(&s, size - smallsize);
		mp_exptmod(&s, &random, &modulus, &root);
	} while(mp_cmp_d(&root, 1) == MP_EQ);

	/* 
	 * We make sure a and g^a != 1 as these would make
	 * determining the shared secret trivial.
	 */
	printf("libnetcrypt: Generating secret and public key...\n");
	do {
		do {
			mp_random(&secret_key, size);
		} while((mp_cmp_d(&secret_key, 1) == MP_EQ) || (mp_cmp_mag(&secret_key, &modulus) != MP_LT));
		mp_exptmod(&root, &secret_key, &modulus, &public_key);
	} while(mp_cmp_d(&public_key, 1) == MP_EQ);

	out = malloc(sizeof(lnc_key_t));
	out->generator = root;
	out->modulus = modulus;
	out->secret_key = secret_key;
	out->public_key = public_key;

	printf("libnetcrypt: Done.\n");
	mp_clear_multi(&small_prime, &random, &mul, &s, &tmp, NULL);
	*status = LNC_OK;
	return out;
}

lnc_key_t *lnc_gen_client_key(const uint32_t size, int *status) {
	lnc_key_t *out = malloc(sizeof(lnc_key_t));

	if(!out) {
		*status = LNC_ERR_MALLOC;
		return NULL;
	}

	mp_init_multi(&(out->generator), &(out->modulus), &(out->secret_key), &(out->public_key), NULL);

	if(mp_random(&(out->secret_key), size) != MP_OKAY) {
		*status = LNC_ERR_LTM;
		free(out);
		return NULL;
	}

	mp_set(&(out->generator), 0);
	mp_set(&(out->modulus), 0);
	mp_set(&(out->public_key), 0);
		
	*status = LNC_OK;
	return out;
}

void lnc_free_key(lnc_key_t *key) {
	if(!key)
		return;

	mp_clear(&(key->generator));
	mp_clear(&(key->modulus));
	mp_clear(&(key->public_key));
	mp_clear(&(key->secret_key));

	free(key);
}
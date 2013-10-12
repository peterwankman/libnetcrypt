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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _MSC_VER
#include <WinSock2.h>
#include <Windows.h>
#endif

#include "../shared/mem.h"
#include "lnc.h"

#ifdef U_S_A_U_S_A_U_S_A
#include <bcrypt.h>
#endif

uint32_t lnc_conv_endian(uint32_t n) {
	uint32_t test = 1, ret = n;
	uint8_t *ptr = ((uint8_t*)&ret);
	int i;

	if(((uint8_t*)&test)[0] == 1) { /* Are we little-endian? */
		for(i = 0; i < sizeof(n); i++) {			
			ptr[sizeof(n) - i - 1] = n & 0xff;
			n >>= 8;
		}
	}

	return ret;
}

size_t lnc_mksalt(char **saltout, size_t *slen) {
	unsigned char salt[SALTLEN / 8];
	size_t i;

	*slen = SALTLEN / 8;

	if(*slen > UINT_MAX) {
		fprintf(stderr, "ERROR (util.c/lnc_mksalt): saltlen too big.\n");
		return 0;
	}

	if(lnc_fill_random(salt, (int)(*slen), NULL) != *slen) {
		fprintf(stderr, "ERROR (util.c/lnc_mksalt): lnc_fill_random(%d) failed.\n", *slen);
		return 0;
	}

	if((*saltout = malloc(2 * *slen + 1)) == NULL) {
		fprintf(stderr, "ERROR (util.c/lnc_salt_hash): malloc(salt) failed.\n");
		return 0;
	}
	memset(*saltout, 0, 2 * *slen + 1);
	for(i = 0; i < *slen; i++)
		sprintf(*saltout, "%s%02x", *saltout, salt[i]);
	(*saltout)[2 * *slen] = '\0';

	return *slen;
}

static uint8_t hex2digit(char in) {
	if(in >= '0' && in <= '9')
		return in - '0';
	else if(in >= 'a' && in <= 'f')
		return in - 'a' + 10;
	else if(in >= 'A' && in <= 'F')
		return in - 'A' + 10;
	else
		return 255;
}

uint8_t *lnc_hex2char(const char *in, size_t len) {
	size_t i;
	uint8_t buf1, buf2, *out;

	if(len % 2)
		return NULL;

	if((out = malloc(len / 2)) == NULL)
		return NULL;

	for(i = 0; i < len; i += 2) {
		if((buf1 = hex2digit(in[i])) == 255) {
			free(out);
			return NULL;
		}
		if((buf2 = hex2digit(in[i + 1])) == 255) {
			free(out);
			return NULL;
		}
		
		buf1 = (buf1 & 0xf) << 4 | (buf2 & 0xf);
		out[i / 2] = buf1;
	}

	return out;
}

int lnc_salt_hash(const char *in, const size_t len, const uint8_t *salthex, char **hashout) {
	lnc_hash_t hash;	
	uint8_t *buf, *salt;
	size_t slen = strlen(salthex) / 2;
	size_t i;

	if((buf = malloc(slen + len)) == NULL) {
		fprintf(stderr, "ERROR (util.c/lnc_salt_hash): malloc(slen + len) failed.\n");
		return 0;
	}

	if((salt = lnc_hex2char(salthex, strlen(salthex))) == NULL) {
		fprintf(stderr, "ERROR (util.c/lnc_salt_hash): lnc_hex2char(%s) failed.\n", salthex);
		free(buf);
		return 0;
	}
		
	for(i = 0; i < slen; i++)
		buf[i] = salt[i];
	free(salt);

	for(i = slen; i < slen + len; i++)
		buf[i] = in[i - slen];

	hash = lnc_sha256(buf, len + slen);
	free(buf);

	if((*hashout = malloc(65)) == NULL) {
		fprintf(stderr, "ERROR (util.c/lnc_salt_hash): malloc(hash) failed.\n");		
		return 0;
	}	
	sprintf(*hashout, "%08x%08x%08x%08x%08x%08x%08x%08x", hash.h0, hash.h1, hash.h2, hash.h3, hash.h4, hash.h5, hash.h6, hash.h7);

	free(hash.string);
	return 256;
}

int lnc_fill_random(unsigned char *dst, int len, void *dat) { 
	int ret = len;
#ifdef _MSC_VER
#ifndef U_S_A_U_S_A_U_S_A
    HCRYPTPROV provider; 
     
    if(!CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_FULL, 0)) {
		fprintf(stderr, "ERROR (util.c/lnc_fill_random): CryptAcquirecontext() failed.\n");
		return 0;
	}
	
    if(!CryptGenRandom(provider, len, dst)) {
		fprintf(stderr, "ERROR (util.c/lnc_fill_random): CryptGenRandom() failed.\n");
		ret = 0;
	}
    CryptReleaseContext(provider, 0);     
#else 
    BCRYPT_ALG_HANDLE provider; 

    if(BCryptOpenAlgorithmProvider(&provider, BCRYPT_RNG_DUAL_EC_ALGORITHM, NULL, 0)) {
		fprintf(stderr, "ERROR (util.c/lnc_fill_random): BCryptOpenAlgorithmProvider() failed. The terrorists win.\n");
		return 0;
	}
    if(BCryptGenRandom(provider, dst, len, 0)) {
		fprintf(stderr, "ERROR (util.c/lnc_fill_random): BCryptGenRandom() failed. The terrorists win.\n");
		ret = 0;
	}
    BCryptCloseAlgorithmProvider(provider, 0); 
#endif 
#else
	FILE *fp;
	if((fp = fopen("/dev/urandom", "r")) == NULL)
		return 0;

	ret = fread(dst, 1, len, fp);
	fclose(fp);
#endif
    return ret; 
}

static int mp_to_file(mp_int *i, FILE *fp) {
	char *buf;
	int size;

	if(mp_radix_size(i, LNC_RADIX, &size) != MP_OKAY)
		return LNC_ERR_LTM;
	if((buf = malloc(size)) == NULL)
		return LNC_ERR_MALLOC;
	if(mp_toradix(i, buf, LNC_RADIX) != MP_OKAY) {
		free(buf);
		return LNC_ERR_LTM;
	}
	
	fprintf(fp, "%s\n", buf);
	free(buf);

	return LNC_OK;
}

void lnc_key_to_file(lnc_key_t *key, char *filename, int *status) {
	FILE *fp = fopen(filename, "w");	
	int ret = LNC_ERR_OPEN;

	if(!fp)
		goto err;

	if((ret = mp_to_file(&(key->generator), fp)) != LNC_OK)
		goto err;
	if((ret = mp_to_file(&(key->modulus), fp)) != LNC_OK)
		goto err;
	if((ret = mp_to_file(&(key->secret_key), fp)) != LNC_OK)
		goto err;
	if((ret = mp_to_file(&(key->public_key), fp)) != LNC_OK)
		goto err;

	ret = LNC_OK;	
err:
	fclose(fp);
	*status = ret;
}

static int mp_from_file(mp_int *i, FILE *fp) {
	char *buf;
	int ret = LNC_OK;

	if((buf = get_line(fp)) == NULL)
		return LNC_ERR_MALLOC;

	if(mp_read_radix(i, buf, LNC_RADIX) != MP_OKAY)
		ret = LNC_ERR_LTM;

	free(buf);
	return ret;
}

lnc_key_t *lnc_key_from_file(char *filename, int *status) {
	FILE *fp = fopen(filename, "r");
	lnc_key_t *out;
	mp_int root, modulus, secret_key, public_key, test;

	if(!fp) {
		*status = LNC_ERR_OPEN;
		return NULL;
	}

	if((out = malloc(sizeof(lnc_key_t))) == NULL) {
		*status = LNC_ERR_MALLOC;
		return NULL;
	}

	if(mp_init_multi(&root, &modulus, &secret_key, &public_key, NULL) != MP_OKAY) {
		*status = LNC_ERR_LTM;
		return NULL;
	}
	
	if((*status = mp_from_file(&root, fp)) != LNC_OK) goto err;
	if((*status = mp_from_file(&modulus, fp)) != LNC_OK) goto err;
	if((*status = mp_from_file(&secret_key, fp)) != LNC_OK) goto err;
	if((*status = mp_from_file(&public_key, fp)) != LNC_OK) goto err;	

	mp_init(&test);
	mp_exptmod(&root, &secret_key, &modulus, &test);

	if(mp_cmp_mag(&public_key, &test) != MP_EQ) {
		*status = LNC_ERR_key;
		mp_clear(&test);
		goto err;
	}	

	out->generator = root;
	out->modulus = modulus;
	out->secret_key = secret_key;
	out->public_key = public_key;

	return out;
err:
	printf("R\n");
	mp_clear_multi(&root, &modulus, &secret_key, &public_key, NULL);
	free(out);
	return NULL;
}

void lnc_xor_block(uint8_t *b1, const uint8_t *b2, const uint32_t len) {
	size_t i;
	
	for(i = 0; i < len; i++)
		b1[i] ^= b2[i];
}

uint8_t *lnc_pad(const uint8_t *data, const uint32_t bsize, const uint32_t inlen, uint32_t *newlen) {
	uint32_t padlen = 1, overlen, pos = inlen;
	uint8_t *out;

	overlen = (inlen + padlen) % bsize;
	padlen += overlen ? bsize - overlen : 0;
	*newlen = inlen + padlen;
	
	if((out = malloc(*newlen)) == NULL) {
		*newlen = inlen;
		return NULL;
	}

	memcpy(out, data, inlen);	

	out[pos++] = 0x80;
	while(pos < *newlen)
		out[pos++] = 0x00;
	
	return out;
}

char *get_line(FILE *fp) {
	int size = 0;
	size_t len = 0;
	char *buf  = NULL;

	do {
		size += MAXBUF;
		buf = realloc(buf, size);
		fgets(buf + len, MAXBUF, fp);
		len = strlen(buf);
	} while (!feof(fp) && buf[len - 1]!='\n');
	buf[len - 1] = '\0';

	return buf;
}

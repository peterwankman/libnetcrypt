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
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
		*status = LNC_ERR_KEY;
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
	size_t len = 0, size = 0;
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

/* NEW KEYFILE FORMAT */

static char *mp_to_char(mp_int *i, size_t *len, int *status) {
	char *intbuf, *outbuf;
	int bitsize, size;

	*len = 0;

	if(mp_radix_size(i, 2, &bitsize) != MP_OKAY) {
		*status = LNC_ERR_LTM;
		return NULL;
	}

	if(bitsize > 0xffff) {
		*status = LNC_ERR_OVER;
		return NULL;
	}

	if((size = mp_unsigned_bin_size(i)) == 0) {		
		*status = LNC_ERR_LTM;
		return NULL;
	}

	if((intbuf = malloc(size)) == NULL) {
		*status = LNC_ERR_MALLOC;
		return NULL;
	}

	if((outbuf = malloc(size + 2)) == NULL) {
		free(intbuf);
		*status = LNC_ERR_MALLOC;
		return NULL;
	}

	if(mp_to_unsigned_bin(i, intbuf) != MP_OKAY) {
		free(intbuf);
		free(outbuf);
		*status = LNC_ERR_LTM;
		return NULL;
	}

	outbuf[0] = (bitsize >> 8) & 0xff;
	outbuf[1] = bitsize & 0xff;

	memcpy(outbuf + 2, intbuf, size);
	free(intbuf);

	*len = (size_t)(size + 2);
	*status = LNC_OK;

	return outbuf;
}

static char *r64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

static char *encode_radix64(const char *in, const size_t len, int *status) {
	size_t pos = 0, remlen = len;
	size_t outpos = 0, outlen = ((len / 3 + 1) * 4 + 1);
	char *out = malloc(outlen);

	if(!out) {
		*status = LNC_ERR_MALLOC;
		return NULL;
	}
	memset(out, 0, outlen);

	while(remlen >= 3) {
		out[outpos++] = r64_table[(in[pos] >> 2) & 63];
		out[outpos++] = r64_table[(((in[pos] & 3) << 4) | ((in[pos + 1] >> 4) & 15)) & 63];
		out[outpos++] = r64_table[(((in[pos + 1] & 15) << 2) | ((in[pos + 2] >> 6) & 3)) & 63];
		out[outpos++] = r64_table[in[pos + 2] & 63];

		remlen -= 3;
		pos += 3;
	}

	if(remlen == 2) {
		out[outpos++] = r64_table[(in[pos] >> 2) & 63];
		out[outpos++] = r64_table[(((in[pos] & 3) << 4) | ((in[pos + 1] >> 4) & 15)) & 63];
		out[outpos++] = r64_table[((in[pos + 1] & 15) << 2) & 63];
		out[outpos++] = r64_table[64];
	} else if(remlen == 1) {
		out[outpos++] = r64_table[(in[pos] >> 2) & 63];
		out[outpos++] = r64_table[((in[pos] & 3) << 4) & 63];
		out[outpos++] = r64_table[64];
		out[outpos++] = r64_table[64];
	}

	*status = LNC_OK;
	return out;
}

void lnc_key_to_file_new(lnc_key_t *key, char *filename, int *status) {
	FILE *fp = fopen(filename, "w");
	int ret = LNC_ERR_OPEN;
	size_t idx;
	time_t now;

	char *outbuf, *encoded;
	char *generator, *modulus, *secret_key, *public_key;
	size_t gensize, modsize, secsize, pubsize;
	int i = 0;

	/* gmsp */

	if(!fp)
		goto err;

	if((generator = mp_to_char(&key->generator, &gensize, &ret)) == NULL)
		goto err;
	if((modulus = mp_to_char(&key->modulus, &modsize, &ret)) == NULL)
		goto err;
	if((secret_key = mp_to_char(&key->secret_key, &secsize, &ret)) == NULL)
		goto err;
	if((public_key = mp_to_char(&key->public_key, &pubsize, &ret)) == NULL)
		goto err;

	if((outbuf = malloc(
		1 + /* Version */
		4 + /* Timestamp */
		gensize + modsize + secsize + pubsize)) == NULL) {
			ret = LNC_ERR_MALLOC;
			goto err;
	}

	now = time(NULL);

	outbuf[0] = LNC_PROTO_VER & 0xff;
	outbuf[1] = (now >> 24) & 0xff;
	outbuf[2] = (now >> 16) & 0xff;
	outbuf[3] = (now >> 8) & 0xff;
	outbuf[4] = now & 0xff;

	idx = 5;

	memcpy(outbuf + idx, generator, gensize);	idx += gensize;
	memcpy(outbuf + idx, modulus, modsize);		idx += modsize;
	memcpy(outbuf + idx, secret_key, secsize);	idx += secsize;
	memcpy(outbuf + idx, public_key, pubsize);	idx += pubsize;

	free(generator);
	free(modulus);
	free(secret_key);
	free(public_key);

	encoded = encode_radix64(outbuf, idx, &ret);
	free(outbuf);

	if(encoded == NULL)
		goto err;
		
	fprintf(fp, "***********************************\n");
	fprintf(fp, "***** This is your secret key *****\n");
	fprintf(fp, "***** DO NOT SHARE THIS FILE! *****\n");
	fprintf(fp, "***********************************\n\n");
	fprintf(fp, "-----BEGIN LNC SECRET KEY BLOCK-----\n");
	
	while(encoded[i]) {
		fputc(encoded[i++], fp);
		if(!(i % 76))
			fputc('\n', fp);
	}

	if(i % 76)
		fprintf(fp, "\n");
	fprintf(fp, "-----END LNC SECRET KEY BLOCK-----\n");

	free(encoded);

err:
	fclose(fp);
	*status = ret;
}

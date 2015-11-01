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

/* From the description on http://garbagecollected.org/2014/09/14/how-google-authenticator-works/ */

#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "../shared/mem.h"
#include "lnc.h"
#include "lnc_macros.h"

#ifdef WITH_AUTH

static uint32_t onetimepass(const uint8_t *key, const size_t s, const uint32_t input, int *status) {
    uint8_t val[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t *mac;
    uint32_t index;
    uint32_t out;

    val[4] = (input >> 24) & 0xff;
    val[5] = (input >> 16) & 0xff;
    val[6] = (input >>  8) & 0xff;
    val[7] = (input >>  0) & 0xff;

	mac = lnc_hmac(lnc_hash_sha1, key, s, val, 8, status);
	if(*status != LNC_OK)
		return 0;
	
    index = mac[19] & 0x0f;

    out =   (mac[index + 0] << 24) |
            (mac[index + 1] << 16) |
            (mac[index + 2] <<  8) |
            (mac[index + 3] <<  0);
    out &= 0x7fffffff;

    free(mac);
    return out % 1000000;
}

static uint8_t *key_from_secret(const uint8_t *secret, int *status) {
	uint8_t *buf, *key;
	size_t keysize;

	if((buf  = malloc(strlen(secret) + 1)) == NULL) {
		*status = LNC_ERR_MALLOC;
		return 0;
	}

	memcpy(buf, secret, strlen(secret) + 1);
	lnc_delete_spaces(buf);
	lnc_strtoupper(buf);

	if((*status = lnc_b32_dec(buf, &key, &keysize)) != LNC_OK) {
		free(buf);
		return NULL;
	}

	free(buf);
	if(keysize != lnc_hash_sha1.outsize) {
		free(key);
		*status = LNC_ERR_VAL;
		return NULL;
	}
	
	return key;
}

uint32_t lnc_gen_auth(const uint8_t *secret, int *status) {
	uint8_t *key = key_from_secret(secret, status);
	uint32_t input = time(NULL) / 30, output;

	output = onetimepass(key, lnc_hash_sha1.outsize, input, status);
	free(key);
	return output;
}

int lnc_check_auth(const uint8_t *secret, const uint32_t token, int *status) {
	uint8_t *key = key_from_secret(secret, status);
	uint32_t input = time(NULL) / 30, candidate;
	uint32_t output = LNC_ERR_VAL;
	int i;

	for(i = input - 4; i < input + 4; i++) {
		candidate = onetimepass(key, lnc_hash_sha1.outsize, i, status);
		if(*status != LNC_OK)
			return 0;
		printf("%06d\n", candidate);
		if(candidate == token) {
			output = LNC_OK;
		}
	}

	free(key);
	return output;
}

#endif
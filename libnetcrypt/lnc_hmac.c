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

#include "../shared/mem.h"
#include "lnc.h"

void lnc_hmac(const lnc_hashdef_t hdef, const uint8_t *key, const size_t klen, const uint8_t *msg, const size_t mlen, int *status) {
	uint8_t *ipad, *opad, *intkey, *buf;
	size_t hlen = hdef.blocksize;
	lnc_hash_t h;
	int i;

	*status = LNC_ERR_MALLOC;

	if((ipad = malloc(hlen)) == NULL)
		return;

	if((opad = malloc(hlen)) == NULL)
		goto freeipad; /* YAY! */

	if((intkey = malloc(hlen)) == NULL)
		goto freeopad;

	if((buf = malloc(hlen + mlen)) == NULL)
		goto freekey;

	if(klen > hlen) {
		h = hdef.hashfunc(key, klen);
		memset(intkey, 0, hlen);
		memcpy(intkey, h.string, hdef.outsize);
		hdef.freefunc(&h);
	} else {
		memset(intkey, 0, hlen);
		memcpy(intkey, key, klen);
	}

	memset(ipad, 0x36, hlen);
	lnc_xor_block(ipad, intkey, hlen);
	
	memset(opad, 0x5c, hlen);
	lnc_xor_block(opad, intkey, hlen);

	memcpy(buf, ipad, hlen);
	memcpy(buf + hlen, msg, mlen);
	h = hdef.hashfunc(buf, hlen + mlen);
	free(buf);

	if((buf = malloc(hlen + hdef.outsize)) == NULL)
		goto freekey;

	memcpy(buf, opad, hlen);
	memcpy(buf + hlen, h.string, hdef.outsize);

	hdef.freefunc(&h);

	h = hdef.hashfunc(buf, hlen + hdef.outsize);

	for(i = 0; i < hdef.outsize; i++) {
		printf("%02x", h.string[i]);
	}
	printf("\n");

	hdef.freefunc(&h);

	free(buf);
freekey:
	free(intkey);
freeopad:
	free(opad);
freeipad:
	free(ipad);
}
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

#include "lnc.h"
#include "../shared/mem.h"

static int shifttbl[64] = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 
	5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

static int ktbl[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static size_t newsize(const size_t insize) {
	size_t size;

	size = insize + 1;
	size += (size % 64 > 56)? 64: 0;
	size += 64 - size % 64;

	return size;
}

static uint8_t *preprocess(const uint8_t *in, const size_t insize, const size_t size) {
	uint8_t *out;
	size_t i, buf = insize * 8;

	if((out = malloc(size)) == NULL)
		return NULL;

	memcpy(out, in, insize);
	out[insize] = 0x80;
	
	for(i = insize + 1; i < size - 8; i++)
		out[i] = 0;

	for(i = 0; i < 8; i++) {
		out[size - 8 + i] = buf & 255;
		buf >>= 8;
	}

	return out;
}

static lnc_hash_t md5init(int *status) {
	lnc_hash_t out;

	out.size = 16;
	if((out.h = malloc(4 * sizeof(uint32_t))) == NULL) {
		*status = LNC_ERR_MALLOC;
		return out;
	}
	
	out.h[0] = 0x67452301;
	out.h[1] = 0xefcdab89;
	out.h[2] = 0x98badcfe;
	out.h[3] = 0x10325476;

	out.string = NULL;

	*status = LNC_OK;
	return out;
}

static uint8_t *statetochar(lnc_hash_t in, int *status) {
	uint8_t *out = malloc(32);
	int i;

	if(out == NULL) {
		*status = LNC_ERR_MALLOC;
		return NULL;
	}

	for(i = 0; i < 5; i++) {
		out[4 * i + + 0] = in.h[i] & 255;
		out[4 * i + + 1] = (in.h[i] >> 8) & 255;
		out[4 * i + + 2] = (in.h[i] >> 16) & 255;
		out[4 * i + + 3] = (in.h[i] >> 24) & 255;
	}

	*status = LNC_OK;
	return out;
}

static lnc_hash_t digest(uint8_t *in, size_t size, int *status) {
	lnc_hash_t out = md5init(status);
	size_t block, nblocks = size / 64;
	int i;
	uint32_t M[16], f, g, temp;
	uint32_t A, B, C, D;

	for(block = 0; block < nblocks; block++) {
		A = out.h[0];
		B = out.h[1];
		C = out.h[2];
		D = out.h[3];
		
		for(i = 0; i < 16; i++) {
			M[i] = (in[block * 64 + 4 * i + 3]) << 24 |
				   (in[block * 64 + 4 * i + 2]) << 16 |
				   (in[block * 64 + 4 * i + 1]) << 8  |
				   (in[block * 64 + 4 * i + 0]);
		}

		for(i = 0; i < 64; i++) {
			if(i < 16) {
				f = (B & C) | ((~B) & D);
				g = i;
			} else if(i < 32) {
				f = (D & B) | ((~D) & C);
				g = (5 * i + 1) % 16;
			} else if(i < 48) {
				f = B ^ C ^ D;
				g = (3 * i + 5) % 16;
			} else {
				f = C ^ (B | (~D));
				g = (7 * i) % 16;
			}

			temp = D;
			D = C;
			C = B;
			B += rotl((A + f + ktbl[i] + M[g]), shifttbl[i]);
			A = temp;
		}
		out.h[0] += A;
		out.h[1] += B;
		out.h[2] += C;
		out.h[3] += D;
	}

	out.string = statetochar(out, status);
	return out;
}

lnc_hash_t lnc_md5(const uint8_t *in, const size_t insize, int *status) {
	uint8_t *prep;
	lnc_hash_t out;
	size_t size = newsize(insize);

	prep = preprocess(in, insize, size);
	out = digest(prep, size, status);
	free(prep);

	return out;
}

void lnc_md5_free(void *in) {
	lnc_hash_t *ctx = in;
	free(ctx->h);
	free(ctx->string);
}

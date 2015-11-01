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

/* From the description of SHA-1 in Wikipedia */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../shared/mem.h"
#include "lnc.h"
#include "lnc_macros.h"

#ifdef WITH_SHA1

static uint8_t *statetochar(const lnc_hash_t in, int *status) {
    uint8_t *out = malloc(20);
    int i;

    if(out == NULL) {
        *status = LNC_ERR_MALLOC;
        return NULL;
    }
    *status = LNC_OK;

    for(i = 0; i < 5; i++) {
        out[i * 4 + 0] = (in.h[i] >> 24) & 0xff;
        out[i * 4 + 1] = (in.h[i] >> 16) & 0xff;
        out[i * 4 + 2] = (in.h[i] >> 8) & 0xff;
        out[i * 4 + 3] = in.h[i] & 0xff;
    }

    return out;
}

static lnc_hash_t sha1init(void) {
    lnc_hash_t out;

    if((out.h = malloc(5 * sizeof(uint32_t))) == NULL)
        return out;

    out.h[0] = 0x67452301;
    out.h[1] = 0xefcdab89;
    out.h[2] = 0x98badcfe;
    out.h[3] = 0x10325476;
    out.h[4] = 0xc3d2e1f0;

    out.string = NULL;

    return out;
}

static size_t newsize(const size_t insize) {
    size_t size;

    size = insize + 1;
    size += (size % 64 > 56)?64:0;
    size += 64 - size % 64;

    return size;
}

static uint8_t *preprocess(const uint8_t *in, const size_t insize, const size_t size) {
    uint8_t *out;
    size_t i;

    if((out = malloc(size)) == NULL)
        return NULL;

    memcpy(out, in, insize);
    out[insize] = 0x80;

    for(i = insize + 1; i < size - 4; i++)
        out[i] = 0;
    for(i = 0; i < 4; i++)
        out[size - 4 + i] = ((insize * 8) >> ((3 - i) * 8)) & 0xff;

    return out;
}

static lnc_hash_t digest(const uint8_t *in, const size_t insize, int *status) {
    lnc_hash_t state;
    uint32_t i, j, k;
    uint32_t a, b, c, d, e;
    uint32_t W[80], f, temp;

    state = sha1init();

    for(i = 0; i < insize / 64; i++) {
        for(j = 0; j < 16; j++) {
            W[j] = 0;
            for(k = 0; k < 4; k++) {
                W[j] <<= 8;
                W[j] |= in[i * 64 + j * 4 + k];
            }
        }

        for(j = 16; j < 80; j++) {
            W[j] = rotl((W[j - 3] ^ W[j - 8] ^ W[j - 14] ^ W[j - 16]), 1);
        }

        a = state.h[0];
        b = state.h[1];
        c = state.h[2];
        d = state.h[3];
        e = state.h[4];

        for(j = 0; j < 80; j++) {
            if(j < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5a827999;
            } else if(j < 40) {
                f = b ^ c ^ d;
                k = 0x6ed9eba1;
            } else if(j < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8f1bbcdc;
            } else {
                f = b ^ c ^ d;
                k = 0xca62c1d6;
            }

            temp = rotl(a, 5) + f + e + k + W[j];
            e = d;
            d = c;
            c = rotl(b, 30);
            b = a;
            a = temp;
        }

        state.h[0] += a;
        state.h[1] += b;
        state.h[2] += c;
        state.h[3] += d;
        state.h[4] += e;
    }

    state.string = statetochar(state, status);
    state.size = 20;

    return state;
}

lnc_hash_t lnc_sha1(const uint8_t *in, const size_t insize, int *status) {
    uint8_t *prep;
    lnc_hash_t out;
    size_t size = newsize(insize);

    prep = preprocess(in, insize, size);
    out = digest(prep, size, status);
    free(prep);

    return out;
}

void lnc_sha1_free(void *in) {
	lnc_hash_t *ctx = in;
    free(ctx->h);
    free(ctx->string);
}

#endif
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

/* 
This file implements the OpenSSH  fingerprint visualization
 * algorithm. For more information, see Dan Kaminsky's talk at
 * 23C3 and the following papers.
 * http://users.ece.cmu.edu/~adrian/projects/validation/validation.pdf
 * http://www.dirk-loss.de/sshvis/drunken_bishop.pdf
 */

#include "../shared/mem.h"
#include "lnc.h"

#define X_SIZE	17
#define Y_SIZE	9

#define X_START (((X_SIZE) - 1) / 2)
#define Y_START (((Y_SIZE) - 1) / 2)

#define coord_to_pos(x, y) ((x) + ((X_SIZE) * (y)))

static uint8_t drbi_symbol[] = " .o+=*BOX@%&#/^SE";

static uint8_t move(char *x, char *y, const uint8_t direction) {
	switch(direction) {
		case 0:
			(*x)--;	(*y)--;	break;
		case 1:
			(*x)++;	(*y)--; break;
		case 2:
			(*x)--; (*y)++; break;
		case 3:
			(*x)++; (*y)++; break;
	}
	if(*x < 0) *x = 0;
	if(*y < 0) *y = 0;
	if(*x == X_SIZE) (*x)--;
	if(*y == Y_SIZE) (*y)--;
	
	return coord_to_pos(*x, *y);
}

static char digits(uint32_t n) {
	int out = 1;
	while(n /= 10)
		out++;
	return out;
}

uint8_t *lnc_rndart(const uint8_t *in, const uint32_t size, int *status) {
	uint8_t *out, pos, currbyte;
	char x = 8, y = 4;
	uint32_t i, j;

	if((out = malloc(X_SIZE * Y_SIZE)) == NULL) {
		*status = LNC_ERR_MALLOC;
		return NULL;
	}
	memset(out, 0, X_SIZE * Y_SIZE);

	pos = coord_to_pos(x, y);

	for(i = 0; i < size; i++) {
		currbyte = in[i];
		for(j = 0; j < 4; j++) {
			out[move(&x, &y, currbyte & 0x3)]++;
			currbyte >>= 2;
		}
	}

	out[coord_to_pos(X_START, Y_START)] = 15;
	out[coord_to_pos(x, y)] = 16;

	*status = LNC_OK;
	return out;
}

void lnc_print_rndart(const uint8_t *in, const char *alg, const uint32_t keysize) {
	char x, y, pad, klen = digits(keysize), alen = 0;

	if(alg)
		alen = strlen(alg);

	pad = (X_SIZE - klen - alen - 5) / 2;

	/* Ugly code equals pretty title line. */
	if(pad < 0) {
		printf("%s%s%d\n+", 
			alg ? alg : "",
			alen ? " " : "",
			keysize);
		for(x = 0; x < X_SIZE; x++)
			printf("-");
	} else {
		printf("+");
		for(x = 0; x < pad; x++)
			printf("-");
		printf("%s[ %s%s", 
			alen ? "" : "-",
			alg ? alg : "",
			alen ? " " : "");
		printf("%d ]", keysize);
		for(x = pad + klen + alen + 5; x < X_SIZE; x++)
			printf("-");
	}
	printf("+\n");
			
	for(y = 0; y < Y_SIZE; y++) {
		printf("|");
		for(x = 0; x < X_SIZE; x++) {
			printf("%c", drbi_symbol[in[coord_to_pos(x, y)]]);
		}
		printf("|\n");
	}

	printf("+");
	for(x = 0; x < X_SIZE; x++)
		printf("-");
	printf("+\n");
}

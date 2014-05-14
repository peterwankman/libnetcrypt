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

#include "../shared/mem.h"
#include "lnc.h"

#define iswserr(lnc_errno) \
	((lnc_errno == LNC_ERR_INIT) || \
	 (lnc_errno == LNC_ERR_ADDR) || \
	 (lnc_errno == LNC_ERR_SOCKET) || \
	 (lnc_errno == LNC_ERR_CONNECT) || \
	 (lnc_errno == LNC_ERR_BIND) || \
	 (lnc_errno == LNC_ERR_LISTEN))

#define iswinderr(lnc_errno) \
	((lnc_errno == LNC_ERR_MALLOC) || \
	 (lnc_errno == LNC_ERR_OPEN) || \
	 (lnc_errno == LNC_ERR_READ) || \
	 (lnc_errno == LNC_ERR_WRITE)) 

static char *alloc_and_copy(const char *str) {
	size_t len;
	char *ret;
		
	len = strlen(str) + 1;
	if(ret = malloc(len)) {
		strncpy(ret, str, len);
		return ret;
	}

	return NULL;
}

static void print_windows_errmsg(int winderr) {
#ifdef _MSC_VER
	char *winderrstr;

	FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, winderr, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&winderrstr, 0, NULL);		

	fprintf(stderr, "-- %s", winderrstr);
	LocalFree(winderrstr);
#endif
}

char *lnc_strerror(const int lnc_errno) {
	switch(lnc_errno) {
		case LNC_OK:
			return alloc_and_copy("Success."); break;
		case LNC_ERR_INIT:
			return alloc_and_copy("WSAStartup failed."); break;
		case LNC_ERR_SOCKET:
			return alloc_and_copy("Invalid socket."); break;
		case LNC_ERR_ADDR:
			return alloc_and_copy("Invalid address."); break;
		case LNC_ERR_CONNECT:
			return alloc_and_copy("connect() failed."); break;
		case LNC_ERR_BIND:
			return alloc_and_copy("bind() failed."); break;
		case LNC_ERR_LISTEN:
			return alloc_and_copy("listen() failed."); break;
		case LNC_ERR_MALLOC:
			return alloc_and_copy("malloc() failed."); break;
		case LNC_ERR_KEY:
			return alloc_and_copy("Invalid key."); break;
		case LNC_ERR_OVER:
			return alloc_and_copy("Integer overflow."); break;
		case LNC_ERR_LTM:
			return alloc_and_copy("libtommath failed."); break;
		case LNC_ERR_OPEN:
			return alloc_and_copy("fopen() failed."); break;
		case LNC_ERR_PROTO:
			return alloc_and_copy("Protocol error."); break;
		case LNC_ERR_READ:
			return alloc_and_copy("Error reading from the socket."); break;
		case LNC_ERR_WRITE:
			return alloc_and_copy("Error writing to the socket."); break;
		case LNC_ERR_WEAK:
			return alloc_and_copy("Weak key.");
		case LNC_ERR_NACK:
			return alloc_and_copy("Remote side rejected transmission.");
		case LNC_ERR_VAL:
			return alloc_and_copy("Invalid value.");
		case LNC_ERR_UNK:
			return alloc_and_copy("Unknown algorithm.");
		case LNC_ERR_AUTH:
			return alloc_and_copy("Authentication failed.");
	}

	return alloc_and_copy("Unknown error code.");
}

void lnc_perror(const int lnc_errno, const char *str) {
	char *errstr = lnc_strerror(lnc_errno);

	fprintf(stderr, "%s: ", str);
	if(errstr) {
		fprintf(stderr, "%s\n", errstr);
		free(errstr);
#ifdef _MSC_VER
		if(iswserr(lnc_errno)) {
			   print_windows_errmsg(WSAGetLastError());
		} else if(iswinderr(lnc_errno)){
			print_windows_errmsg(GetLastError());
		}
#endif
	} else
		fprintf(stderr, "Double fault. lnc_strerror() failed.\n");
}

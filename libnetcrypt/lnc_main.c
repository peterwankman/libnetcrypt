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
#include <time.h>

#include "../shared/mem.h"
#include "lnc.h"

lnc_sock_t *lnc_accept(lnc_sock_t *socket, const lnc_key_t *key, int *status) {
	lnc_sock_t *ret;
	int retval;

	if(!key) {
		*status = LNC_ERR_key;
		return NULL;
	}

	if(!socket) {
		*status = LNC_ERR_SOCKET;	
		return NULL;
	}

	if((ret = malloc(sizeof(lnc_sock_t))) == NULL) {
		*status = LNC_ERR_MALLOC;		
		return NULL;
	}

	ret->s = accept(socket->s, NULL, NULL);
	ret->sym_key = NULL;
	ret->sym_key_size = 0;
	ret->cookie = NULL;

	if((retval = lnc_handshake_server(ret, key)) != LNC_OK) {
		*status = retval;
		lnc_freesock(ret);
		return NULL;
	}

	*status = LNC_OK;
	return ret;
}

lnc_sock_t *lnc_listen(const u_short port, int *status) {
	lnc_sock_t *ret;
	SOCKADDR_IN addr;
	SOCKET s;

	memset(&addr, 0, sizeof(SOCKADDR_IN));
	addr.sin_addr.s_addr = ADDR_ANY;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if((s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
		*status = LNC_ERR_SOCKET;
		return NULL;
	}

	if(bind(s, (SOCKADDR*)(&addr), sizeof(SOCKADDR)) == SOCKET_ERROR) {
		*status = LNC_ERR_BIND;
		return NULL;
	}

	if(listen(s, LNC_BACKLOG) == SOCKET_ERROR) {
		*status = LNC_ERR_LISTEN;
		return NULL;
	}

	if((ret = malloc(sizeof(lnc_sock_t))) == NULL) {
		*status = LNC_ERR_MALLOC;
		return NULL;
	}

	ret->s = s;
	ret->sym_key = NULL;
	ret->sym_key_size = 0;
	ret->cookie = NULL;

	*status = LNC_OK;
	return ret;
}

lnc_sock_t *lnc_connect(const char *remote_addr, const u_short port, const lnc_key_t *key, int *status) {
	lnc_sock_t *ret;
	SOCKADDR_IN addr;
	SOCKET s;
	struct hostent *resolved;
	int i = 0;

	if(!key) {
		*status = LNC_ERR_key;
		return NULL;
	}

	if((resolved = gethostbyname(remote_addr)) == NULL) {
		*status = LNC_ERR_ADDR;
		return NULL;
	}

	memset(&addr, 0, sizeof(SOCKADDR_IN));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if(resolved->h_addr_list[0]) {
		addr.sin_addr.s_addr = *(u_long*)resolved->h_addr_list[i];
	} else {
		addr.sin_addr.s_addr = inet_addr(remote_addr);
	}

	if((s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
		*status = LNC_ERR_SOCKET;
		return NULL;
	}

	if(connect(s, (SOCKADDR*)(&addr), sizeof(SOCKADDR)) == SOCKET_ERROR) {
		*status = LNC_ERR_CONNECT;
		return NULL;
	}

	if((ret = malloc(sizeof(lnc_sock_t))) == NULL) {
		*status = LNC_ERR_MALLOC;	
		return NULL;
	}

	ret->s = s;
	ret->sym_key = NULL;
	ret->sym_key_size = 0;
	ret->cookie = NULL;

	if((i = lnc_handshake_client(ret, key)) != LNC_OK) {
		*status = i;
		lnc_freesock(ret);
		return NULL;
	}

	*status = LNC_OK;
	return ret;
}

int lnc_init(void) {
#ifdef _MSC_VER
	WSADATA wsa;
	if(WSAStartup(MAKEWORD(2,0), &wsa) != 0)
		return LNC_ERR_INIT;
#endif
	return LNC_OK;
}

void lnc_exit(void) {
#ifdef _MSC_VER
	WSACleanup();
#endif
}

void lnc_freesock(lnc_sock_t *socket) {
	if(!socket)
		return;

	if(socket->cookie)
		free(socket->cookie);
	if(socket->sym_key)
		free(socket->sym_key);
	free(socket);
}

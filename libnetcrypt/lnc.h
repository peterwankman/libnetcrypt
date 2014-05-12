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

#ifndef LNC_H_
#define LNC_H_

#ifdef _MSC_VER
#include <WinSock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#define SOCKET int
#define SOCKADDR struct sockaddr
#define SOCKADDR_IN struct sockaddr_in
#define ADDR_ANY INADDR_ANY
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#endif

#include "lnc_typedefs.h"
#include "lnc_aes.h"
#include "lnc_cast6.h"
#include "lnc_dh.h"
#include "lnc_error.h"
#include "lnc_hmac.h"
#include "lnc_proto.h"
#include "lnc_reg.h"
#include "lnc_rndart.h"
#include "lnc_sha256.h"
#include "lnc_util.h"

#define LNC_BACKLOG		16
#define LNC_RADIX		64

lnc_sock_t *lnc_accept(lnc_sock_t *socket, const lnc_key_t *key, int *status);
lnc_sock_t *lnc_listen(const u_short port, int *status);
lnc_sock_t *lnc_connect(const char *remote_addr, const u_short port, const lnc_key_t *key, int *status);
int lnc_init(void);
void lnc_exit(void);
void lnc_freesock(lnc_sock_t *socket);

#endif

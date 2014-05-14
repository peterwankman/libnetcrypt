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

#ifndef LNC_PROTO_H_
#define LNC_PROTO_H_

#define LNC_MAGIC		0xbaef00a5
#define LNC_PROTO_VER	0x00000002

#define LNC_MSG_NACK	0
#define LNC_MSG_ACK		1

int lnc_handshake_server(lnc_sock_t *socket, const lnc_key_t *key);
int lnc_handshake_client(lnc_sock_t *socket, const lnc_key_t *key, const uint32_t hashid, const uint32_t symid);
int lnc_send(lnc_sock_t *socket, const uint8_t *data, const uint32_t len);
int lnc_recv(lnc_sock_t *socket, uint8_t **dst);

#endif
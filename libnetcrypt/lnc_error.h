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

#ifndef LNC_ERROR_H_
#define LNC_ERROR_H_

#define LNC_OK			0
#define LNC_ERR_INIT	1
#define LNC_ERR_ADDR	2
#define LNC_ERR_SOCKET	3
#define LNC_ERR_CONNECT	4
#define LNC_ERR_BIND	5
#define LNC_ERR_LISTEN	6
#define LNC_ERR_MALLOC	7
#define LNC_ERR_KEY		8
#define LNC_ERR_OVER	9
#define LNC_ERR_LTM		10
#define LNC_ERR_OPEN	11
#define LNC_ERR_PROTO	12
#define LNC_ERR_READ	13
#define LNC_ERR_WRITE	14
#define LNC_ERR_WEAK	15
#define LNC_ERR_NACK	16
#define LNC_ERR_VAL		17
#define LNC_ERR_UNK		18
#define LNC_ERR_AUTH	19

char *lnc_strerror(const int lnc_errno);
void lnc_perror(const int lnc_errno, const char *str);

#endif
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

#include <stdlib.h>

#include "../libtommath/tommath.h"
#include "../shared/mem.h"
#include "lnc.h"

static int sendmp(SOCKET s, mp_int mpi) {
	uint8_t *buf;
	uint32_t size, bigsize;

	size = mp_unsigned_bin_size(&mpi);
	bigsize = lnc_conv_endian(size);

	if((buf = malloc(size)) == NULL)
		return LNC_ERR_MALLOC;

	if(mp_to_unsigned_bin(&mpi, buf) != MP_OKAY) {
		free(buf);
		return LNC_ERR_LTM;
	}

	if(send(s, (char*)&bigsize, sizeof(bigsize), 0) != sizeof(bigsize)) return LNC_ERR_WRITE;
	if(send(s, buf, size, 0) != size) return LNC_ERR_WRITE;
	free(buf);

	return LNC_OK;
}

static int recvmp(SOCKET s, mp_int *mpi) {
	uint8_t *buf;
	uint32_t recvint, recvd = 0, size;
	int ret = LNC_OK;
	
	if(recv(s, (char*)&recvint, sizeof(recvint), 0) != sizeof(recvint)) return LNC_ERR_READ;
	size = lnc_conv_endian(recvint);
	
	if((buf = malloc(size)) == NULL) return LNC_ERR_MALLOC;
	do {
		recvd += recv(s, buf + recvd, size, 0);
	} while(size > recvd);

	if(mp_read_unsigned_bin(mpi, buf, size) != MP_OKAY)
		ret = LNC_ERR_LTM;

	free(buf);
	return ret;
}

static int insert_key(lnc_sock_t *socket, lnc_hash_t key) {
	char *buf = malloc(key.size);

	if(!buf)
		return LNC_ERR_MALLOC;

	memcpy(buf, key.string, key.size);
	socket->sym_key = buf;
	socket->sym_key_size = key.size;
	
	return LNC_OK;
}

static uint32_t get_real_len(uint8_t *in, uint32_t inlen) {
	while(!in[--inlen]);
	if(in[inlen] == 0x80)
		return inlen;
	return 0;
}

static int mkcookie(lnc_sock_t *socket) {
	size_t bsize = socket->symdef->bsize;
	uint8_t *buf = malloc(bsize);

	if(!buf)
		return 0;

	lnc_fill_random(buf, bsize, NULL);
	socket->cookie_size = bsize;
	socket->cookie = buf;
	return bsize;
}

static int sendcookie(lnc_sock_t *socket) {
	uint32_t bufsize;
	void *context;
	char *enccookie;
	int status;
	lnc_symdef_t *symdef = socket->symdef;

	if((bufsize = mkcookie(socket)) == 0)
		return LNC_ERR_MALLOC;

	symdef->init(&context, socket->cookie, socket->sym_key, &status);
	if(status != LNC_OK)
		return status;

	symdef->enc(context);

	enccookie = symdef->tochar(context, &status);
	if(status != LNC_OK)
		return status;

	bufsize = lnc_conv_endian(socket->cookie_size);
	if(send(socket->s, (char*)&bufsize, sizeof(bufsize), 0) != sizeof(bufsize)) {
		free(enccookie);
		return LNC_ERR_WRITE;
	}	

	if(send(socket->s, enccookie, socket->symdef->bsize, 0) != socket->symdef->bsize) {
		free(enccookie);
		return LNC_ERR_WRITE;
	}

	free(enccookie);
	symdef->clear(context);
	return LNC_OK;
}

static int recvcookie(lnc_sock_t *socket) {
	lnc_symdef_t *symdef = socket->symdef;
	uint32_t bufsize;
	void *context;
	char *buf;
	int status;

	if(recv(socket->s, (char*)&bufsize, sizeof(bufsize), 0) != sizeof(bufsize)) return LNC_ERR_READ;
	
	bufsize = lnc_conv_endian(bufsize);
	if(bufsize != symdef->bsize) return LNC_ERR_PROTO;

	socket->cookie_size = bufsize;
	if((buf = malloc(bufsize)) == NULL) return LNC_ERR_MALLOC;

	if(recv(socket->s, buf, bufsize, 0) != bufsize) {
		free(buf);		
		return LNC_ERR_READ;
	}

	symdef->init(&context, buf, socket->sym_key, &status);
	if(status != LNC_OK)
		return status;

	symdef->dec(context);
	socket->cookie = symdef->tochar(context, &status);
	if(status != LNC_OK)
		return status;

	free(buf);
	symdef->clear(context);
	return LNC_OK;
}

int lnc_handshake_server(lnc_sock_t *socket, const lnc_key_t *key) {
	uint32_t magic = lnc_conv_endian(LNC_MAGIC), protover = lnc_conv_endian(LNC_PROTO_VER);
	uint32_t recvint, ack = LNC_msg_ACK, nack = LNC_msg_NACK;
	uint32_t hashid, symid;
	lnc_hashdef_t *hashdef;
	lnc_symdef_t *symdef;
	lnc_hash_t sym_key;
	int ret, bufsize, status;
	char *buf;
	SOCKET s = socket->s;
	mp_int client_key, shared_key;

	if(recv(s, (char*)&recvint, sizeof(recvint), 0) != sizeof(recvint)) goto nack;
	if(recvint != magic) goto nack;
	if(recv(s, (char*)&recvint, sizeof(recvint), 0) != sizeof(recvint)) goto nack;
	if(recvint != protover) goto nack;

	/* CHECK STATUS! */
	if(recv(s, (char*)&hashid, sizeof(hashid), 0) != sizeof(hashid)) goto nack;
	if((hashdef = lnc_get_hash(hashid, &status)) == NULL) goto nack;
	socket->hashdef = hashdef;

	if(recv(s, (char*)&symid, sizeof(symid), 0) != sizeof(symid)) goto nack;
	if((symdef = lnc_get_sym(symid, &status)) == NULL) goto nack;
	socket->symdef = symdef;

	if(send(s, (char*)&ack, sizeof(ack), 0) != sizeof(ack)) return LNC_ERR_WRITE;

	if(send(s, (char*)&magic, sizeof(magic), 0) != sizeof(magic)) return LNC_ERR_WRITE;
	if(send(s, (char*)&protover, sizeof(protover), 0) != sizeof(protover)) return LNC_ERR_WRITE;	
	if(sendmp(s, key->generator) != LNC_OK) return LNC_ERR_WRITE;
	if(sendmp(s, key->modulus) != LNC_OK) return LNC_ERR_WRITE;
	if(sendmp(s, key->public_key) != LNC_OK) return LNC_ERR_WRITE;
	if(recv(s, (char*)&recvint, sizeof(recvint), 0) != sizeof(recvint)) return LNC_ERR_READ;
	if(recvint != ack) { printf(":((\n"); return LNC_ERR_NACK; }

	if(mp_init_multi(&client_key, &shared_key, NULL) != MP_OKAY) return LNC_ERR_LTM;
	
	if((ret = recvmp(s, &client_key)) != LNC_OK) {
		send(s, (char*)&nack, sizeof(nack), 0);
		mp_clear_multi(&client_key, &shared_key, NULL);
		return ret;
	}
	/* The client public key cannot be 1 if the client is legitimate, as g^n can
	 * not equal 1 for any n. If we do receive that value, somebody is trying an
	 * attack. The shared secret would then equal 1, rendering any further encryption
	 * trivial to break.
	 */
	if(mp_cmp_d(&client_key, 1) == MP_EQ) {
		send(s, (char*)&nack, sizeof(nack), 0);
		mp_clear_multi(&client_key, &shared_key, NULL);
		return LNC_ERR_WEAK;
	}

	mp_exptmod(&client_key, (mp_int*)&(key->secret_key), (mp_int*)&(key->modulus), &shared_key);

	/* A shared key that equals 1, also equals trouble. Reject that. */
	if(mp_cmp_d(&shared_key, 1) == MP_EQ) {
		send(s, (char*)&nack, sizeof(nack), 0);
		mp_clear_multi(&client_key, &shared_key, NULL);
		return LNC_ERR_WEAK;
	}

	/* Otherwise accept the key */
	send(s, (char*)&ack, sizeof(ack), 0);

	bufsize = mp_unsigned_bin_size(&shared_key);
	if((buf = malloc(bufsize)) == NULL) {
		mp_clear_multi(&client_key, &shared_key, NULL);
		return LNC_ERR_MALLOC;
	}

	if(mp_to_unsigned_bin(&shared_key, buf) != MP_OKAY) {
		mp_clear_multi(&client_key, &shared_key, NULL);
		return LNC_ERR_LTM;
	}

	sym_key = hashdef->hashfunc(buf, bufsize, &ret);
	mp_clear_multi(&client_key, &shared_key, NULL);
	free(buf);

	if(ret != LNC_OK)
		return ret;

	if((ret = insert_key(socket, sym_key)) != LNC_OK) {
		hashdef->freefunc(&sym_key);
		return ret;
	}
	hashdef->freefunc(&sym_key);

	return sendcookie(socket);
nack:
	send(s, (char*)&nack, sizeof(nack), 0);
	return LNC_ERR_NACK;
}

int lnc_handshake_client(lnc_sock_t *socket, const lnc_key_t *key, const uint32_t hashid, const uint32_t symid) {
	uint32_t magic = lnc_conv_endian(LNC_MAGIC), protover = lnc_conv_endian(LNC_PROTO_VER);
	uint32_t recvint, ack = LNC_msg_ACK, nack = LNC_msg_NACK;
	SOCKET s = socket->s;
	mp_int root, modulus, server_key, public_key, shared_key;
	lnc_hash_t sym_key;
	int bufsize, ret, status;
	char *buf;

	if((socket->symdef = lnc_get_sym(symid, &status)) == NULL)
		return status;
	if((socket->hashdef = lnc_get_hash(hashid, &status)) == NULL)
		return status;

	if(send(s, (char*)&magic, sizeof(magic), 0) != sizeof(magic)) return LNC_ERR_WRITE;
	if(send(s, (char*)&protover, sizeof(protover), 0) != sizeof(protover)) return LNC_ERR_WRITE;
	
	if(send(s, (char*)&hashid, sizeof(hashid), 0) != sizeof(hashid)) return LNC_ERR_WRITE;
	if(send(s, (char*)&symid, sizeof(symid), 0) != sizeof(symid)) return LNC_ERR_WRITE;
	if(recv(s, (char*)&recvint, sizeof(recvint), 0) != sizeof(recvint)) return LNC_ERR_READ;
	if(recvint != ack) return LNC_ERR_NACK;

	if(recv(s, (char*)&recvint, sizeof(recvint), 0) != sizeof(recvint)) return LNC_ERR_READ;
	if(recvint != magic) return LNC_ERR_PROTO;
	if(recv(s, (char*)&recvint, sizeof(recvint), 0) != sizeof(recvint)) return LNC_ERR_READ;
	if(recvint != protover) return LNC_ERR_PROTO;

	if(mp_init_multi(&root, &modulus, &server_key, &public_key, &shared_key, NULL) != MP_OKAY)
		return LNC_ERR_LTM;
	
	if((recvmp(s, &root) != LNC_OK) || (recvmp(s, &modulus) != LNC_OK) || (recvmp(s, &server_key) != LNC_OK)) {
		mp_clear_multi(&root, &modulus, &public_key, &server_key, &shared_key, NULL);
		send(s, (char*)&nack, sizeof(nack), 0);
		return LNC_ERR_READ;
	}

	if((mp_cmp_d(&server_key, 1) == MP_EQ) || (mp_cmp_d(&root, 1) == MP_EQ)) {
		mp_clear_multi(&root, &modulus, &public_key, &server_key, &shared_key, NULL);
		send(s, (char*)&nack, sizeof(nack), 0);
		return LNC_ERR_WEAK;
	}

	/* See explanation above for client key = 1 */
	if((mp_exptmod(&root, (mp_int*)&(key->secret_key), &modulus, &public_key) != MP_OKAY) ||
	   (mp_exptmod(&server_key, (mp_int*)&(key->secret_key), &modulus, &shared_key) != MP_OKAY)) {
		mp_clear_multi(&root, &modulus, &public_key, &server_key, &shared_key, NULL);
		send(s, (char*)&nack, sizeof(nack), 0);
		return LNC_ERR_LTM;
	}

	/* Reject a shared secret of value 1. See above. */
	if(mp_cmp_d(&shared_key, 1) == MP_EQ) {
		mp_clear_multi(&root, &modulus, &public_key, &server_key, &shared_key, NULL);
		send(s, (char*)&nack, sizeof(nack), 0);
		return LNC_ERR_WEAK;
	}

	/* Otherwise accept the key */
	send(s, (char*)&ack, sizeof(ack), 0);

	if((ret = sendmp(s, public_key)) != LNC_OK) {
		mp_clear_multi(&root, &modulus, &public_key, &server_key, &shared_key, NULL);
		return ret;
	}

	if(recv(s, (char*)&recvint, sizeof(recvint), 0) != sizeof(recvint)) return LNC_ERR_READ;
	if(recvint != ack) return LNC_ERR_NACK;
	
	bufsize = mp_unsigned_bin_size(&shared_key);	
	if((buf = malloc(bufsize)) == NULL) {
		mp_clear_multi(&root, &modulus, &public_key, &server_key, &shared_key, NULL);
		return LNC_ERR_MALLOC;
	}
	mp_to_unsigned_bin(&shared_key, buf);
	mp_clear_multi(&root, &modulus, &public_key, &server_key, &shared_key, NULL);

	sym_key = socket->hashdef->hashfunc(buf, bufsize, &ret);
	free(buf);

	if(ret != LNC_OK)
		return ret;

	if((ret = insert_key(socket, sym_key)) != LNC_OK) {
		socket->hashdef->freefunc(&sym_key);
		return ret;
	}
	socket->hashdef->freefunc(&sym_key);
	
	return recvcookie(socket);
}

/* change to allow for checking status */
int lnc_send(lnc_sock_t *socket, const uint8_t *data, const uint32_t len) {
	lnc_symdef_t *symdef = socket->symdef;
	size_t bsize = symdef->bsize;
	uint8_t *IV, *buf, *padded, *encblock;
	uint32_t padlen, nblocks, sendblocks, currblock = 1;
	void *context;
	int status;

	if((IV = malloc(bsize)) == NULL)
		return 0;

	lnc_fill_random(IV, bsize, NULL);
	
	if((buf = padded = lnc_pad(data, bsize, len, &padlen)) == NULL)
		return 0;

	nblocks = padlen / bsize + 1;
	sendblocks = lnc_conv_endian(nblocks);
	send(socket->s, (char*)&sendblocks, sizeof(sendblocks), 0);
	send(socket->s, IV, bsize, 0);	
	
	do {
		lnc_xor_block(buf, IV, bsize);
		lnc_xor_block(buf, socket->cookie, bsize);

		symdef->init(&context, buf, socket->sym_key, &status);
		if(status != LNC_OK)
			return 0;

		symdef->enc(context);
		encblock = symdef->tochar(context, &status);
		if(status != LNC_OK)
			return 0;
		
		if(send(socket->s, encblock, bsize, 0) != bsize) {
			free(encblock);
			symdef->clear(context);
			free(padded);
			return 0;
		}

		symdef->clear(context);
		memcpy(IV, encblock, bsize);
		free(encblock);

		buf += bsize;
		currblock += 1;
	} while(currblock < nblocks);
	free(padded);
	free(IV);

	return nblocks;
}

/* ditto */
int lnc_recv(lnc_sock_t *socket, uint8_t **dst) {
	lnc_symdef_t *symdef = socket->symdef;
	size_t bsize = symdef->bsize;
	uint32_t recvlen, blockcnt = 1, ret = 0;
	uint8_t *IV, *currblock, *decblock, *dstbuf;
	void *context;
	int status;

	if((IV = malloc(bsize)) == NULL)
		return 0;

	if((currblock = malloc(bsize)) == NULL)
		goto freeiv;

	recv(socket->s, (char*)&recvlen, sizeof(recvlen), 0);
	recvlen = lnc_conv_endian(recvlen);

	if(recvlen < 2)
		goto freecurr;

	if((dstbuf = malloc(recvlen * (bsize - 1))) == NULL)
		goto freecurr;

	if(recv(socket->s, IV, bsize, 0) != bsize)
		goto freedst;

	do {
		if((ret = recv(socket->s, currblock, bsize, 0)) != bsize)
			goto freedst;

		symdef->init(&context, currblock, socket->sym_key, &status);
		if(status != LNC_OK)
			goto freedst;

		symdef->dec(context);
		decblock = symdef->tochar(context, &status);
		if(status != LNC_OK)
			goto freedst;

		symdef->clear(context);

		lnc_xor_block(decblock, socket->cookie, bsize);
		lnc_xor_block(decblock, IV, bsize);
		memcpy(dstbuf + (blockcnt - 1) * bsize, decblock, bsize);
		memcpy(IV, currblock, bsize);

		free(decblock);	
		blockcnt++;
	} while(blockcnt < recvlen);

	ret = get_real_len(dstbuf, (blockcnt - 1) * bsize);

	if(ret) {
		if((*dst = malloc(ret)) != NULL) {
			memcpy(*dst, dstbuf, ret);
		} else {
			ret = 0;
		}
	}
	
freedst:
	free(dstbuf);
freecurr:
	free(currblock);
freeiv:
	free(IV);
	return ret;
}

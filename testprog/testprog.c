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

#include "../shared/mem.h"
#include "../libnetcrypt/lnc.h"
#include "../libtommath/tommath.h"

#include "getopt.h"

#define KEYSIZE 4096
#define TESTMSG	"libnetcrypt test message"

void server(u_short port, lnc_key_t *key) {
	lnc_sock_t *listsock, *accsock;
	uint32_t status, nclient = 0;
	uint8_t *rndart;

	printf("Opening socket on port %d... ", port);
	if((listsock = lnc_listen(port, &status)) == NULL) {
		lnc_perror(status, "\nERROR (libnetcrypt)");
		return;
	} else
		printf("OK.\n");

	while(nclient < 3) {
		if((accsock = lnc_accept(listsock, key, &status)) == NULL) {
			lnc_freesock(listsock);
			lnc_perror(status, "ERROR (libnetcrypt)");
			return;
		}
		printf("Got client %d!\n", ++nclient);

		if((rndart = lnc_rndart(accsock->sym_key, 16, &status)) == NULL) {
			lnc_perror(status, "ERROR (rndart)");
		} else {
			lnc_print_rndart(rndart, "AES", 256);
			free(rndart);
		}

		printf("Sending '%s'... ", TESTMSG);

		if(lnc_send(accsock, TESTMSG, strlen(TESTMSG) + 1))
			printf("Success.\n");
		else
			printf("Failed.\n");

		lnc_freesock(accsock);
	}
	lnc_freesock(listsock);	
}

void client(char *remote_addr, u_short port, lnc_key_t *key) {
	lnc_sock_t *socket;
	lnc_hash_t ret;	
	uint8_t *buf, *rndart;
	uint32_t status, rcvd;

	printf("Connecting to %s:%d... ", remote_addr, port);
	socket = lnc_connect(remote_addr, port, key, &status);
	if(status != LNC_OK) {
		lnc_perror(status, "\nERROR (libnetcrypt)");
		return;
	}
	printf("Success!\n");

	if((rndart = lnc_rndart(socket->sym_key, 16, &status)) == NULL) {
		lnc_perror(status, "ERROR (rndart)");
	} else {
		lnc_print_rndart(rndart, "AES", 256);
		free(rndart);
	}

	printf("\nReceiving Data... ");

	if(rcvd = lnc_recv(socket, &buf)) {
		printf("%d bytes.\n", rcvd);
		printf("Data:    '%s'\n", buf);

		ret = lnc_sha256(buf, rcvd - 1);
		printf("SHA-256: %08x%08x%08x%08x%08x%08x%08x%08x\n",
			ret.h0, ret.h1, ret.h2, ret.h3,
			ret.h4, ret.h5, ret.h6, ret.h7);
		lnc_clear_hash(ret);

		ret = lnc_sha256(TESTMSG, strlen(TESTMSG));
		printf("TESTMSG: %08x%08x%08x%08x%08x%08x%08x%08x\n",
			ret.h0, ret.h1, ret.h2, ret.h3,
			ret.h4, ret.h5, ret.h6, ret.h7);
		lnc_clear_hash(ret);
		free(buf);
	} else 
		printf("Failed.\n");

	lnc_freesock(socket);
}

void usage(char *argv) {
	printf("USAGE: %s [-c <ADDR] [-k <FILENAME>] [-l] -p <PORT>\n", argv);
	printf("-c:		Connect\n");
	printf("-l:		Listen\n");
	printf("-k:		Key file\n");
	printf("-k:		Port\n");
	printf("Option -p is required.\n");	
	printf("Options -c and -l are mutually exclusive.\n");
}

lnc_key_t *new_key(int size, char *filename) {
	lnc_key_t *out;
	int status;

	out = lnc_gen_key(KEYSIZE, &status);
	if(status != LNC_OK) {
		lnc_perror(status, "ERROR (libnetcrypt/lnc_gen_key)");
		return NULL;
	}

	if(filename) {
		lnc_key_to_file(out, filename, &status);
		if(status != LNC_OK) {
			lnc_perror(status, "ERROR (libnetcrypt/lnc_key_to_file)");
			free(out);
			return NULL;
		}
	}

	return out;
}

int main(int argc, char **argv) {
	int c, listen = 0, status;
	u_short portnum = 0;
	char *remote_addr = NULL, *keyfile = NULL;
	lnc_key_t *key;
	
	while((c = getopt(argc, argv, "c:k:lp:")) != -1) {
		switch(c) {
			case 'c': remote_addr = optarg;	break;
			case 'k':
				keyfile = optarg; break;
			case 'l':
				listen = 1; break;
			case 'p':
				portnum = atoi(optarg);	break;
			case ':':
			case '?':
				usage(argv[0]);
				return EXIT_FAILURE;
		}
	}

	lnc_init();

	if(keyfile) {		
		key = lnc_key_from_file(keyfile, &status);
		if(status == LNC_ERR_OPEN) {
			printf("Key file does not exist. Generating a new one...\n");
			key = new_key(KEYSIZE, keyfile);
		} else if(status != LNC_OK) {
			lnc_perror(status, "ERROR (libnetcrypt)");
			return EXIT_FAILURE;
		}
	} else if(listen) {		
		printf("Generating one-time server key...\n");
		key = new_key(KEYSIZE, NULL);
	} else {
		printf("Generating one-time client key... ");
		key = lnc_gen_client_key(KEYSIZE, &status);
		if(status != LNC_OK) {
			printf("Failed.\n");
			lnc_perror(status, "ERROR (libnetcrypt)");
			return EXIT_FAILURE;
		}
		printf("Done.\n");
	}
	
	if(remote_addr)
		client(remote_addr, portnum, key);
	else if(listen)
		server(portnum, key);
	else {
		fprintf(stderr, "ERROR: The developer is an idiot.\n");
		return EXIT_FAILURE;
	}

	lnc_free_key(key);
	lnc_exit();

#ifdef _DEBUG
	if(get_mem_allocated())
		print_mem_list();
#endif

	return EXIT_SUCCESS;	
}
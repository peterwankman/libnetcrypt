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
#include <string.h>

char *optarg;
int optind = 1, opterr = 1, optopt = '\0';

int getopt(int argc, char *const argv[], const char *optstring) {
	static int nextchar = 1;
	char *found;

	if(!optind) optind = 1;

	do {
		if(!argv[optind] ||
		   *argv[optind] != '-')
			return -1;

		if(argv[optind][0] == '-') {
			if(argv[optind][1] == '\0')
				return -1;
			if(argv[optind][1] == '-' && 
			   argv[optind][2] == '\0') {
				optind++;
				return -1;
			}
		}
	
		if(argv[optind][nextchar] != '\0') {
			optopt = argv[optind][nextchar];
			if(found = strchr(optstring, optopt)) {
				if(found[0] == '\0') {
					optind++;
					nextchar = 1;
					continue;
				}
				if(found[1] == ':') {
					if(argv[optind][nextchar + 1] == '\0')
						optarg = argv[++optind];
					else
						optarg = argv[optind] + nextchar + 1;
						
					if(!optarg) {
						if(opterr)
							fprintf(stderr, "%s: option requires an argument -- '%c'\n", argv[0], optopt);
						if(optstring[0] == ':')
							return ':';				
						return '?';
					}
				} else {
					nextchar++;
					return optopt;
				}
				optind++;
				nextchar = 1;
				return optopt;
			} else {
				optind++;
				nextchar = 1;
				if(opterr)
					fprintf(stderr, "%s: unrecognised option -- '%c'\n", argv[0], optopt);
				return '?';
			}		
		}
		optind++;
		nextchar = 1;	
	} while(optind <= argc);

	return -1;
}
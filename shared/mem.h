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

#ifndef MEM_H_
#define MEM_H_

#ifdef _DEBUG
#define malloc(ptr) mem_alloc(ptr, __FILE__, __LINE__)
#define realloc(ptr, n) mem_realloc(ptr, n, __FILE__, __LINE__)
#define free(ptr) mem_free(ptr)
#endif

void *mem_alloc(const size_t n, const char *file, const int line);
void *mem_realloc(void *ptr, const size_t n, const char *file, const int line);
void *mem_free(void *ptr);
size_t get_mem_allocated(void);
void print_mem_list(void);

#endif
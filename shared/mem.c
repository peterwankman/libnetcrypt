/* 
 * mem.c -- Memory leak checker
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
#include <stdlib.h>
#include <string.h>

typedef struct ml {
	const void *ptr;
	size_t n;
	int line;
	char *file;
	struct ml *next, *prev;
} memlist_item_t;

static memlist_item_t *end = NULL, *start = NULL;
static size_t mem_allocated = 0;

static int addtolist(const void *ptr, const size_t n, const char *file, const int line) {
	memlist_item_t *new_item;

	if((new_item = malloc(sizeof(memlist_item_t))) == NULL) {
		fprintf(stderr, "ERROR (mem.c): Failed to allocate new entry in memlist\n");
		return 0;
	}

	if(ptr) {
		new_item->next = NULL;
		new_item->ptr = ptr;
		new_item->n = n;
		new_item->line = line;
		new_item->file = malloc(strlen(file) + 1);
		strcpy(new_item->file, file);

		if(!end) {
			new_item->prev = NULL;
			start = new_item;
		} else {
			new_item->prev = end;
			end->next = new_item;		
		}
		end = new_item;

		mem_allocated += n;
	} else {
		fprintf(stderr, "Warning: Tried to add a null pointer to the memlist");
		fprintf(stderr, " in File %s, line %d.\n", file, line);
	}

	return 1;
}

static memlist_item_t *findinlist(void *ptr) {
	memlist_item_t *curr = start;
	size_t out = 0;

	while(curr) {
		if(curr->ptr == ptr)
			return curr;		
		curr = curr->next;
	}

	fprintf(stderr, "ERROR (mem.c): Pointer %08x not found in memlist.\n", ptr);
	return NULL;
}

static size_t delfromlist(void *ptr) {
	memlist_item_t *curr = start;
	size_t out = 0;

	curr = findinlist(ptr);
	if(curr) {
		if(curr == start)
			start = curr->next;

		if(curr->prev)
			curr->prev->next = curr->next;
		if(curr->next)
			curr->next->prev = curr->prev;

		if(end == curr)
			end = curr->prev;

		out = curr->n;
		free(curr->file);
		free(curr);

		return out;
	}		
	fprintf(stderr, "ERROR (mem.c/delfromlist): Pointer %08x not found in memlist.\n", ptr);
	return 0;
}

void mem_free(void *ptr) {
	size_t n = delfromlist(ptr);

	if(n) {
		free(ptr);
		mem_allocated -= n;
	}
}

void *mem_alloc(const size_t n, const char *file, const int line) {
	void *new;

	if(n == 0) {
		fprintf(stderr, "Warning: Tried to allocate 0 bytes\n");
		fprintf(stderr, " in file %s, line %d.\n", file, line);
	}

	new = malloc(n);
	addtolist(new, n, file, line);

	return new;
}

void *mem_realloc(void *ptr, const size_t n, const char *file, const int line) {
	void *new = mem_alloc(n, file, line);
	memlist_item_t *entry = NULL;

	if(ptr)
		entry = findinlist(ptr);
	else
		return new;
	
	if(n == 0) {
		mem_free(ptr);
		return NULL;
	}
		
	if(!entry) {
		fprintf(stderr, "Warning (mem.c/realloc): Pointer %08x not found in memlist.\n", ptr);		
		mem_free(ptr);
		return NULL;
	}

	if(new) {
		memcpy(new, ptr, entry->n > n ? n : entry->n);
		mem_free(ptr);
		return new;
	}

	mem_free(ptr);
	mem_free(new);
	return NULL;
}

size_t get_mem_allocated(void) { return mem_allocated; }

void print_mem_list(void) {
	memlist_item_t *curr = start;

	while(curr) {
		printf("%08x %d %d %s\n", curr->ptr, curr->n, curr->line, curr->file);
		curr = curr->next;
	}
}
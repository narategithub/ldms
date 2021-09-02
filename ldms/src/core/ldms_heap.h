/* -*- c-basic-offset: 8 -*-
 * Copyright (c) 2019 National Technology & Engineering Solutions
 * of Sandia, LLC (NTESS). Under the terms of Contract DE-NA0003525 with
 * NTESS, the U.S. Government retains certain rights in this software.
 * Copyright (c) 2013,2018 Open Grid Computing, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the BSD-type
 * license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *      Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *
 *      Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 *      Neither the name of Sandia nor the names of any contributors may
 *      be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 *      Neither the name of Open Grid Computing nor the names of any
 *      contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
 *
 *      Modified source versions must be plainly marked as such, and
 *      must not be misrepresented as being the original software.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef __LDMS_HEAP_H__
#define __LDMS_HEAP_H__
#include "rrbt.h"
typedef struct ldms_heap_info {
	void *start;		/*< The address of the start of the heap */
	size_t grain;		/*< The minimum allocation size as 2^x */
	size_t grain_bits;	/*< x in 2^x */
	size_t size;		/*< The size of the heap in bytes */
	size_t free_chunks;	/*< number of unallocated chunks current */
	size_t free_bytes;	/*< number of unallocated grains current */
	size_t largest;		/*< largest unallocated chunk size in grains */
	size_t smallest;	/*< smallest unallocated chunk size in grains */
} *ldms_heap_info_t;
#define LDMS_HEAP_MIN_SIZE 512

struct ldms_heap {
	uint32_t grain_bits:8;
	uint32_t grain:24;	/* Minimum allocation size and alignment */
	uint64_t size;		/* Size of the heap in bytes */
	struct rrbt size_tree;	/* Tree ordered by size */
	struct rrbt addr_tree;	/* Tree ordered by addr/offset */
};

typedef struct ldms_heap_instance {
	struct ldms_heap *data;
	struct ldms_heap_base *base;
	pthread_mutex_t lock;
	rrbt_t size_tree;
	rrbt_t addr_tree;
	struct rrbt_instance size_inst;
	struct rrbt_instance addr_inst;
} *ldms_heap_t;

struct ldms_heap_base {
	char signature[8];	/* Identifies start of heap and
				   prevents 0 from ever being returned
				   by an allocation */
	uint8_t start[0];
};

/**
 * \brief Get information about the heap configuration
 *
 * \param mmi	Pointer to the mm_info structure to be filled in.
 */
void ldms_heap_get_info(ldms_heap_t h, ldms_heap_info_t i);

/**
 * \brief Initialize the heap.
 *
 * Initializes the heap data at teh specified base address
 *
 * \param size	The size of the heap in bytes.
 * \param grain	The minimum allocation size.
 */
void ldms_heap_init(struct ldms_heap *heap, void *base, size_t size, size_t grain);

/**
 * \brief Gets a handle to the heap at the specified base address
 *
 * Returns a handle to the heap at the specified address.
 *
 * \param base	The address where the heap is located
 * \returns A handle to the heap or NULL if there is an error
 */
ldms_heap_t ldms_heap_get(ldms_heap_t h, struct ldms_heap *heap, void *base);

/**
 * \brief Allocate memory from the heap.
 *
 * Allocates memory of the requested size from the heap. The memory
 * allocated will be aligned on the \c grain boundary specified in \c mm_init
 *
 * \param size	The requested buffer size in bytes.
 * \returns	A pointer to the allocated memory or NULL if there is
 *		insufficient memory.
 */
void *ldms_heap_alloc(ldms_heap_t heap, size_t size);

/*
 * \brief Return heap bytes required to store element of specified size
 *
 * The heap has overhead. This function returns the amount of heap
 * memory consumed to store an element of size \c size
 *
 * \param grain_sz The grain size of the heap
 * \param data_sz The size of the element in bytes
 * \returns The number of bytes of heap memory consumed.
 */
size_t ldms_heap_alloc_size(size_t grain_sz, size_t data_sz);

/**
 * \brief Return memory to the heap.
 *
 * \param ptr	Pointer to the buffer to free.
 */
void ldms_heap_free(ldms_heap_t h, void *ptr);

uint64_t ldms_heap_off(ldms_heap_t h, void *p);
void *ldms_heap_ptr(ldms_heap_t h, uint64_t off);

#endif

